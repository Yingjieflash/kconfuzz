// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/kconfuzz"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}

	execQueues
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	f := &Fuzzer{
		Stats:  newStats(target),
		Config: cfg,
		Cover:  newCover(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
	}
	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

func (fuzzer *Fuzzer) RecommendedCalls() int {
	if fuzzer.Config.ModeKFuzzTest {
		return prog.RecommendedCallsKFuzzTest
	}
	return prog.RecommendedCalls
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	triageQueue          *queue.DynamicOrderer
	smashQueue           *queue.PlainQueue
	source               queue.Source
}

var debugResultSummaries atomic.Int32
var debugTriageSummaries atomic.Int32

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
		triageQueue:          queue.DynamicOrder(),
		smashQueue:           queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		skipQueue = 2
	}
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(
		ret.triageCandidateQueue,
		ret.candidateQueue,
		ret.triageQueue,
		queue.Alternate(ret.smashQueue, skipQueue),
		queue.Callback(fuzzer.genFuzz),
	)
	return ret
}

func (fuzzer *Fuzzer) CandidatesToTriage() int {
	return fuzzer.statCandidates.Val() + fuzzer.statJobsTriageCandidate.Val()
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.CandidatesToTriage() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepareKConfuzz(req)
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) prepareKConfuzz(req *queue.Request) {
	if req == nil || req.Type != flatrpc.RequestTypeProgram || req.Prog == nil ||
		req.KConfuzzConfigDisabled {
		return
	}
	if !kconfuzz.ActionsEnabled() {
		req.KConfuzzConfigActions = nil
		req.KConfuzzConfigContext = nil
		return
	}
	hadContext := req.KConfuzzConfigContext != nil
	if req.KConfuzzConfigContext != nil {
		req.KConfuzzConfigContext = kconfuzz.FilterSupportedContext(req.KConfuzzConfigContext, req.Prog)
	}
	if len(req.KConfuzzConfigActions) == 0 && req.KConfuzzConfigContext != nil {
		req.KConfuzzConfigActions = prog.CloneKConfuzzConfigActions(req.KConfuzzConfigContext.Actions)
	}
	if len(req.KConfuzzConfigActions) != 0 {
		if req.KConfuzzConfigContext == nil {
			req.KConfuzzConfigContext = &prog.KConfuzzConfigContext{
				Strategy: prog.KConfuzzConfigStrategySequence,
				Source:   "request-actions",
				Actions:  prog.CloneKConfuzzConfigActions(req.KConfuzzConfigActions),
			}
		}
		req.KConfuzzConfigActions = prog.NormalizeKConfuzzConfigActions(req.Prog,
			kconfuzz.FilterSupportedActions(req.KConfuzzConfigActions))
		if len(req.KConfuzzConfigActions) == 0 {
			req.KConfuzzConfigContext = nil
			return
		}
		req.KConfuzzConfigContext.Actions = prog.CloneKConfuzzConfigActions(req.KConfuzzConfigActions)
		kconfuzz.Debugf("using explicit config context source=%s actions=%d calls=%d",
			req.KConfuzzConfigContext.Source, len(req.KConfuzzConfigActions), len(req.Prog.Calls))
		return
	}
	if hadContext {
		return
	}
	req.KConfuzzConfigContext = kconfuzz.PlanContextFromEnv(req.Prog)
	if req.KConfuzzConfigContext != nil {
		req.KConfuzzConfigActions = prog.CloneKConfuzzConfigActions(req.KConfuzzConfigContext.Actions)
	}
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	if debugResultSummaries.Add(1) <= 20 {
		calls, signalCount, coverCount := 0, 0, 0
		if res.Info != nil {
			calls = len(res.Info.Calls)
			for _, info := range res.Info.Calls {
				if info == nil {
					continue
				}
				signalCount += len(info.Signal)
				coverCount += len(info.Cover)
			}
			if res.Info.Extra != nil {
				signalCount += len(res.Info.Extra.Signal)
				coverCount += len(res.Info.Extra.Cover)
			}
		}
		kconfuzz.Debugf("exec result status=%v info=%v calls=%d raw_signal=%d raw_cover=%d flags=%v attempt=%d",
			res.Status, res.Info != nil, calls, signalCount, coverCount, flags, attempt)
	}
	if req.KConfuzzConfigContext != nil &&
		(res.Status == queue.Crashed || res.Status == queue.Hanged || res.Status == queue.ExecFailure) &&
		kconfuzz.DangerousConfigResult(req.KConfuzzConfigContext, res.Output, res.Err,
			res.Status == queue.Crashed, res.Status == queue.Hanged) {
		kconfuzz.RecordEnvFailureAudit(req.Prog, req.KConfuzzConfigContext, res.Output, res.Err, res.Status.String())
		kconfuzz.QuarantineContext(req.Prog, req.KConfuzzConfigContext, res.Status.String())
	}

	// If we are already triaging this exact prog, this is flaky coverage.
	// Hanged programs are harmful as they consume executor procs.
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	// Triage the program.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	var triage map[int]*triageCall
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, call, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			queue, stat := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queue, stat = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{
				p:                 req.Prog.Clone(),
				kconfuzzConfig:    req.KConfuzzConfigContext.CloneForProg(req.Prog),
				kconfuzzOriginSig: req.KConfuzzOriginSig,
				executor:          res.Executor,
				flags:             flags,
				queue:             queue.Append(),
				calls:             triage,
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			sort.Strings(job.info.Calls)
			fuzzer.startJob(stat, job)
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)
	}

	// Corpus candidates may have flaky coverage, so we give them a second chance.
	maxCandidateAttempts := 3
	if req.Risky() {
		// In non-snapshot mode usually we are not sure which exactly input caused the crash,
		// so give it one more chance. In snapshot mode we know for sure, so don't retry.
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...any)
	Snapshot       bool
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(call string) bool
	PatchTest      bool
	ModeKFuzzTest  bool
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if len(info.Signal) != 0 && debugTriageSummaries.Add(1) <= 40 {
		kconfuzz.Debugf("triage candidate call=%d name=%s raw_signal=%d prio=%d new_max=%d",
			call, p.CallName(call), len(info.Signal), prio, newMaxSignal.Len())
	}
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		kconfuzz.Debugf("triage filtered call=%d name=%s new_max=%d",
			call, p.CallName(call), newMaxSignal.Len())
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
		fuzzer.statCompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
		fuzzer.statCoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	var req *queue.Request
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req = mutateProgRequest(fuzzer, rnd)
	}
	if req == nil {
		req = genProgRequest(fuzzer, rnd)
	}
	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		p := randomCollide(req.Prog, rnd)
		req = &queue.Request{
			Prog:                  p,
			KConfuzzConfigContext: req.KConfuzzConfigContext.CloneForProg(p),
			KConfuzzOriginSig:     req.KConfuzzOriginSig,
			Stat:                  fuzzer.statExecCollide,
		}
	}
	fuzzer.prepare(req, 0, 0)
	return req
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	kconfuzz.Debugf("starting job type=%T", newJob)
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
		kconfuzz.Debugf("finished job type=%T", newJob)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...any) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
)

type Candidate struct {
	Prog           *prog.Prog
	Flags          ProgFlags
	KConfuzzConfig *prog.KConfuzzConfigContext
	Sig            string
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.statCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		req := &queue.Request{
			Prog:              candidate.Prog,
			ExecOpts:          setFlags(flatrpc.ExecFlagCollectSignal),
			KConfuzzOriginSig: candidate.Sig,
			Stat:              fuzzer.statExecCandidate,
			Important:         true,
		}
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	relationBoosts := kconfuzz.RelationChoiceBoostsFromEnv(
		fuzzer.target, fuzzer.Config.EnabledCalls)
	newCt := fuzzer.target.BuildChoiceTableWithBoosts(programs, fuzzer.Config.EnabledCalls, relationBoosts)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}
