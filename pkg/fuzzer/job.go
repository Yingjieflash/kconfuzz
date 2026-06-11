// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/kconfuzz"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type job interface {
	run(fuzzer *Fuzzer)
}

type jobIntrospector interface {
	getInfo() *JobInfo
}

type JobInfo struct {
	Name  string
	Calls []string
	Type  string
	Execs atomic.Int32

	syncBuffer
}

func (ji *JobInfo) ID() string {
	return fmt.Sprintf("%p", ji)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.target.Generate(rnd,
		fuzzer.RecommendedCalls(),
		fuzzer.ChoiceTable())
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	item := chooseMutationSeed(fuzzer, rnd)
	if item == nil {
		return nil
	}
	p := item.Prog
	newP := p.Clone()
	newP.Mutate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)
	return &queue.Request{
		Prog:              newP,
		ExecOpts:          setFlags(flatrpc.ExecFlagCollectSignal),
		KConfuzzOriginSig: item.Sig,
		Stat:              fuzzer.statExecFuzz,
	}
}

func chooseMutationSeed(fuzzer *Fuzzer, rnd *rand.Rand) *corpus.Item {
	for try := 0; try < 8; try++ {
		item := fuzzer.Config.Corpus.ChooseItem(rnd)
		if item == nil {
			return nil
		}
		if !kconfuzz.ShouldSkipPenalizedSeed(item.Sig, rnd) {
			return item
		}
	}
	return nil
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p                 *prog.Prog
	kconfuzzConfig    *prog.KConfuzzConfigContext
	kconfuzzOriginSig string
	executor          queue.ExecutorID
	flags             ProgFlags
	fuzzer            *Fuzzer
	queue             queue.Executor
	// Set of calls that gave potential new coverage.
	calls map[int]*triageCall

	info *JobInfo
}

type triageCall struct {
	errno     int32
	newSignal signal.Signal

	// Filled after deflake:
	signals         [deflakeNeedRuns]signal.Signal
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint64

	kconfuzzABChecked bool
	kconfuzzDependent bool
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
//
// During corpus triage we are more permissive and require only 2/6 to produce new stable signal.
// Such parameters make 80% flakiness to pass 99% of time, and even 60% flakiness passes 96% of time.
// First, we don't need to be strict during corpus triage since the program has already passed
// the stricter check when it was added to the corpus. So we can do fewer runs during triage,
// and finish it sooner. If the program does not produce any stable signal any more, just flakes,
// (if the kernel code was changed, or configs disabled), then it still should be phased out
// of the corpus eventually.
// Second, even if small percent of programs are dropped from the corpus due to flaky signal,
// later after several restarts we will add them to the corpus again, and it will create lots
// of duplicate work for minimization/hints/smash/fault injection. For example, a program with
// 60% flakiness has 68% chance to pass 3/5 criteria, but it's also likely to be dropped from
// the corpus if we use the same 3/5 criteria during triage. With a large corpus this effect
// can cause re-addition of thousands of programs to the corpus, and hundreds of thousands
// of runs for the additional work. With 2/6 criteria, a program with 60% flakiness has
// 96% chance to be kept in the corpus after retriage.
const (
	deflakeNeedRuns         = 3
	deflakeMaxRuns          = 5
	deflakeNeedCorpusRuns   = 2
	deflakeMinCorpusRuns    = 4
	deflakeMaxCorpusRuns    = 6
	deflakeTotalCorpusRuns  = 20
	deflakeNeedSnapshotRuns = 2
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) *queue.Result {
	return job.executeWithKConfuzz(req, flags, job.kconfuzzConfig, false)
}

func (job *triageJob) executeWithKConfuzz(req *queue.Request, flags ProgFlags,
	kconfuzzConfig *prog.KConfuzzConfigContext, disableKConfuzz bool) *queue.Result {
	defer job.info.Execs.Add(1)
	req.Important = true // All triage executions are important.
	if disableKConfuzz {
		req.KConfuzzConfigDisabled = true
		req.KConfuzzConfigActions = nil
		req.KConfuzzConfigContext = nil
	} else if kconfuzzConfig != nil {
		req.KConfuzzConfigContext = kconfuzzConfig.CloneForProg(req.Prog)
		if req.KConfuzzConfigContext != nil {
			req.KConfuzzConfigActions = prog.CloneKConfuzzConfigActions(req.KConfuzzConfigContext.Actions)
		}
	}
	if req.KConfuzzOriginSig == "" {
		req.KConfuzzOriginSig = job.kconfuzzOriginSig
	}
	return job.fuzzer.executeWithFlags(job.queue, req, flags)
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	fuzzer.statNewInputs.Add(1)
	job.fuzzer = fuzzer
	kconfuzz.Debugf("triage job started calls=%d prog_calls=%d", len(job.calls), len(job.p.Calls))
	job.info.Logf("\n%s", job.p.Serialize())
	for call, info := range job.calls {
		job.info.Logf("call #%d [%s]: |new signal|=%d%s",
			call, job.p.CallName(call), info.newSignal.Len(), signalPreview(info.newSignal))
	}

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(job.execute)
	if stop {
		kconfuzz.Debugf("triage job stopped during deflake")
		return
	}
	var wg sync.WaitGroup
	for call, info := range job.calls {
		wg.Add(1)
		go func() {
			job.handleCall(call, info)
			wg.Done()
		}()
	}
	wg.Wait()
	kconfuzz.Debugf("triage job complete calls=%d", len(job.calls))
}

func (job *triageJob) handleCall(call int, info *triageCall) {
	if info.newStableSignal.Empty() {
		kconfuzz.Debugf("skip corpus save call=%d name=%s reason=no_new_stable_signal",
			call, job.p.CallName(call))
		return
	}

	kconfuzzConfig := job.kconfuzzConfig.CloneForProg(job.p)
	disableKConfuzz := false
	if kconfuzzConfig != nil && kconfuzz.MetadataEnabled() {
		info.kconfuzzDependent = job.checkKConfuzzDependency(call, info)
		info.kconfuzzABChecked = true
		if !info.kconfuzzDependent {
			kconfuzzConfig = nil
			disableKConfuzz = true
		}
	} else if !kconfuzz.MetadataEnabled() {
		kconfuzzConfig = nil
		disableKConfuzz = true
	}

	p := job.p
	if job.flags&ProgMinimized == 0 {
		p, call = job.minimize(call, info, kconfuzzConfig, disableKConfuzz)
		if p == nil {
			return
		}
	}
	if kconfuzzConfig != nil {
		kconfuzzConfig = job.minimizeKConfuzzConfig(p, call, info, kconfuzzConfig)
	}
	callName := p.CallName(call)
	if !job.fuzzer.Config.NewInputFilter(callName) {
		kconfuzz.Debugf("skip corpus save call=%d name=%s reason=filtered", call, callName)
		return
	}
	if job.flags&ProgSmashed == 0 {
		job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
			exec:              job.fuzzer.smashQueue,
			p:                 p.Clone(),
			kconfuzzOriginSig: job.kconfuzzOriginSig,
			info: &JobInfo{
				Name:  p.String(),
				Type:  "smash",
				Calls: []string{p.CallName(call)},
			},
		})
		if job.fuzzer.Config.Comparisons && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
				exec:              job.fuzzer.smashQueue,
				p:                 p.Clone(),
				call:              call,
				kconfuzzOriginSig: job.kconfuzzOriginSig,
				info: &JobInfo{
					Name:  p.String(),
					Type:  "hints",
					Calls: []string{p.CallName(call)},
				},
			})
		}
		if job.fuzzer.Config.FaultInjection && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec:              job.fuzzer.smashQueue,
				p:                 p.Clone(),
				call:              call,
				kconfuzzOriginSig: job.kconfuzzOriginSig,
			})
		}
	}
	job.fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, p)
	input := corpus.NewInput{
		Prog:           p,
		Call:           call,
		KConfuzzConfig: nil,
		Signal:         info.stableSignal,
		Cover:          info.cover.Serialize(),
		RawCover:       info.rawCover,
	}
	job.fuzzer.Config.Corpus.Save(input)
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result) (stop bool) {
	job.info.Logf("deflake started")
	kconfuzz.Debugf("deflake started calls=%d flags=%v", len(job.calls), job.flags)

	avoid := []queue.ExecutorID{job.executor}
	needRuns := deflakeNeedCorpusRuns
	if job.fuzzer.Config.Snapshot {
		needRuns = deflakeNeedSnapshotRuns
	} else if job.flags&ProgFromCorpus == 0 {
		needRuns = deflakeNeedRuns
	}
	prevTotalNewSignal := 0
	for run := 1; ; run++ {
		totalNewSignal := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
		}
		if job.stopDeflake(run, needRuns, prevTotalNewSignal == totalNewSignal) {
			break
		}
		prevTotalNewSignal = totalNewSignal
		kconfuzz.Debugf("deflake run=%d need=%d return_all=%d", run, needRuns, len(indices))
		result := exec(&queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Avoid:           avoid,
			Stat:            job.fuzzer.statExecTriage,
		}, progInTriage)
		kconfuzz.Debugf("deflake run=%d result status=%v info=%v", run, result.Status, result.Info != nil)
		if result.Stop() {
			return true
		}
		avoid = append(avoid, result.Executor)
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after needRuns runs,
			// it won't be stable. However, it's still possible if we do more than needRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			thisSignal := signal.FromRaw(res.Signal, prio)
			for j := needRuns - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
			}
			info.signals[0].Merge(thisSignal)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	job.info.Logf("deflake complete")
	for call, info := range job.calls {
		info.stableSignal = info.signals[needRuns-1]
		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
		kconfuzz.Debugf("deflake call=%d name=%s new=%d stable=%d new_stable=%d",
			call, job.p.CallName(call), info.newSignal.Len(), info.stableSignal.Len(),
			info.newStableSignal.Len())
		job.info.Logf("call #%d [%s]: |stable signal|=%d, |new stable signal|=%d%s",
			call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
			signalPreview(info.newStableSignal))
	}
	return false
}

func (job *triageJob) stopDeflake(run, needRuns int, noNewSignal bool) bool {
	if job.fuzzer.Config.Snapshot {
		return run >= needRuns+1
	}
	haveSignal := true
	for _, call := range job.calls {
		if !call.newSignal.IntersectsWith(call.signals[needRuns-1]) {
			haveSignal = false
		}
	}
	if job.flags&ProgFromCorpus == 0 {
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if run >= deflakeMaxRuns {
			return true
		}
		noChance := true
		for _, call := range job.calls {
			if left := deflakeMaxRuns - run; left >= needRuns ||
				call.newSignal.IntersectsWith(call.signals[needRuns-left-1]) {
				noChance = false
			}
		}
		if haveSignal || noChance {
			return true
		}
	} else if run >= deflakeTotalCorpusRuns ||
		noNewSignal && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveSignal) {
		// For programs from the corpus we use a different condition b/c we want to extract
		// as much flaky signal from them as possible. They have large coverage and run
		// in the beginning, gathering flaky signal on them allows to grow max signal quickly
		// and avoid lots of useless executions later. Any bit of flaky coverage discovered
		// later will lead to triage, and if we are unlucky to conclude it's stable also
		// to minimization+smash+hints (potentially thousands of runs).
		// So we run them at least 5 times, or while we are still getting any new signal.
		return true
	}
	return false
}

func (job *triageJob) checkKConfuzzDependency(call int, info *triageCall) bool {
	reproduced := job.reproducesSignal(&queue.Request{
		Prog:            job.p,
		ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
		ReturnAllSignal: []int{call},
		Stat:            job.fuzzer.statExecTriage,
	}, call, info.newStableSignal, nil, true, 2)
	if reproduced {
		job.info.Logf("[call #%d] kconfuzz A/B: without-config reproduced new signal", call)
		return false
	}
	job.info.Logf("[call #%d] kconfuzz A/B: new signal requires config context", call)
	return true
}

func (job *triageJob) reproducesSignal(req *queue.Request, call int, want signal.Signal,
	kconfuzzConfig *prog.KConfuzzConfigContext, disableKConfuzz bool, attempts int) bool {
	var mergedSignal signal.Signal
	for i := 0; i < attempts; i++ {
		req1 := &queue.Request{
			Type:            req.Type,
			ExecOpts:        req.ExecOpts,
			Prog:            req.Prog,
			ReturnAllSignal: append([]int(nil), req.ReturnAllSignal...),
			Stat:            req.Stat,
		}
		result := job.executeWithKConfuzz(req1, progInTriage, kconfuzzConfig, disableKConfuzz)
		if result.Stop() || result.Info == nil {
			return false
		}
		thisSignal := getSignalAndCover(req.Prog, result.Info, call)
		if mergedSignal.Len() == 0 {
			mergedSignal = thisSignal
		} else {
			mergedSignal.Merge(thisSignal)
		}
		if signalContainsAll(want, mergedSignal) {
			return true
		}
	}
	return false
}

func signalContainsAll(want, got signal.Signal) bool {
	return want.Intersection(got).Len() == want.Len()
}

func (job *triageJob) minimize(call int, info *triageCall,
	kconfuzzConfig *prog.KConfuzzConfigContext, disableKConfuzz bool) (*prog.Prog, int) {
	job.info.Logf("[call #%d] minimize started", call)
	minimizeAttempts := 3
	if job.fuzzer.Config.Snapshot {
		minimizeAttempts = 2
	}
	stop := false
	mode := prog.MinimizeCorpus
	if job.fuzzer.Config.PatchTest {
		mode = prog.MinimizeCallsOnly
	}
	p, call := prog.Minimize(job.p, call, mode, func(p1 *prog.Prog, call1 int) bool {
		if stop {
			return false
		}
		var mergedSignal signal.Signal
		for i := 0; i < minimizeAttempts; i++ {
			result := job.executeWithKConfuzz(&queue.Request{
				Prog:            p1,
				ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
				ReturnAllSignal: []int{call1},
				Stat:            job.fuzzer.statExecMinimize,
			}, 0, kconfuzzConfig, disableKConfuzz)
			if result.Stop() {
				stop = true
				return false
			}
			if !reexecutionSuccess(result.Info, info.errno, call1) {
				// The call was not executed or failed.
				continue
			}
			thisSignal := getSignalAndCover(p1, result.Info, call1)
			if mergedSignal.Len() == 0 {
				mergedSignal = thisSignal
			} else {
				mergedSignal.Merge(thisSignal)
			}
			if info.newStableSignal.Intersection(mergedSignal).Len() == info.newStableSignal.Len() {
				job.info.Logf("[call #%d] minimization step success (|calls| = %d)",
					call, len(p1.Calls))
				return true
			}
		}
		job.info.Logf("[call #%d] minimization step failure", call)
		return false
	})
	if stop {
		return nil, 0
	}
	return p, call
}

func (job *triageJob) minimizeKConfuzzConfig(p *prog.Prog, call int, info *triageCall,
	kconfuzzConfig *prog.KConfuzzConfigContext) *prog.KConfuzzConfigContext {
	kconfuzzConfig = kconfuzzConfig.CloneForProg(p)
	if kconfuzzConfig == nil || len(kconfuzzConfig.Actions) == 0 {
		return nil
	}
	maxSavedActions := kconfuzz.SaveMaxActions()
	originalActions := len(kconfuzzConfig.Actions)
	job.info.Logf("[call #%d] kconfuzz action minimization started (|actions| = %d)",
		call, len(kconfuzzConfig.Actions))
	kconfuzz.Debugf("action minimization start call=%d actions=%d save_max=%d",
		call, originalActions, maxSavedActions)

	// First keep the original syzkaller-style invariant: preserve all of the
	// new stable signal attributed to this input. Chunk deletion makes large
	// all-related plans cheaper to shrink before the one-by-one pass.
	strictPerAction := maxSavedActions == 0 || len(kconfuzzConfig.Actions) <= maxSavedActions*2
	kconfuzzConfig = job.reduceKConfuzzActions(p, call, info.newStableSignal,
		kconfuzzConfig, strictPerAction, 0)
	if kconfuzzConfig == nil {
		return nil
	}

	// If the strict signal-preserving context is still too large, compact the
	// saved metadata around a single stable signal. The full action set was
	// already useful for discovery; the corpus item only needs enough context
	// to reproduce a real config-dependent signal when it is reloaded/mutated.
	if maxSavedActions > 0 && len(kconfuzzConfig.Actions) > maxSavedActions {
		target := kconfuzzAnchorSignal(info.newStableSignal)
		if !target.Empty() {
			compact := job.reduceKConfuzzActions(p, call, target, kconfuzzConfig, true, 1)
			if compact != nil && len(compact.Actions) < len(kconfuzzConfig.Actions) {
				probe, ok := job.probeKConfuzzSignal(p, call, target, compact, 2)
				if ok {
					kconfuzzConfig = compact
					info.stableSignal = probe.Signal
					info.newStableSignal = target
					if len(probe.Cover) != 0 {
						info.cover = probe.Cover
					}
					if len(probe.RawCover) != 0 {
						info.rawCover = probe.RawCover
					}
					job.info.Logf("[call #%d] kconfuzz action compaction preserved anchor signal (|actions| = %d)",
						call, len(kconfuzzConfig.Actions))
					kconfuzz.Debugf("action compaction call=%d original=%d compact=%d target=%d",
						call, originalActions, len(kconfuzzConfig.Actions), target.Len())
				}
			}
		}
		if len(kconfuzzConfig.Actions) > maxSavedActions {
			kconfuzzConfig.Actions = limitKConfuzzActionsForSave(kconfuzzConfig.Actions, maxSavedActions)
			job.info.Logf("[call #%d] kconfuzz action save cap applied (|actions| = %d)",
				call, len(kconfuzzConfig.Actions))
			kconfuzz.Debugf("action save cap call=%d original=%d capped=%d",
				call, originalActions, len(kconfuzzConfig.Actions))
		}
	}

	beforeRiskTighten := len(kconfuzzConfig.Actions)
	kconfuzzConfig = kconfuzz.TightenContextForSave(kconfuzzConfig, p)
	if kconfuzzConfig == nil || len(kconfuzzConfig.Actions) == 0 {
		kconfuzz.Debugf("action mixed-risk save tightening dropped context call=%d original=%d",
			call, beforeRiskTighten)
		return nil
	}
	if len(kconfuzzConfig.Actions) < beforeRiskTighten {
		job.info.Logf("[call #%d] kconfuzz mixed-risk save cap applied (|actions| = %d)",
			call, len(kconfuzzConfig.Actions))
		kconfuzz.Debugf("action mixed-risk save cap call=%d original=%d capped=%d",
			call, beforeRiskTighten, len(kconfuzzConfig.Actions))
	}

	kconfuzzConfig.Actions = prog.NormalizeKConfuzzConfigActions(p, kconfuzzConfig.Actions)
	if len(kconfuzzConfig.Actions) == 0 {
		return nil
	}
	kconfuzzConfig.ConfigDependent = true
	job.info.Logf("[call #%d] kconfuzz action minimization complete (|actions| = %d)",
		call, len(kconfuzzConfig.Actions))
	kconfuzz.Debugf("action minimization complete call=%d original=%d final=%d",
		call, originalActions, len(kconfuzzConfig.Actions))
	return kconfuzzConfig
}

func limitKConfuzzActionsForSave(actions []prog.KConfuzzConfigAction, limit int) []prog.KConfuzzConfigAction {
	if limit <= 0 || len(actions) <= limit {
		return prog.CloneKConfuzzConfigActions(actions)
	}
	ret := make([]prog.KConfuzzConfigAction, 0, limit)
	for i := 0; i < limit; i++ {
		index := i * len(actions) / limit
		ret = append(ret, actions[index])
	}
	return ret
}

func (job *triageJob) reduceKConfuzzActions(p *prog.Prog, call int, target signal.Signal,
	kconfuzzConfig *prog.KConfuzzConfigContext, perAction bool, minActions int) *prog.KConfuzzConfigContext {
	if target.Empty() {
		return kconfuzzConfig
	}
	kconfuzzConfig = kconfuzzConfig.CloneForProg(p)
	if kconfuzzConfig == nil || len(kconfuzzConfig.Actions) == 0 {
		return nil
	}
	if minActions < 0 {
		minActions = 0
	}
	for chunk := len(kconfuzzConfig.Actions) / 2; chunk >= 2; chunk /= 2 {
		for index := 0; index < len(kconfuzzConfig.Actions); {
			end := index + chunk
			if end > len(kconfuzzConfig.Actions) {
				end = len(kconfuzzConfig.Actions)
			}
			test := kconfuzzConfig.Clone()
			test.Actions = append(test.Actions[:index], test.Actions[end:]...)
			if len(test.Actions) < minActions {
				index += chunk
				continue
			}
			if job.reproducesKConfuzzSignal(p, call, target, test, 2) {
				kconfuzzConfig.Actions = prog.CloneKConfuzzConfigActions(test.Actions)
				job.info.Logf("[call #%d] kconfuzz action minimization removed chunk=%d (|actions| = %d)",
					call, end-index, len(kconfuzzConfig.Actions))
				continue
			}
			index += chunk
		}
	}
	if !perAction {
		return kconfuzzConfig
	}
	for index := 0; index < len(kconfuzzConfig.Actions); {
		test := kconfuzzConfig.Clone()
		test.Actions = append(test.Actions[:index], test.Actions[index+1:]...)
		if len(test.Actions) < minActions {
			index++
			continue
		}
		if job.reproducesKConfuzzSignal(p, call, target, test, 2) {
			kconfuzzConfig.Actions = prog.CloneKConfuzzConfigActions(test.Actions)
			job.info.Logf("[call #%d] kconfuzz action minimization removed action (|actions| = %d)",
				call, len(kconfuzzConfig.Actions))
			continue
		}
		index++
	}
	return kconfuzzConfig
}

func (job *triageJob) reproducesKConfuzzSignal(p *prog.Prog, call int, target signal.Signal,
	kconfuzzConfig *prog.KConfuzzConfigContext, attempts int) bool {
	_, ok := job.probeKConfuzzSignal(p, call, target, kconfuzzConfig, attempts)
	return ok
}

type kconfuzzSignalProbe struct {
	Signal   signal.Signal
	Cover    cover.Cover
	RawCover []uint64
}

func (job *triageJob) probeKConfuzzSignal(p *prog.Prog, call int, target signal.Signal,
	kconfuzzConfig *prog.KConfuzzConfigContext, attempts int) (kconfuzzSignalProbe, bool) {
	var probe kconfuzzSignalProbe
	for i := 0; i < attempts; i++ {
		result := job.executeWithKConfuzz(&queue.Request{
			Prog:            p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: []int{call},
			Stat:            job.fuzzer.statExecMinimize,
		}, progInTriage, kconfuzzConfig, kconfuzzConfig == nil || len(kconfuzzConfig.Actions) == 0)
		if result.Stop() || result.Info == nil {
			return probe, false
		}
		inf := callInfo(result.Info, call)
		if inf == nil {
			continue
		}
		probe.Signal.Merge(signal.FromRaw(inf.Signal, signalPrio(p, inf, call)))
		probe.Cover.Merge(inf.Cover)
		if len(probe.RawCover) == 0 && job.fuzzer.Config.FetchRawCover {
			probe.RawCover = append([]uint64(nil), inf.Cover...)
		}
		if signalContainsAll(target, probe.Signal) {
			return probe, true
		}
	}
	return probe, false
}

func callInfo(info *flatrpc.ProgInfo, call int) *flatrpc.CallInfo {
	if info == nil {
		return nil
	}
	if call == -1 {
		return info.Extra
	}
	if call < 0 || call >= len(info.Calls) {
		return nil
	}
	return info.Calls[call]
}

func kconfuzzAnchorSignal(s signal.Signal) signal.Signal {
	raw := s.ToRaw()
	if len(raw) == 0 {
		return nil
	}
	sort.Slice(raw, func(i, j int) bool {
		return raw[i] < raw[j]
	})
	return signal.FromRaw(raw[:1], 0)
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		if call < 0 || call >= len(info.Calls) {
			return false
		}
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) signal.Signal {
	inf := info.Extra
	if call != -1 {
		if call < 0 || call >= len(info.Calls) {
			return nil
		}
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
}

func signalPreview(s signal.Signal) string {
	if s.Len() > 0 && s.Len() <= 3 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range s.ToRaw() {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func (job *triageJob) getInfo() *JobInfo {
	return job.info
}

type smashJob struct {
	exec              queue.Executor
	p                 *prog.Prog
	kconfuzzConfig    *prog.KConfuzzConfigContext
	kconfuzzOriginSig string
	info              *JobInfo
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	fuzzer.Logf(2, "smashing the program %s:", job.p)
	job.info.Logf("\n%s", job.p.Serialize())

	const iters = 25
	rnd := fuzzer.rand()
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		p.Mutate(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:                  p,
			ExecOpts:              setFlags(flatrpc.ExecFlagCollectSignal),
			KConfuzzConfigContext: job.kconfuzzConfig.CloneForProg(p),
			KConfuzzOriginSig:     job.kconfuzzOriginSig,
			Stat:                  fuzzer.statExecSmash,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
	}
}

func (job *smashJob) getInfo() *JobInfo {
	return job.info
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec              queue.Executor
	p                 *prog.Prog
	call              int
	kconfuzzConfig    *prog.KConfuzzConfigContext
	kconfuzzOriginSig string
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:                  newProg,
			KConfuzzConfigContext: job.kconfuzzConfig.CloneForProg(newProg),
			KConfuzzOriginSig:     job.kconfuzzOriginSig,
			Stat:                  fuzzer.statExecFaultInject,
		})
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	exec              queue.Executor
	p                 *prog.Prog
	call              int
	kconfuzzConfig    *prog.KConfuzzConfigContext
	kconfuzzOriginSig string
	info              *JobInfo
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program several times to get comparisons from KCOV.
	// Additional executions lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p
	job.info.Logf("\n%s", p.Serialize())

	var comps prog.CompMap
	for i := 0; i < 3; i++ {
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:                  p,
			ExecOpts:              setFlags(flatrpc.ExecFlagCollectComps),
			KConfuzzConfigContext: job.kconfuzzConfig.CloneForProg(p),
			KConfuzzOriginSig:     job.kconfuzzOriginSig,
			Stat:                  fuzzer.statExecSeed,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if result.Info == nil || len(result.Info.Calls[job.call].Comps) == 0 {
			continue
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	job.info.Logf("stable comps: %d", comps.Len())
	fuzzer.hintsLimiter.Limit(comps)
	job.info.Logf("stable comps (after the hints limiter): %d", comps.Len())

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			defer job.info.Execs.Add(1)
			result := fuzzer.execute(job.exec, &queue.Request{
				Prog:                  p,
				ExecOpts:              setFlags(flatrpc.ExecFlagCollectSignal),
				KConfuzzConfigContext: job.kconfuzzConfig.CloneForProg(p),
				KConfuzzOriginSig:     job.kconfuzzOriginSig,
				Stat:                  fuzzer.statExecHint,
			})
			return !result.Stop()
		})
}

func (job *hintsJob) getInfo() *JobInfo {
	return job.info
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Logf(logFmt string, args ...any) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	fmt.Fprintf(&sb.buf, "%s: ", time.Now().Format(time.DateTime))
	fmt.Fprintf(&sb.buf, logFmt, args...)
	sb.buf.WriteByte('\n')
}

func (sb *syncBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Bytes()
}
