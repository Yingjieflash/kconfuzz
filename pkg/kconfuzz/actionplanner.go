// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfuzz

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
)

const RelationTableEnv = "SYZ_KCONFUZZ_RELATION_TABLE"

const (
	debugEnv              = "SYZ_KCONFUZZ_DEBUG"
	ActionStrategyEnv     = "SYZ_KCONFUZZ_ACTION_STRATEGY"
	MaxActionsEnv         = "SYZ_KCONFUZZ_MAX_ACTIONS"
	MaxActionsPerCallEnv  = "SYZ_KCONFUZZ_MAX_ACTIONS_PER_CALL"
	RandomActionsEnv      = "SYZ_KCONFUZZ_RANDOM_ACTIONS"
	RelatedActionsEnv     = "SYZ_KCONFUZZ_RELATED_ACTIONS"
	AuditFileEnv          = "SYZ_KCONFUZZ_AUDIT_FILE"
	ChoiceWeightEnv       = "SYZ_KCONFUZZ_CHOICE_WEIGHT"
	ChoiceMaxCallsEnv     = "SYZ_KCONFUZZ_CHOICE_MAX_CALLS_PER_PARAM"
	DisableActionsEnv     = "SYZ_KCONFUZZ_DISABLE_ACTIONS"
	DisableChoiceEnv      = "SYZ_KCONFUZZ_DISABLE_CHOICE"
	DisableMetadataEnv    = "SYZ_KCONFUZZ_DISABLE_METADATA"
	SaveMaxActionsEnv     = "SYZ_KCONFUZZ_SAVE_MAX_ACTIONS"
	RiskyMaxActionsEnv    = "SYZ_KCONFUZZ_RISKY_MAX_ACTIONS"
	RiskySaveMaxEnv       = "SYZ_KCONFUZZ_RISKY_SAVE_MAX_ACTIONS"
	DisableSeedPenaltyEnv = "SYZ_KCONFUZZ_DISABLE_SEED_PENALTY"
)

const unlimitedActions = -1

type Strategy int

const (
	StrategySequence Strategy = iota
	StrategyCall
	StrategyBoth
)

type Options struct {
	Strategy                 Strategy
	MaxActionsPerProgram     int
	MaxActionsPerCall        int
	RandomActionsPerProgram  int
	RelatedActionsPerProgram int
}

type ConfigParam struct {
	Name                       string
	ID                         uint64
	ValueCount                 uint64
	Domain                     string
	ValueDomain                string
	AutoSafe                   bool
	Mutator                    bool
	MutatorConfidence          string
	MutatorKind                string
	MutatorFamily              string
	MutatorProbTfuzz           uint64
	MutatorProbSeed            uint64
	MutatorProbRandomLegal     uint64
	MutatorProbOutOfDomain     uint64
	MutatorTfuzzValueIDs       []uint64
	MutatorSeedValueIDs        []uint64
	MutatorRandomValueIDs      []uint64
	MutatorOutOfDomainValueIDs []uint64
}

type Planner struct {
	callToParams map[string][]ConfigParam
	edgeCount    int
	audit        Audit
}

type Audit struct {
	Event                        string         `json:"event,omitempty"`
	Path                         string         `json:"path,omitempty"`
	RawRows                      int            `json:"raw_rows"`
	LoadedEdges                  int            `json:"loaded_edges"`
	LoadedCalls                  int            `json:"loaded_calls"`
	LoadedParams                 int            `json:"loaded_params"`
	DroppedMissingParam          int            `json:"dropped_missing_param"`
	DroppedMissingCall           int            `json:"dropped_missing_call"`
	DroppedUnsafeParam           int            `json:"dropped_unsafe_param"`
	DroppedDomainMismatch        int            `json:"dropped_domain_mismatch"`
	DroppedGenericDomain         int            `json:"dropped_generic_domain"`
	LoadedParamDomains           map[string]int `json:"loaded_param_domains,omitempty"`
	LoadedParamValueDomains      map[string]int `json:"loaded_param_value_domains,omitempty"`
	ChoiceInputCalls             int            `json:"choice_input_calls,omitempty"`
	ChoiceUnsupportedCalls       int            `json:"choice_unsupported_calls,omitempty"`
	ChoiceDisabledCalls          int            `json:"choice_disabled_calls,omitempty"`
	ChoiceFilteredCalls          int            `json:"choice_filtered_calls,omitempty"`
	ChoiceParamGroups            int            `json:"choice_param_groups,omitempty"`
	ChoiceDroppedSingletonParams int            `json:"choice_dropped_singleton_params,omitempty"`
	ChoiceRelationPairs          int            `json:"choice_relation_pairs,omitempty"`
	ChoiceBoostEdges             int            `json:"choice_boost_edges,omitempty"`
	ChoiceWeight                 int            `json:"choice_weight,omitempty"`
}

type EnvFailureAudit struct {
	Event       string                  `json:"event"`
	ProgramSig  string                  `json:"program_sig,omitempty"`
	ConfigSig   string                  `json:"config_sig,omitempty"`
	Status      string                  `json:"status,omitempty"`
	CrashTitle  string                  `json:"crash_title,omitempty"`
	Strategy    string                  `json:"strategy,omitempty"`
	Source      string                  `json:"source,omitempty"`
	Calls       []string                `json:"calls,omitempty"`
	ActionCount int                     `json:"action_count"`
	Actions     []EnvFailureAuditAction `json:"actions,omitempty"`
}

type EnvFailureAuditAction struct {
	BeforeCall int    `json:"before_call"`
	ParamID    uint64 `json:"param_id"`
	Param      string `json:"param,omitempty"`
	ValueID    uint64 `json:"value_id"`
	Value      string `json:"value,omitempty"`
	Flags      uint64 `json:"flags,omitempty"`
}

type relationRow struct {
	Param            string `json:"param"`
	ParamDomain      string `json:"param_domain"`
	SyzkallerCall    string `json:"syzkaller_call"`
	DescriptorDomain string `json:"descriptor_domain"`
}

func LoadRelationTable(path string) (*Planner, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	audit := Audit{
		Path:                    path,
		LoadedParamDomains:      make(map[string]int),
		LoadedParamValueDomains: make(map[string]int),
	}
	byCall := make(map[string]map[uint64]ConfigParam)
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 16*1024*1024)
	for scanner.Scan() {
		audit.RawRows++
		var row relationRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		param, ok := SupportedParams[row.Param]
		if !ok {
			audit.DroppedMissingParam++
			continue
		}
		if row.SyzkallerCall == "" {
			audit.DroppedMissingCall++
			continue
		}
		if !allowedRelatedParam(param) {
			audit.DroppedUnsafeParam++
			continue
		}
		// Keep the executor-action MVP conservative: generic edges are too noisy
		// for automatic parameter writes.
		if row.DescriptorDomain == "generic" {
			audit.DroppedGenericDomain++
			continue
		}
		if row.ParamDomain != row.DescriptorDomain {
			audit.DroppedDomainMismatch++
			continue
		}
		if byCall[row.SyzkallerCall] == nil {
			byCall[row.SyzkallerCall] = make(map[uint64]ConfigParam)
		}
		byCall[row.SyzkallerCall][param.ID] = param
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	callToParams := make(map[string][]ConfigParam)
	edgeCount := 0
	loadedParamIDs := make(map[uint64]bool)
	for call, params := range byCall {
		for _, param := range params {
			callToParams[call] = append(callToParams[call], param)
			loadedParamIDs[param.ID] = true
			audit.LoadedParamDomains[param.Domain]++
			audit.LoadedParamValueDomains[param.ValueDomain]++
		}
		sort.Slice(callToParams[call], func(i, j int) bool {
			return callToParams[call][i].ID < callToParams[call][j].ID
		})
		edgeCount += len(callToParams[call])
	}
	audit.LoadedCalls = len(callToParams)
	audit.LoadedEdges = edgeCount
	audit.LoadedParams = len(loadedParamIDs)
	return &Planner{callToParams: callToParams, edgeCount: edgeCount, audit: audit}, nil
}

func (p *Planner) Plan(prg *prog.Prog, opts Options) []prog.KConfuzzConfigAction {
	if p == nil || prg == nil {
		return nil
	}
	opts = normalizeOptions(opts, 4)
	used := make(map[uint64]bool)
	actions := p.planRandomLevel(prg, opts.RandomActionsPerProgram, used)

	remaining := remainingActions(opts.MaxActionsPerProgram, len(actions))
	relatedLimit := opts.RelatedActionsPerProgram
	if isUnlimited(relatedLimit) {
		relatedLimit = remaining
	} else if !isUnlimited(remaining) && relatedLimit > remaining {
		relatedLimit = remaining
	}
	if relatedLimit == 0 {
		return actions
	}
	relatedOpts := opts
	relatedOpts.MaxActionsPerProgram = relatedLimit
	relatedOpts.RandomActionsPerProgram = 0
	actions = append(actions, p.planRelated(prg, relatedOpts, used)...)
	return actions
}

func normalizeOptions(opts Options, defaultMaxActions int) Options {
	if opts.MaxActionsPerProgram == 0 {
		opts.MaxActionsPerProgram = defaultMaxActions
	} else if opts.MaxActionsPerProgram < 0 {
		opts.MaxActionsPerProgram = unlimitedActions
	}
	if opts.MaxActionsPerCall <= 0 {
		opts.MaxActionsPerCall = 1
	}
	if opts.RandomActionsPerProgram < 0 {
		opts.RandomActionsPerProgram = 0
	}
	if !isUnlimited(opts.MaxActionsPerProgram) &&
		opts.RandomActionsPerProgram > opts.MaxActionsPerProgram {
		opts.RandomActionsPerProgram = opts.MaxActionsPerProgram
	}
	if opts.RelatedActionsPerProgram == 0 {
		opts.RelatedActionsPerProgram = remainingActions(opts.MaxActionsPerProgram,
			opts.RandomActionsPerProgram)
	}
	if opts.RelatedActionsPerProgram < 0 {
		opts.RelatedActionsPerProgram = unlimitedActions
	}
	if !isUnlimited(opts.MaxActionsPerProgram) &&
		!isUnlimited(opts.RelatedActionsPerProgram) &&
		opts.RandomActionsPerProgram+opts.RelatedActionsPerProgram > opts.MaxActionsPerProgram {
		opts.RelatedActionsPerProgram = opts.MaxActionsPerProgram - opts.RandomActionsPerProgram
	}
	return opts
}

func isUnlimited(limit int) bool {
	return limit < 0
}

func remainingActions(limit, used int) int {
	if isUnlimited(limit) {
		return unlimitedActions
	}
	if used >= limit {
		return 0
	}
	return limit - used
}

func (p *Planner) planRelated(
	prg *prog.Prog,
	opts Options,
	skip map[uint64]bool,
) []prog.KConfuzzConfigAction {
	switch opts.Strategy {
	case StrategyCall:
		return p.planCallLevel(prg, opts, skip)
	case StrategyBoth:
		return p.planBothLevels(prg, opts, skip)
	default:
		return p.planSequenceLevel(prg, opts, skip)
	}
}

func (p *Planner) PlanContext(prg *prog.Prog, opts Options, source string) *prog.KConfuzzConfigContext {
	actions := p.Plan(prg, opts)
	if len(actions) == 0 {
		return nil
	}
	ctx := &prog.KConfuzzConfigContext{
		Strategy: strategyName(opts.Strategy),
		Source:   source,
		Actions:  prog.NormalizeKConfuzzConfigActions(prg, actions),
	}
	return ctx
}

func (p *Planner) planSequenceLevel(
	prg *prog.Prog,
	opts Options,
	skip map[uint64]bool,
) []prog.KConfuzzConfigAction {
	seen := make(map[uint64]ConfigParam)
	for _, call := range prg.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		for _, param := range p.callToParams[call.Meta.Name] {
			if skip[param.ID] {
				continue
			}
			seen[param.ID] = param
		}
	}
	seed := planSeed(prg)
	params := shuffledParams(seen, seed)
	if !isUnlimited(opts.MaxActionsPerProgram) && len(params) > opts.MaxActionsPerProgram {
		params = params[:opts.MaxActionsPerProgram]
	}
	actions := make([]prog.KConfuzzConfigAction, 0, len(params))
	for i, param := range params {
		actions = append(actions, configActionWithSeed(0, valueSeed(seed, i, 0, param), param))
		skip[param.ID] = true
	}
	return actions
}

func (p *Planner) planCallLevel(
	prg *prog.Prog,
	opts Options,
	skip map[uint64]bool,
) []prog.KConfuzzConfigAction {
	var actions []prog.KConfuzzConfigAction
	seen := make(map[uint64]bool)
	for id := range skip {
		seen[id] = true
	}
	seed := planSeed(prg)
	for index, call := range prg.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		addedForCall := 0
		params := shuffledParamSlice(p.callToParams[call.Meta.Name],
			mix64(seed^uint64(index+1)))
		for _, param := range params {
			if seen[param.ID] {
				continue
			}
			seen[param.ID] = true
			skip[param.ID] = true
			actions = append(actions, configActionWithSeed(index,
				valueSeed(seed, len(actions), index, param), param))
			addedForCall++
			if !isUnlimited(opts.MaxActionsPerProgram) &&
				len(actions) >= opts.MaxActionsPerProgram {
				return actions
			}
			if addedForCall >= opts.MaxActionsPerCall {
				break
			}
		}
	}
	return actions
}

func (p *Planner) isMixedRiskProgram(prg *prog.Prog) bool {
	return ProgramHasEnvRisk(prg) && p.hasRelatedCall(prg)
}

func (p *Planner) hasRelatedCall(prg *prog.Prog) bool {
	if p == nil || prg == nil {
		return false
	}
	for _, call := range prg.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if len(p.callToParams[call.Meta.Name]) != 0 {
			return true
		}
	}
	return false
}

func (p *Planner) relatedCallIndexByParam(prg *prog.Prog) map[uint64]int {
	ret := make(map[uint64]int)
	if p == nil || prg == nil {
		return ret
	}
	for index, call := range prg.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		for _, param := range p.callToParams[call.Meta.Name] {
			if _, ok := ret[param.ID]; !ok {
				ret[param.ID] = index
			}
		}
	}
	return ret
}

func (p *Planner) tightenRiskyContext(ctx *prog.KConfuzzConfigContext, prg *prog.Prog,
	limit int, suffix string) *prog.KConfuzzConfigContext {
	ctx = ctx.CloneForProg(prg)
	if ctx == nil || len(ctx.Actions) == 0 || !p.isMixedRiskProgram(prg) {
		return ctx
	}
	byParam := p.relatedCallIndexByParam(prg)
	ret := make([]prog.KConfuzzConfigAction, 0, len(ctx.Actions))
	seen := make(map[uint64]bool)
	for _, action := range ctx.Actions {
		beforeCall, ok := byParam[action.ParamID]
		if !ok || seen[action.ParamID] {
			continue
		}
		action.BeforeCall = beforeCall
		ret = append(ret, action)
		seen[action.ParamID] = true
	}
	if !isUnlimited(limit) && len(ret) > limit {
		ret = limitActions(ret, limit)
	}
	ctx.Actions = prog.NormalizeKConfuzzConfigActions(prg, ret)
	if len(ctx.Actions) == 0 {
		return nil
	}
	if suffix != "" && !strings.Contains(ctx.Source, suffix) {
		if ctx.Source == "" {
			ctx.Source = suffix
		} else {
			ctx.Source += "/" + suffix
		}
	}
	return ctx
}

func (p *Planner) planBothLevels(
	prg *prog.Prog,
	opts Options,
	skip map[uint64]bool,
) []prog.KConfuzzConfigAction {
	actions := p.planSequenceLevel(prg, opts, skip)
	if !isUnlimited(opts.MaxActionsPerProgram) && len(actions) >= opts.MaxActionsPerProgram {
		return actions
	}
	remaining := opts
	remaining.MaxActionsPerProgram = remainingActions(opts.MaxActionsPerProgram, len(actions))
	callActions := p.planCallLevel(prg, remaining, skip)
	for _, action := range callActions {
		actions = append(actions, action)
		if !isUnlimited(opts.MaxActionsPerProgram) && len(actions) >= opts.MaxActionsPerProgram {
			break
		}
	}
	return actions
}

func (p *Planner) planRandomLevel(
	prg *prog.Prog,
	limit int,
	skip map[uint64]bool,
) []prog.KConfuzzConfigAction {
	if limit <= 0 {
		return nil
	}
	params := randomCandidateParams()
	if len(params) == 0 {
		return nil
	}
	seed := planSeed(prg)
	start := int(seed % uint64(len(params)))
	step := 1
	if len(params) > 1 {
		step = int(seed%uint64(len(params)-1)) + 1
		for gcd(step, len(params)) != 1 {
			step++
			if step >= len(params) {
				step = 1
			}
		}
	}
	baseValueSeed := seed % 1000000
	actions := make([]prog.KConfuzzConfigAction, 0, limit)
	for seen, index := 0, start; seen < len(params) && len(actions) < limit; seen++ {
		param := params[index]
		if !skip[param.ID] {
			actions = append(actions, configActionWithSeed(0,
				valueSeed(baseValueSeed, len(actions), 0, param), param))
			skip[param.ID] = true
		}
		index = (index + step) % len(params)
	}
	return actions
}

func planSeed(prg *prog.Prog) uint64 {
	h := fnv.New64a()
	if prg != nil {
		_, _ = h.Write(prg.Serialize())
		for index, call := range prg.Calls {
			name := ""
			if call != nil && call.Meta != nil {
				name = call.Meta.Name
			}
			fmt.Fprintf(h, "%d:%s\n", index, name)
		}
	}
	seed := h.Sum64()
	if seed == 0 {
		return 1
	}
	return seed
}

func mix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func valueSeed(programSeed uint64, actionIndex, callIndex int, param ConfigParam) uint64 {
	seed := programSeed ^ (param.ID * 0x9e3779b97f4a7c15)
	seed ^= uint64(actionIndex+1) * 0xbf58476d1ce4e5b9
	seed ^= uint64(callIndex+1) * 0x94d049bb133111eb
	return mix64(seed)
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		return -a
	}
	return a
}

var randomCandidateCache struct {
	once   sync.Once
	params []ConfigParam
}

func randomCandidateParams() []ConfigParam {
	randomCandidateCache.once.Do(func() {
		for _, param := range SupportedParams {
			if !safeRandomParam(param) {
				continue
			}
			randomCandidateCache.params = append(randomCandidateCache.params, param)
		}
		sort.Slice(randomCandidateCache.params, func(i, j int) bool {
			return randomCandidateCache.params[i].ID < randomCandidateCache.params[j].ID
		})
	})
	return randomCandidateCache.params
}

func ProgramHasEnvRisk(prg *prog.Prog) bool {
	if prg == nil {
		return false
	}
	weakFamilies := make(map[string]bool)
	for _, call := range prg.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		strong, weak := envRiskCall(call.Meta.Name)
		if strong {
			return true
		}
		if weak != "" {
			weakFamilies[weak] = true
		}
	}
	return len(weakFamilies) >= 2
}

func envRiskCall(name string) (bool, string) {
	name = strings.ToLower(name)
	for _, token := range []string{
		"fuse",
		"mount",
		"umount",
		"fsopen",
		"fsmount",
		"fsconfig",
		"fspick",
		"open_tree",
		"move_mount",
		"pivot_root",
		"loop",
		"io_uring",
	} {
		if strings.Contains(name, token) {
			return true, ""
		}
	}
	for _, token := range []string{"mmap", "bpf", "xattr"} {
		if strings.Contains(name, token) {
			return false, token
		}
	}
	return false, ""
}

func safeRandomParam(param ConfigParam) bool {
	if !conservativeRandomParam(param) {
		return false
	}
	switch param.MutatorFamily {
	case "bool", "enum", "bitmask":
	default:
		return false
	}
	return true
}

func allowedRelatedParam(param ConfigParam) bool {
	if !param.Mutator || param.ValueCount <= 1 {
		return false
	}
	return !hardBlockedConfigParam(param)
}

func conservativeRandomParam(param ConfigParam) bool {
	if !allowedRelatedParam(param) || !param.AutoSafe {
		return false
	}
	if param.Domain == "generic" {
		return false
	}
	switch param.MutatorConfidence {
	case "high", "medium":
	default:
		return false
	}
	switch param.MutatorKind {
	case "unbounded_numeric", "unbounded_numeric_taint", "bounded_numeric_taint":
		return false
	}
	if strings.Contains(strings.ToLower(param.Name), "disable") {
		return false
	}
	return true
}

func hardBlockedConfigParam(param ConfigParam) bool {
	name := strings.ToLower(param.Name)
	for _, token := range []string{
		"panic",
		"watchdog",
		"lockup",
		"hung_task",
		"sysrq",
		"modules_disabled",
		"kexec",
	} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func sortedParams(params map[uint64]ConfigParam) []ConfigParam {
	ret := make([]ConfigParam, 0, len(params))
	for _, param := range params {
		ret = append(ret, param)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].ID < ret[j].ID
	})
	return ret
}

func shuffledParams(params map[uint64]ConfigParam, seed uint64) []ConfigParam {
	return shuffledParamSlice(sortedParams(params), seed)
}

func shuffledParamSlice(params []ConfigParam, seed uint64) []ConfigParam {
	ret := append([]ConfigParam(nil), params...)
	sort.Slice(ret, func(i, j int) bool {
		hi := mix64(seed ^ ret[i].ID)
		hj := mix64(seed ^ ret[j].ID)
		if hi == hj {
			return ret[i].ID < ret[j].ID
		}
		return hi < hj
	})
	return ret
}

func nextValue(callIndex int, param ConfigParam) uint64 {
	if param.ValueCount <= 1 {
		return 0
	}
	return uint64(callIndex+int(param.ID)+1) % param.ValueCount
}

func configAction(beforeCall, callIndex int, param ConfigParam) prog.KConfuzzConfigAction {
	valueID, flags := plannedValue(callIndex, param)
	return prog.KConfuzzConfigAction{
		BeforeCall: beforeCall,
		ParamID:    param.ID,
		ValueID:    valueID,
		Flags:      flags,
	}
}

func configActionWithSeed(beforeCall int, seed uint64, param ConfigParam) prog.KConfuzzConfigAction {
	valueID, flags := plannedValueFromSeed(seed, param)
	return prog.KConfuzzConfigAction{
		BeforeCall: beforeCall,
		ParamID:    param.ID,
		ValueID:    valueID,
		Flags:      flags,
	}
}

func plannedValue(callIndex int, param ConfigParam) (uint64, uint64) {
	return plannedValueFromSeed(uint64(callIndex)+param.ID+1, param)
}

func plannedValueFromSeed(seed uint64, param ConfigParam) (uint64, uint64) {
	if valueID, ok := plannedMutatorValue(seed, param); ok {
		return valueID, 0
	}
	if param.ValueCount <= 1 {
		return 0, prog.KConfuzzConfigFlagFlip
	}
	return seed % param.ValueCount, prog.KConfuzzConfigFlagFlip
}

func plannedMutatorValue(seed uint64, param ConfigParam) (uint64, bool) {
	if !param.Mutator {
		return 0, false
	}
	for _, ids := range [][]uint64{
		param.MutatorTfuzzValueIDs,
		param.MutatorSeedValueIDs,
		param.MutatorRandomValueIDs,
	} {
		if valueID, ok := deterministicValueID(ids, param.ValueCount, seed); ok {
			return valueID, true
		}
	}
	return 0, false
}

func deterministicValueID(ids []uint64, valueCount uint64, seed uint64) (uint64, bool) {
	if valueCount == 0 || len(ids) == 0 {
		return 0, false
	}
	start := int(seed % uint64(len(ids)))
	for i := 0; i < len(ids); i++ {
		valueID := ids[(start+i)%len(ids)]
		if valueID < valueCount {
			return valueID, true
		}
	}
	return 0, false
}

func strategyName(strategy Strategy) string {
	switch strategy {
	case StrategyCall:
		return prog.KConfuzzConfigStrategyCall
	case StrategyBoth:
		return prog.KConfuzzConfigStrategyBoth
	default:
		return prog.KConfuzzConfigStrategySequence
	}
}

var envPlanner struct {
	once    sync.Once
	planner *Planner
}

func plannerFromEnv() *Planner {
	envPlanner.once.Do(func() {
		path := os.Getenv(RelationTableEnv)
		if path == "" {
			return
		}
		planner, err := LoadRelationTable(path)
		if err == nil {
			envPlanner.planner = planner
			debugf("loaded relation table %s: calls=%d edges=%d", path,
				len(planner.callToParams), planner.edgeCount)
			planner.writeAudit("relation-load", planner.audit)
		} else {
			debugf("failed to load relation table %s: %v", path, err)
		}
	})
	return envPlanner.planner
}

func optionsFromEnv() Options {
	opts := Options{
		Strategy:                 strategyFromEnv(),
		MaxActionsPerProgram:     limitFromEnv(MaxActionsEnv, 8),
		MaxActionsPerCall:        intFromEnv(MaxActionsPerCallEnv, 1),
		RandomActionsPerProgram:  intFromEnv(RandomActionsEnv, 0),
		RelatedActionsPerProgram: limitFromEnv(RelatedActionsEnv, 8),
	}
	return normalizeOptions(opts, 8)
}

func strategyFromEnv() Strategy {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(ActionStrategyEnv))) {
	case "", prog.KConfuzzConfigStrategySequence:
		return StrategySequence
	case prog.KConfuzzConfigStrategyCall:
		return StrategyCall
	case prog.KConfuzzConfigStrategyBoth:
		return StrategyBoth
	default:
		debugf("unknown %s=%q, using sequence", ActionStrategyEnv, os.Getenv(ActionStrategyEnv))
		return StrategySequence
	}
}

func intFromEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		debugf("bad %s=%q, using %d", name, value, fallback)
		return fallback
	}
	return parsed
}

func limitFromEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		debugf("bad %s=%q, using %d", name, value, fallback)
		return fallback
	}
	if parsed == 0 {
		return unlimitedActions
	}
	return parsed
}

func PlanFromEnv(prg *prog.Prog) []prog.KConfuzzConfigAction {
	ctx := PlanContextFromEnv(prg)
	if ctx == nil {
		return nil
	}
	return prog.CloneKConfuzzConfigActions(ctx.Actions)
}

func PlanContextFromEnv(prg *prog.Prog) *prog.KConfuzzConfigContext {
	if !ActionsEnabled() {
		return nil
	}
	planner := plannerFromEnv()
	if planner == nil {
		return nil
	}
	opts := optionsFromEnv()
	ctx := planner.PlanContext(prg, opts, RelationTableEnv)
	if ctx != nil {
		debugf("planned %d %s config actions for %d calls", len(ctx.Actions),
			ctx.Strategy, len(prg.Calls))
	}
	return ctx
}

func MutateContext(ctx *prog.KConfuzzConfigContext, prg *prog.Prog, rnd *rand.Rand) *prog.KConfuzzConfigContext {
	ctx = ctx.CloneForProg(prg)
	if ctx == nil || len(ctx.Actions) == 0 {
		return ctx
	}
	ctx.Source = "inherited-mutated"
	switch rnd.Intn(3) {
	case 0:
		action := &ctx.Actions[rnd.Intn(len(ctx.Actions))]
		if param, ok := paramByID(action.ParamID); ok {
			mutateActionValue(action, param, rnd)
		}
	case 1:
		action := &ctx.Actions[rnd.Intn(len(ctx.Actions))]
		action.BeforeCall = rnd.Intn(len(prg.Calls) + 1)
	case 2:
		if len(ctx.Actions) > 1 {
			index := rnd.Intn(len(ctx.Actions))
			ctx.Actions = append(ctx.Actions[:index], ctx.Actions[index+1:]...)
		}
	}
	ctx.Actions = prog.NormalizeKConfuzzConfigActions(prg, ctx.Actions)
	ctx.Actions = FilterSupportedActions(ctx.Actions)
	if len(ctx.Actions) == 0 && !ctx.ConfigDependent {
		return nil
	}
	return ctx
}

func mutateActionValue(action *prog.KConfuzzConfigAction, param ConfigParam, rnd *rand.Rand) {
	if action == nil || param.ValueCount == 0 {
		return
	}
	if valueID, ok := chooseMutatorValueID(param, rnd); ok {
		action.ValueID = valueID
		action.Flags &^= prog.KConfuzzConfigFlagFlip
		return
	}
	if param.ValueCount <= 1 {
		return
	}
	delta := uint64(rnd.Intn(int(param.ValueCount-1)) + 1)
	action.ValueID = (action.ValueID + delta) % param.ValueCount
	action.Flags &^= prog.KConfuzzConfigFlagFlip
}

type mutatorPool struct {
	weight uint64
	ids    []uint64
}

func chooseMutatorValueID(param ConfigParam, rnd *rand.Rand) (uint64, bool) {
	if !param.Mutator || param.ValueCount == 0 {
		return 0, false
	}
	pools := []mutatorPool{
		{weight: param.MutatorProbTfuzz, ids: param.MutatorTfuzzValueIDs},
		{weight: param.MutatorProbSeed, ids: param.MutatorSeedValueIDs},
		{weight: param.MutatorProbRandomLegal, ids: param.MutatorRandomValueIDs},
	}
	var total uint64
	var filtered []mutatorPool
	for _, pool := range pools {
		if pool.weight == 0 || !hasValidValueID(pool.ids, param.ValueCount) {
			continue
		}
		total += pool.weight
		filtered = append(filtered, pool)
	}
	if total == 0 {
		for _, ids := range [][]uint64{
			param.MutatorTfuzzValueIDs,
			param.MutatorSeedValueIDs,
			param.MutatorRandomValueIDs,
		} {
			if valueID, ok := randomValueID(ids, param.ValueCount, rnd); ok {
				return valueID, true
			}
		}
		return 0, false
	}
	pick := uint64(rnd.Int63n(int64(total)))
	for _, pool := range filtered {
		if pick < pool.weight {
			return randomValueID(pool.ids, param.ValueCount, rnd)
		}
		pick -= pool.weight
	}
	return 0, false
}

func hasValidValueID(ids []uint64, valueCount uint64) bool {
	for _, id := range ids {
		if id < valueCount {
			return true
		}
	}
	return false
}

func randomValueID(ids []uint64, valueCount uint64, rnd *rand.Rand) (uint64, bool) {
	if valueCount == 0 || len(ids) == 0 {
		return 0, false
	}
	start := rnd.Intn(len(ids))
	for i := 0; i < len(ids); i++ {
		valueID := ids[(start+i)%len(ids)]
		if valueID < valueCount {
			return valueID, true
		}
	}
	return 0, false
}

func FilterSupportedActions(actions []prog.KConfuzzConfigAction) []prog.KConfuzzConfigAction {
	if len(actions) == 0 {
		return nil
	}
	ret := make([]prog.KConfuzzConfigAction, 0, len(actions))
	for _, action := range actions {
		param, ok := paramByID(action.ParamID)
		if !ok || !allowedRelatedParam(param) || param.ValueCount == 0 {
			continue
		}
		if action.ValueID >= param.ValueCount && action.Flags&prog.KConfuzzConfigFlagFlip == 0 {
			continue
		}
		ret = append(ret, action)
	}
	return ret
}

func FilterSupportedContext(ctx *prog.KConfuzzConfigContext, prg *prog.Prog) *prog.KConfuzzConfigContext {
	ctx = ctx.CloneForProg(prg)
	if ctx == nil {
		return nil
	}
	if ContextQuarantined(prg, ctx) {
		return nil
	}
	ctx.Actions = FilterSupportedActions(ctx.Actions)
	if len(ctx.Actions) == 0 && !ctx.ConfigDependent {
		return nil
	}
	if ContextQuarantined(prg, ctx) {
		return nil
	}
	return ctx
}

func TightenContextForSave(ctx *prog.KConfuzzConfigContext, prg *prog.Prog) *prog.KConfuzzConfigContext {
	return ctx.CloneForProg(prg)
}

func limitActions(actions []prog.KConfuzzConfigAction, limit int) []prog.KConfuzzConfigAction {
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

var quarantinedContexts sync.Map

func QuarantineContext(prg *prog.Prog, ctx *prog.KConfuzzConfigContext, reason string) {
	key := contextQuarantineKey(prg, ctx)
	if key == "" {
		return
	}
	quarantinedContexts.Store(key, reason)
	debugf("quarantined config context key=%s reason=%s actions=%d env_risk=%v",
		key, reason, len(ctx.Actions), ProgramHasEnvRisk(prg))
}

func ContextQuarantined(prg *prog.Prog, ctx *prog.KConfuzzConfigContext) bool {
	key := contextQuarantineKey(prg, ctx)
	if key == "" {
		return false
	}
	_, ok := quarantinedContexts.Load(key)
	return ok
}

func contextQuarantineKey(prg *prog.Prog, ctx *prog.KConfuzzConfigContext) (key string) {
	defer func() {
		if recover() != nil {
			key = ""
		}
	}()
	ctx = ctx.CloneForProg(prg)
	if prg == nil || ctx == nil || len(ctx.Actions) == 0 {
		return ""
	}
	return hash.String(prg.Serialize(), ctx.SignatureData())
}

func OutputLooksLikeEnvFailure(output []byte, err error) bool {
	return EnvFailureTitle(output, err) != ""
}

func EnvFailureTitle(output []byte, err error) string {
	text := strings.ToLower(string(output))
	if err != nil {
		text += "\n" + strings.ToLower(err.Error())
	}
	switch {
	case strings.Contains(text, "failed to mkdtemp"):
		return "SYZFAIL: failed to mkdtemp"
	case strings.Contains(text, "mkdir(syz-tmp) failed"):
		return "SYZFAIL: mkdir(syz-tmp) failed"
	case strings.Contains(text, "mmap of data segment failed"):
		return "SYZFAIL: mmap of data segment failed"
	case strings.Contains(text, "sigbus"):
		return "SYZFAIL: SIGBUS"
	case strings.Contains(text, "no space left on device"):
		return "SYZFAIL: no space left on device"
	}
	return ""
}

var paramsByID struct {
	sync.Once
	m map[uint64]ConfigParam
}

func ConfigParamByID(id uint64) (ConfigParam, bool) {
	paramsByID.Once.Do(func() {
		paramsByID.m = make(map[uint64]ConfigParam, len(SupportedParams))
		for _, param := range SupportedParams {
			paramsByID.m[param.ID] = param
		}
	})
	param, ok := paramsByID.m[id]
	return param, ok
}

func RecordEnvFailureAudit(prg *prog.Prog, ctx *prog.KConfuzzConfigContext,
	output []byte, err error, status string) {
	if prg == nil || ctx == nil || len(ctx.Actions) == 0 {
		return
	}
	title := EnvFailureTitle(output, err)
	if title == "" {
		return
	}
	ctx = ctx.CloneForProg(prg)
	if ctx == nil || len(ctx.Actions) == 0 {
		return
	}
	rec := EnvFailureAudit{
		Event:       "env-failure",
		ProgramSig:  hash.String(prg.Serialize()),
		ConfigSig:   hash.String(ctx.SignatureData()),
		Status:      status,
		CrashTitle:  title,
		Strategy:    ctx.Strategy,
		Source:      ctx.Source,
		ActionCount: len(ctx.Actions),
		Calls:       make([]string, 0, len(prg.Calls)),
		Actions:     make([]EnvFailureAuditAction, 0, len(ctx.Actions)),
	}
	for _, call := range prg.Calls {
		if call != nil && call.Meta != nil {
			rec.Calls = append(rec.Calls, call.Meta.Name)
		}
	}
	for _, action := range ctx.Actions {
		auditAction := EnvFailureAuditAction{
			BeforeCall: action.BeforeCall,
			ParamID:    action.ParamID,
			ValueID:    action.ValueID,
			Value:      ConfigValueString(action.ParamID, action.ValueID),
			Flags:      action.Flags,
		}
		if param, ok := ConfigParamByID(action.ParamID); ok {
			auditAction.Param = param.Name
		}
		rec.Actions = append(rec.Actions, auditAction)
	}
	writeAuditJSON(rec)
}

var penalizedSeeds struct {
	sync.Mutex
	scores map[string]int
}

func PenalizeSeed(sig, reason string) int {
	if sig == "" || !SeedPenaltyEnabled() {
		return 0
	}
	penalizedSeeds.Lock()
	defer penalizedSeeds.Unlock()
	if penalizedSeeds.scores == nil {
		penalizedSeeds.scores = make(map[string]int)
	}
	if penalizedSeeds.scores[sig] < 8 {
		penalizedSeeds.scores[sig]++
	}
	score := penalizedSeeds.scores[sig]
	debugf("penalized config seed sig=%s score=%d reason=%s", sig, score, reason)
	return score
}

func SeedPenalty(sig string) int {
	if sig == "" || !SeedPenaltyEnabled() {
		return 0
	}
	penalizedSeeds.Lock()
	defer penalizedSeeds.Unlock()
	return penalizedSeeds.scores[sig]
}

func ShouldSkipPenalizedSeed(sig string, rnd *rand.Rand) bool {
	score := SeedPenalty(sig)
	if score <= 0 || rnd == nil {
		return false
	}
	if score > 4 {
		score = 4
	}
	keepEvery := 1 << score
	return rnd.Intn(keepEvery) != 0
}

func SeedPenaltyEnabled() bool {
	return !envEnabled(DisableSeedPenaltyEnv)
}

func DangerousConfigResult(ctx *prog.KConfuzzConfigContext, output []byte, err error, crashed, hanged bool) bool {
	if ctx == nil || len(ctx.Actions) == 0 {
		return false
	}
	if OutputLooksLikeEnvFailure(output, err) {
		return true
	}
	if crashed {
		return true
	}
	return hanged && len(ctx.Actions) >= dangerousActionThreshold(2, 4)
}

func dangerousActionThreshold(multiplier, fallback int) int {
	limit := RiskyMaxActions()
	if isUnlimited(limit) || limit <= 0 {
		return fallback
	}
	return limit * multiplier
}

func RelationChoiceBoostsFromEnv(target *prog.Target, enabled map[*prog.Syscall]bool) []prog.ChoiceTableBoost {
	if !ChoiceEnabled() {
		return nil
	}
	planner := plannerFromEnv()
	if planner == nil || target == nil {
		return nil
	}
	choiceWeight := intFromEnv(ChoiceWeightEnv, 3)
	if choiceWeight <= 0 {
		choiceWeight = 3
	}
	maxCallsPerParam := intFromEnv(ChoiceMaxCallsEnv, 12)
	if maxCallsPerParam <= 1 {
		maxCallsPerParam = 12
	}

	byParam := make(map[uint64]map[int]*prog.Syscall)
	audit := planner.audit
	audit.Event = "choice-boost-build"
	audit.ChoiceWeight = choiceWeight
	for callName, params := range planner.callToParams {
		audit.ChoiceInputCalls++
		meta := target.SyscallMap[callName]
		if meta == nil {
			audit.ChoiceUnsupportedCalls++
			continue
		}
		if meta.Attrs.NoGenerate || meta.Attrs.Disabled {
			audit.ChoiceDisabledCalls++
			continue
		}
		if enabled != nil && !enabled[meta] {
			audit.ChoiceFilteredCalls++
			continue
		}
		for _, param := range params {
			if byParam[param.ID] == nil {
				byParam[param.ID] = make(map[int]*prog.Syscall)
			}
			byParam[param.ID][meta.ID] = meta
		}
	}

	paramIDs := make([]uint64, 0, len(byParam))
	for id := range byParam {
		paramIDs = append(paramIDs, id)
	}
	sort.Slice(paramIDs, func(i, j int) bool {
		return paramIDs[i] < paramIDs[j]
	})

	type pair struct {
		from int
		to   int
	}
	weights := make(map[pair]int32)
	for _, id := range paramIDs {
		callMap := byParam[id]
		calls := make([]*prog.Syscall, 0, len(callMap))
		for _, call := range callMap {
			calls = append(calls, call)
		}
		sort.Slice(calls, func(i, j int) bool {
			return calls[i].ID < calls[j].ID
		})
		if len(calls) < 2 {
			continue
		}
		audit.ChoiceParamGroups++
		if len(calls) > maxCallsPerParam {
			calls = calls[:maxCallsPerParam]
		}
		audit.ChoiceRelationPairs += len(calls) * (len(calls) - 1) / 2
		for _, from := range calls {
			for _, to := range calls {
				if from.ID == to.ID {
					continue
				}
				weights[pair{from: from.ID, to: to.ID}] += int32(choiceWeight)
			}
		}
	}
	audit.ChoiceDroppedSingletonParams = len(byParam) - audit.ChoiceParamGroups

	pairs := make([]pair, 0, len(weights))
	for pair := range weights {
		pairs = append(pairs, pair)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].from == pairs[j].from {
			return pairs[i].to < pairs[j].to
		}
		return pairs[i].from < pairs[j].from
	})
	boosts := make([]prog.ChoiceTableBoost, 0, len(pairs))
	for _, pair := range pairs {
		boosts = append(boosts, prog.ChoiceTableBoost{
			From:   target.Syscalls[pair.from],
			To:     target.Syscalls[pair.to],
			Weight: weights[pair],
		})
	}
	audit.ChoiceBoostEdges = len(boosts)
	if len(boosts) != 0 {
		debugf("built %d relation choice-table boosts from %d parameter groups",
			len(boosts), audit.ChoiceParamGroups)
	}
	planner.writeAudit("choice-boost-build", audit)
	return boosts
}

var paramByIDCache struct {
	once sync.Once
	m    map[uint64]ConfigParam
}

func paramByID(id uint64) (ConfigParam, bool) {
	paramByIDCache.once.Do(func() {
		paramByIDCache.m = make(map[uint64]ConfigParam, len(SupportedParams))
		for _, param := range SupportedParams {
			paramByIDCache.m[param.ID] = param
		}
	})
	param, ok := paramByIDCache.m[id]
	return param, ok
}

func (p *Planner) writeAudit(event string, audit Audit) {
	audit.Event = event
	writeAuditJSON(audit)
}

func writeAuditJSON(record interface{}) {
	data, err := json.Marshal(record)
	if err != nil {
		debugf("failed to marshal audit event: %v", err)
		return
	}
	debugf("audit %s", data)
	path := strings.TrimSpace(os.Getenv(AuditFileEnv))
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		debugf("failed to open audit file %s: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil && err != io.ErrShortWrite {
		debugf("failed to write audit file %s: %v", path, err)
	}
}

func Debugf(format string, args ...interface{}) {
	if os.Getenv(debugEnv) == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "kconfuzz: "+format+"\n", args...)
}

func debugf(format string, args ...interface{}) {
	Debugf(format, args...)
}

func ActionsEnabled() bool {
	return !envEnabled(DisableActionsEnv)
}

func ChoiceEnabled() bool {
	return !envEnabled(DisableChoiceEnv)
}

func MetadataEnabled() bool {
	return !envEnabled(DisableMetadataEnv)
}

func SaveMaxActions() int {
	limit := intFromEnv(SaveMaxActionsEnv, 0)
	if limit < 0 {
		return 0
	}
	return limit
}

func RiskyMaxActions() int {
	return limitFromEnv(RiskyMaxActionsEnv, 2)
}

func RiskySaveMaxActions() int {
	return limitFromEnv(RiskySaveMaxEnv, 2)
}

func envEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
