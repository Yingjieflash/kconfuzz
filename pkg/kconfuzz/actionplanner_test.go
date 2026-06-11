// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfuzz

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestLoadRelationTableAndPlanSequence(t *testing.T) {
	planner := loadTestPlanner(t)
	prg := testProg("accept$inet", "setsockopt$inet_sctp6_SCTP_ASSOCINFO")

	actions := planner.Plan(prg, Options{
		Strategy:             StrategySequence,
		MaxActionsPerProgram: 4,
	})
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2: %+v", len(actions), actions)
	}
	checkActionParams(t, actions,
		SupportedParams["net/ipv4/tcp_autocorking"].ID,
		SupportedParams["net/sctp/prsctp_enable"].ID)
	for _, action := range actions {
		if action.BeforeCall != 0 {
			t.Fatalf("sequence action should run before the sequence: %+v", action)
		}
	}
	if planner.audit.RawRows != 4 {
		t.Fatalf("got raw rows %d, want 4", planner.audit.RawRows)
	}
	if planner.audit.LoadedEdges != 2 || planner.audit.LoadedCalls != 2 || planner.audit.LoadedParams != 2 {
		t.Fatalf("bad audit loaded counts: %+v", planner.audit)
	}
	if planner.audit.DroppedGenericDomain != 1 || planner.audit.DroppedUnsafeParam != 1 {
		t.Fatalf("bad audit drop counts: %+v", planner.audit)
	}
}

func TestLoadRelationTableAndPlanCallLevel(t *testing.T) {
	planner := loadTestPlanner(t)
	prg := testProg("accept$inet", "setsockopt$inet_sctp6_SCTP_ASSOCINFO")

	actions := planner.Plan(prg, Options{
		Strategy:             StrategyCall,
		MaxActionsPerProgram: 4,
		MaxActionsPerCall:    1,
	})
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2: %+v", len(actions), actions)
	}
	checkActionParams(t, actions,
		SupportedParams["net/ipv4/tcp_autocorking"].ID,
		SupportedParams["net/sctp/prsctp_enable"].ID)
	checkActionBeforeCall(t, actions, SupportedParams["net/ipv4/tcp_autocorking"].ID, 0)
	checkActionBeforeCall(t, actions, SupportedParams["net/sctp/prsctp_enable"].ID, 1)
	checkActionValuesValid(t, actions)
}

func TestPlanBothLevel(t *testing.T) {
	planner := loadTestPlanner(t)
	prg := testProg("accept$inet", "setsockopt$inet_sctp6_SCTP_ASSOCINFO")

	actions := planner.Plan(prg, Options{
		Strategy:             StrategyBoth,
		MaxActionsPerProgram: 4,
		MaxActionsPerCall:    1,
	})
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2: %+v", len(actions), actions)
	}
	checkActionParams(t, actions,
		SupportedParams["net/ipv4/tcp_autocorking"].ID,
		SupportedParams["net/sctp/prsctp_enable"].ID)
	ctx := planner.PlanContext(prg, Options{Strategy: StrategyBoth}, "test")
	if ctx == nil || ctx.Strategy != prog.KConfuzzConfigStrategyBoth {
		t.Fatalf("bad context: %+v", ctx)
	}
}

func TestPlanContextFromEnvStrategy(t *testing.T) {
	resetEnvPlanner()
	t.Setenv(RelationTableEnv, writeTestRelation(t))
	t.Setenv(ActionStrategyEnv, prog.KConfuzzConfigStrategyCall)
	t.Setenv(MaxActionsEnv, "3")
	t.Setenv(MaxActionsPerCallEnv, "1")
	t.Setenv(RandomActionsEnv, "0")

	ctx := PlanContextFromEnv(testProg("accept$inet", "setsockopt$inet_sctp6_SCTP_ASSOCINFO"))
	if ctx == nil {
		t.Fatalf("got nil context")
	}
	if ctx.Strategy != prog.KConfuzzConfigStrategyCall {
		t.Fatalf("got strategy %q, want call", ctx.Strategy)
	}
	if len(ctx.Actions) != 2 || ctx.Actions[1].BeforeCall != 1 {
		t.Fatalf("bad actions: %+v", ctx.Actions)
	}
}

func TestPlanContextFromEnvZeroMeansUnlimited(t *testing.T) {
	resetEnvPlanner()
	path := filepath.Join(t.TempDir(), "relation.jsonl")
	data := "" +
		`{"param":"net/ipv4/tcp_autocorking","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_ecn","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_ecn_fallback","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_plb_enabled","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(RelationTableEnv, path)
	t.Setenv(MaxActionsEnv, "0")
	t.Setenv(RelatedActionsEnv, "0")
	t.Setenv(RandomActionsEnv, "0")

	ctx := PlanContextFromEnv(testProg("accept$inet"))
	if ctx == nil {
		t.Fatalf("got nil context")
	}
	if len(ctx.Actions) != 4 {
		t.Fatalf("got %d actions, want all 4 related actions: %+v", len(ctx.Actions), ctx.Actions)
	}
	checkNoDuplicateParams(t, ctx.Actions)
}

func TestPlanContextMixedRiskKeepsPaperStyleSequence(t *testing.T) {
	resetEnvPlanner()
	t.Setenv(RelationTableEnv, writeTestRelation(t))
	t.Setenv(ActionStrategyEnv, prog.KConfuzzConfigStrategySequence)
	t.Setenv(MaxActionsEnv, "4")
	t.Setenv(RandomActionsEnv, "0")
	t.Setenv(RiskyMaxActionsEnv, "1")

	ctx := PlanContextFromEnv(testProg("syz_mount_image$fuse", "accept$inet",
		"setsockopt$inet_sctp6_SCTP_ASSOCINFO"))
	if ctx == nil {
		t.Fatalf("got nil context")
	}
	if ctx.Strategy != prog.KConfuzzConfigStrategySequence {
		t.Fatalf("got strategy %q, want sequence", ctx.Strategy)
	}
	if len(ctx.Actions) != 2 {
		t.Fatalf("got %d actions, want 2: %+v", len(ctx.Actions), ctx.Actions)
	}
	for _, action := range ctx.Actions {
		if action.BeforeCall != 0 {
			t.Fatalf("sequence action should stay before the program: %+v", action)
		}
	}
}

func TestFilterSupportedContextDoesNotRetargetMixedRiskSavedSequence(t *testing.T) {
	resetEnvPlanner()
	t.Setenv(RelationTableEnv, writeTestRelation(t))
	t.Setenv(RiskyMaxActionsEnv, "2")
	ipv4 := SupportedParams["net/ipv4/tcp_autocorking"]
	sctp := SupportedParams["net/sctp/prsctp_enable"]
	unrelated := SupportedParams["net/ipv4/tcp_ecn"]
	ctx := &prog.KConfuzzConfigContext{
		Strategy:        prog.KConfuzzConfigStrategySequence,
		Source:          "loaded-test",
		ConfigDependent: true,
		Actions: []prog.KConfuzzConfigAction{
			{BeforeCall: 0, ParamID: ipv4.ID, ValueID: 0},
			{BeforeCall: 0, ParamID: sctp.ID, ValueID: 0},
			{BeforeCall: 0, ParamID: unrelated.ID, ValueID: 0},
		},
	}

	filtered := FilterSupportedContext(ctx, testProg("syz_mount_image$fuse", "accept$inet",
		"setsockopt$inet_sctp6_SCTP_ASSOCINFO"))
	if filtered == nil {
		t.Fatalf("got nil context")
	}
	checkActionParams(t, filtered.Actions, ipv4.ID, sctp.ID, unrelated.ID)
	checkActionBeforeCall(t, filtered.Actions, ipv4.ID, 0)
	checkActionBeforeCall(t, filtered.Actions, sctp.ID, 0)
	checkActionBeforeCall(t, filtered.Actions, unrelated.ID, 0)
	if filtered.Source != "loaded-test" {
		t.Fatalf("source changed unexpectedly: %q", filtered.Source)
	}
}

func TestSaveMaxActionsFromEnv(t *testing.T) {
	if got := SaveMaxActions(); got != 0 {
		t.Fatalf("got %d, want default 0", got)
	}
	t.Setenv(SaveMaxActionsEnv, "64")
	if got := SaveMaxActions(); got != 64 {
		t.Fatalf("got %d, want 64", got)
	}
	t.Setenv(SaveMaxActionsEnv, "-1")
	if got := SaveMaxActions(); got != 0 {
		t.Fatalf("got %d, want negative value clamped to 0", got)
	}
}

func TestRiskyActionLimitsFromEnv(t *testing.T) {
	if got := RiskyMaxActions(); got != 2 {
		t.Fatalf("got %d, want default 2", got)
	}
	if got := RiskySaveMaxActions(); got != 2 {
		t.Fatalf("got %d, want default 2", got)
	}
	t.Setenv(RiskyMaxActionsEnv, "1")
	t.Setenv(RiskySaveMaxEnv, "3")
	if got := RiskyMaxActions(); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
	if got := RiskySaveMaxActions(); got != 3 {
		t.Fatalf("got %d, want 3", got)
	}
}

func TestSeedPenaltySkipsIncreasingly(t *testing.T) {
	sig := "seed-penalty-test"
	if got := SeedPenalty(sig); got != 0 {
		t.Fatalf("got initial score %d, want 0", got)
	}
	if got := PenalizeSeed(sig, "test"); got != 1 {
		t.Fatalf("got score %d, want 1", got)
	}
	if got := PenalizeSeed(sig, "test"); got != 2 {
		t.Fatalf("got score %d, want 2", got)
	}
	rnd := rand.New(rand.NewSource(1))
	var skipped bool
	for i := 0; i < 32; i++ {
		if ShouldSkipPenalizedSeed(sig, rnd) {
			skipped = true
			break
		}
	}
	if !skipped {
		t.Fatalf("penalized seed was never skipped")
	}
	t.Setenv(DisableSeedPenaltyEnv, "1")
	if SeedPenalty(sig) != 0 || ShouldSkipPenalizedSeed(sig, rnd) {
		t.Fatalf("seed penalty was not disabled")
	}
}

func TestPlanRandomFallbackActions(t *testing.T) {
	planner := loadTestPlanner(t)
	prg := testProg("unrelated$call")

	actions := planner.Plan(prg, Options{
		MaxActionsPerProgram:    2,
		RandomActionsPerProgram: 2,
	})
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2 random actions: %+v", len(actions), actions)
	}
	seen := make(map[uint64]bool)
	for _, action := range actions {
		if action.BeforeCall != 0 {
			t.Fatalf("random action should be sequence-level: %+v", action)
		}
		if seen[action.ParamID] {
			t.Fatalf("duplicate random action: %+v", actions)
		}
		seen[action.ParamID] = true
		param, ok := paramByID(action.ParamID)
		if !ok || !safeRandomParam(param) {
			t.Fatalf("bad random param: action=%+v param=%+v ok=%v", action, param, ok)
		}
		if action.ValueID >= param.ValueCount && action.Flags&prog.KConfuzzConfigFlagFlip == 0 {
			t.Fatalf("bad random value: action=%+v param=%+v", action, param)
		}
	}
}

func TestUnlimitedAllRelatedSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relation.jsonl")
	data := "" +
		`{"param":"net/ipv4/tcp_autocorking","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_ecn","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_ecn_fallback","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_plb_enabled","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	planner, err := LoadRelationTable(path)
	if err != nil {
		t.Fatal(err)
	}

	limited := planner.Plan(testProg("accept$inet"), Options{
		Strategy:             StrategySequence,
		MaxActionsPerProgram: 2,
	})
	if len(limited) != 2 {
		t.Fatalf("limited plan got %d actions, want 2: %+v", len(limited), limited)
	}
	all := planner.Plan(testProg("accept$inet"), Options{
		Strategy:                 StrategySequence,
		MaxActionsPerProgram:     unlimitedActions,
		RelatedActionsPerProgram: unlimitedActions,
	})
	if len(all) != 4 {
		t.Fatalf("unlimited plan got %d actions, want 4: %+v", len(all), all)
	}
	checkNoDuplicateParams(t, all)
	for _, action := range all {
		if action.BeforeCall != 0 {
			t.Fatalf("sequence action should run before the sequence: %+v", action)
		}
	}
}

func TestSequenceSelectionUsesStableShuffle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relation.jsonl")
	data := "" +
		`{"param":"net/ipv4/tcp_autocorking","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_ecn","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_ecn_fallback","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_plb_enabled","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	planner, err := LoadRelationTable(path)
	if err != nil {
		t.Fatal(err)
	}

	prg := testProg("accept$inet", "mmap")
	first := planner.Plan(prg, Options{
		Strategy:             StrategySequence,
		MaxActionsPerProgram: 2,
	})
	second := planner.Plan(prg, Options{
		Strategy:             StrategySequence,
		MaxActionsPerProgram: 2,
	})
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("got first=%+v second=%+v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("stable shuffle changed between identical programs: first=%+v second=%+v", first, second)
		}
	}
	lowest := []uint64{
		SupportedParams["net/ipv4/tcp_autocorking"].ID,
		SupportedParams["net/ipv4/tcp_ecn"].ID,
	}
	if first[0].ParamID == lowest[0] && first[1].ParamID == lowest[1] {
		t.Fatalf("selection still appears to be fixed low-ID truncation: %+v", first)
	}
}

func TestRandomCandidatePoolIsConservative(t *testing.T) {
	params := randomCandidateParams()
	if len(params) == 0 {
		t.Fatalf("empty random candidate pool")
	}
	for _, param := range params {
		if !safeRandomParam(param) {
			t.Fatalf("unsafe random candidate: %+v", param)
		}
	}
	for _, name := range []string{
		"kernel/panic",
		"kernel/modules_disabled",
		"net/ipv6/conf/all/disable_ipv6",
		"user/max_user_namespaces",
	} {
		param, ok := SupportedParams[name]
		if !ok {
			t.Fatalf("missing test param %q", name)
		}
		if safeRandomParam(param) {
			t.Fatalf("%q should not be a safe random candidate: %+v", name, param)
		}
	}
}

func TestAuditFileFromEnv(t *testing.T) {
	resetEnvPlanner()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv(RelationTableEnv, writeTestRelation(t))
	t.Setenv(AuditFileEnv, auditPath)
	t.Setenv(debugEnv, "1")

	if PlanContextFromEnv(testProg("accept$inet")) == nil {
		t.Fatalf("got nil context")
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec Audit
	if err := json.Unmarshal(data[:len(data)-1], &rec); err != nil {
		t.Fatalf("failed to decode audit %q: %v", data, err)
	}
	if rec.Event != "relation-load" || rec.LoadedEdges != 2 || rec.DroppedUnsafeParam != 1 {
		t.Fatalf("bad audit record: %+v", rec)
	}
}

func TestMutateContext(t *testing.T) {
	param0 := SupportedParams["net/ipv4/tcp_autocorking"]
	param1 := SupportedParams["net/sctp/prsctp_enable"]
	ctx := &prog.KConfuzzConfigContext{
		Strategy: prog.KConfuzzConfigStrategySequence,
		Source:   "test",
		Actions: []prog.KConfuzzConfigAction{
			{BeforeCall: 0, ParamID: param0.ID, ValueID: 0, Flags: prog.KConfuzzConfigFlagFlip},
			{BeforeCall: 1, ParamID: param1.ID, ValueID: 0, Flags: prog.KConfuzzConfigFlagFlip},
		},
	}
	prg := testProg("accept$inet", "setsockopt$inet_sctp6_SCTP_ASSOCINFO")
	original := ctx.Clone()
	var sawValue, sawBeforeCall, sawRemove bool
	for seed := int64(0); seed < 1000; seed++ {
		mutated := MutateContext(ctx, prg, rand.New(rand.NewSource(seed)))
		if mutated == nil {
			t.Fatalf("mutation returned nil")
		}
		if mutated == ctx {
			t.Fatalf("mutation reused caller-owned context")
		}
		if mutated.Source != "inherited-mutated" {
			t.Fatalf("got source %q, want inherited-mutated", mutated.Source)
		}
		for _, action := range mutated.Actions {
			param, ok := paramByID(action.ParamID)
			if !ok {
				t.Fatalf("unknown param id %d", action.ParamID)
			}
			if action.ValueID >= param.ValueCount {
				t.Fatalf("bad value id in action %+v for param %+v", action, param)
			}
			if action.BeforeCall < 0 || action.BeforeCall > len(prg.Calls) {
				t.Fatalf("bad before_call in action %+v", action)
			}
		}
		if len(mutated.Actions) < len(ctx.Actions) {
			sawRemove = true
		}
		for _, action := range mutated.Actions {
			if action.ValueID != 0 {
				sawValue = true
			}
			if action.BeforeCall > 1 {
				sawBeforeCall = true
			}
		}
	}
	if !prog.KConfuzzConfigContextEqual(ctx, original) {
		t.Fatalf("mutation modified original context: %+v", ctx)
	}
	if !sawValue || !sawBeforeCall || !sawRemove {
		t.Fatalf("mutation coverage incomplete: value=%v before_call=%v remove=%v",
			sawValue, sawBeforeCall, sawRemove)
	}
}

func TestMutatorRegistryAndMutation(t *testing.T) {
	param := SupportedParams["net/ipv4/tcp_autocorking"]
	if !param.Mutator {
		t.Fatalf("tcp_autocorking has no mutator metadata")
	}
	if !hasValidValueID(param.MutatorTfuzzValueIDs, param.ValueCount) &&
		!hasValidValueID(param.MutatorSeedValueIDs, param.ValueCount) &&
		!hasValidValueID(param.MutatorRandomValueIDs, param.ValueCount) &&
		!hasValidValueID(param.MutatorOutOfDomainValueIDs, param.ValueCount) {
		t.Fatalf("mutator has no usable value pool: %+v", param)
	}
	if param.MutatorProbTfuzz != 0 &&
		!hasValidValueID(param.MutatorTfuzzValueIDs, param.ValueCount) {
		t.Fatalf("tfuzz pool has non-zero weight but no usable values: %+v", param)
	}
	if param.MutatorProbSeed != 0 &&
		!hasValidValueID(param.MutatorSeedValueIDs, param.ValueCount) {
		t.Fatalf("seed pool has non-zero weight but no usable values: %+v", param)
	}
	if param.MutatorProbRandomLegal != 0 &&
		!hasValidValueID(param.MutatorRandomValueIDs, param.ValueCount) {
		t.Fatalf("random legal pool has non-zero weight but no usable values: %+v", param)
	}
	if param.MutatorProbOutOfDomain != 0 &&
		!hasValidValueID(param.MutatorOutOfDomainValueIDs, param.ValueCount) {
		t.Fatalf("out-of-domain pool has non-zero weight but no usable values: %+v", param)
	}
	action := configAction(0, 0, param)
	if action.Flags&prog.KConfuzzConfigFlagFlip != 0 {
		t.Fatalf("mutator-backed planned action should use exact value: %+v", action)
	}
	var sawExactMutation bool
	for seed := int64(0); seed < 100; seed++ {
		mutated := action
		mutateActionValue(&mutated, param, rand.New(rand.NewSource(seed)))
		if mutated.ValueID >= param.ValueCount {
			t.Fatalf("bad mutated value id: action=%+v param=%+v", mutated, param)
		}
		if mutated.Flags&prog.KConfuzzConfigFlagFlip == 0 {
			sawExactMutation = true
		}
	}
	if !sawExactMutation {
		t.Fatalf("mutator never produced an exact value")
	}
}

func TestFilterSupportedActions(t *testing.T) {
	safe := SupportedParams["net/ipv4/tcp_autocorking"]
	unsafe := SupportedParams["kernel/modules_disabled"]
	actions := []prog.KConfuzzConfigAction{
		{BeforeCall: 0, ParamID: safe.ID, ValueID: 0, Flags: prog.KConfuzzConfigFlagFlip},
		{BeforeCall: 0, ParamID: unsafe.ID, ValueID: 0, Flags: prog.KConfuzzConfigFlagFlip},
		{BeforeCall: 0, ParamID: safe.ID, ValueID: safe.ValueCount + 1},
	}
	filtered := FilterSupportedActions(actions)
	if len(filtered) != 1 {
		t.Fatalf("got %d actions, want 1: %+v", len(filtered), filtered)
	}
	if filtered[0].ParamID != safe.ID {
		t.Fatalf("kept wrong action: %+v", filtered[0])
	}
}

func TestRelationChoiceBoostsFromEnv(t *testing.T) {
	resetEnvPlanner()
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	accept := target.SyscallMap["accept$inet"]
	connect := target.SyscallMap["connect$inet"]
	if accept == nil || connect == nil {
		t.Fatalf("missing test syscalls: accept=%v connect=%v", accept, connect)
	}
	path := filepath.Join(t.TempDir(), "relation.jsonl")
	data := "" +
		`{"param":"net/ipv4/tcp_autocorking","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/ipv4/tcp_autocorking","param_domain":"ipv4","syzkaller_call":"connect$inet","descriptor_domain":"ipv4"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(RelationTableEnv, path)
	t.Setenv(ChoiceWeightEnv, "7")

	boosts := RelationChoiceBoostsFromEnv(target, nil)
	if len(boosts) != 2 {
		t.Fatalf("got %d boosts, want 2: %+v", len(boosts), boosts)
	}
	checkBoost := func(from, to *prog.Syscall) {
		t.Helper()
		for _, boost := range boosts {
			if boost.From == from && boost.To == to && boost.Weight == 7 {
				return
			}
		}
		t.Fatalf("missing boost %s -> %s in %+v", from.Name, to.Name, boosts)
	}
	checkBoost(accept, connect)
	checkBoost(connect, accept)

	base, _ := target.CalculatePriorities(nil, map[*prog.Syscall]bool{accept: true, connect: true})
	boosted, _ := target.CalculatePrioritiesWithBoosts(nil,
		map[*prog.Syscall]bool{accept: true, connect: true}, boosts)
	if boosted[accept.ID][connect.ID] <= base[accept.ID][connect.ID] {
		t.Fatalf("relation boost did not increase priority: base=%d boosted=%d",
			base[accept.ID][connect.ID], boosted[accept.ID][connect.ID])
	}
}

func TestRelationChoiceBoostsFromRealRelationFile(t *testing.T) {
	path := os.Getenv("SYZ_KCONFUZZ_TEST_RELATION_TABLE")
	if path == "" {
		t.Skip("set SYZ_KCONFUZZ_TEST_RELATION_TABLE to run the real relation-table smoke")
	}
	resetEnvPlanner()
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(RelationTableEnv, path)
	t.Setenv(ChoiceWeightEnv, "3")

	boosts := RelationChoiceBoostsFromEnv(target, nil)
	if len(boosts) == 0 {
		t.Fatalf("relation table %s produced no choice-table boosts", path)
	}
	base, _ := target.CalculatePriorities(nil, nil)
	boosted, _ := target.CalculatePrioritiesWithBoosts(nil, nil, boosts)
	for _, boost := range boosts {
		if boosted[boost.From.ID][boost.To.ID] > base[boost.From.ID][boost.To.ID] {
			t.Logf("relation table %s produced %d boosts; sample %s -> %s: base=%d boosted=%d",
				path, len(boosts), boost.From.Name, boost.To.Name,
				base[boost.From.ID][boost.To.ID], boosted[boost.From.ID][boost.To.ID])
			return
		}
	}
	t.Fatalf("relation table %s produced %d boosts but no sampled priority increased", path, len(boosts))
}

func loadTestPlanner(t *testing.T) *Planner {
	t.Helper()
	path := writeTestRelation(t)
	planner, err := LoadRelationTable(path)
	if err != nil {
		t.Fatal(err)
	}
	return planner
}

func writeTestRelation(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relation.jsonl")
	data := "" +
		`{"param":"net/ipv4/tcp_autocorking","param_domain":"ipv4","syzkaller_call":"accept$inet","descriptor_domain":"ipv4"}` + "\n" +
		`{"param":"net/sctp/prsctp_enable","param_domain":"sctp","syzkaller_call":"setsockopt$inet_sctp6_SCTP_ASSOCINFO","descriptor_domain":"sctp"}` + "\n" +
		`{"param":"net/sctp/addip_enable","param_domain":"sctp","syzkaller_call":"bpf$BPF_LINK_CREATE","descriptor_domain":"generic"}` + "\n" +
		`{"param":"kernel/modules_disabled","param_domain":"generic","syzkaller_call":"mmap","descriptor_domain":"generic"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func resetEnvPlanner() {
	envPlanner.once = sync.Once{}
	envPlanner.planner = nil
}

func testProg(calls ...string) *prog.Prog {
	prg := &prog.Prog{}
	for _, name := range calls {
		prg.Calls = append(prg.Calls, &prog.Call{
			Meta: &prog.Syscall{Name: name},
		})
	}
	return prg
}

func checkAction(t *testing.T, action prog.KConfuzzConfigAction, beforeCall int, paramID, valueID, flags uint64) {
	t.Helper()
	if action.BeforeCall != beforeCall || action.ParamID != paramID || action.ValueID != valueID || action.Flags != flags {
		t.Fatalf("got action %+v, want before=%d param=%d value=%d flags=%d",
			action, beforeCall, paramID, valueID, flags)
	}
}

func checkActionParams(t *testing.T, actions []prog.KConfuzzConfigAction, params ...uint64) {
	t.Helper()
	got := make(map[uint64]bool)
	for _, action := range actions {
		got[action.ParamID] = true
	}
	for _, param := range params {
		if !got[param] {
			t.Fatalf("missing param %d in actions %+v", param, actions)
		}
	}
	if len(got) != len(params) {
		t.Fatalf("got params %+v, want %+v", got, params)
	}
}

func checkActionBeforeCall(t *testing.T, actions []prog.KConfuzzConfigAction, param uint64, beforeCall int) {
	t.Helper()
	for _, action := range actions {
		if action.ParamID == param {
			if action.BeforeCall != beforeCall {
				t.Fatalf("got before_call=%d for param %d, want %d: %+v",
					action.BeforeCall, param, beforeCall, actions)
			}
			return
		}
	}
	t.Fatalf("missing param %d in actions %+v", param, actions)
}

func checkActionValuesValid(t *testing.T, actions []prog.KConfuzzConfigAction) {
	t.Helper()
	for _, action := range actions {
		param, ok := paramByID(action.ParamID)
		if !ok {
			t.Fatalf("unknown param in action: %+v", action)
		}
		if action.ValueID >= param.ValueCount && action.Flags&prog.KConfuzzConfigFlagFlip == 0 {
			t.Fatalf("bad value for action=%+v param=%+v", action, param)
		}
	}
}

func checkNoDuplicateParams(t *testing.T, actions []prog.KConfuzzConfigAction) {
	t.Helper()
	seen := make(map[uint64]bool)
	for _, action := range actions {
		if seen[action.ParamID] {
			t.Fatalf("duplicate param in actions: %+v", actions)
		}
		seen[action.ParamID] = true
	}
}

func checkPlannedAction(t *testing.T, action prog.KConfuzzConfigAction, beforeCall, callIndex int, param ConfigParam) {
	t.Helper()
	valueID, flags := plannedValue(callIndex, param)
	checkAction(t, action, beforeCall, param.ID, valueID, flags)
}
