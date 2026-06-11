// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/kconfuzz"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestPrepareKConfuzzExplicitContext(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}
	p := &prog.Prog{
		Target: target,
		Calls: []*prog.Call{
			prog.MakeCall(target.SyscallMap["test$manual"], nil),
		},
	}
	param := kconfuzz.SupportedParams["net/ipv4/tcp_autocorking"]
	ctx := &prog.KConfuzzConfigContext{
		Strategy: prog.KConfuzzConfigStrategySequence,
		Source:   "test",
		Actions: []prog.KConfuzzConfigAction{{
			BeforeCall: 0,
			ParamID:    param.ID,
			ValueID:    1,
			Flags:      prog.KConfuzzConfigFlagFlip,
		}},
	}
	req := &queue.Request{
		Prog:                  p,
		KConfuzzConfigContext: ctx,
	}
	var fuzzer Fuzzer
	fuzzer.prepareKConfuzz(req)
	if len(req.KConfuzzConfigActions) != 1 {
		t.Fatalf("got %d actions, want 1", len(req.KConfuzzConfigActions))
	}
	if req.KConfuzzConfigContext == ctx {
		t.Fatalf("prepareKConfuzz reused caller-owned context")
	}
	if !prog.KConfuzzConfigContextEqual(req.KConfuzzConfigContext, ctx) {
		t.Fatalf("context changed unexpectedly: %+v", req.KConfuzzConfigContext)
	}
}

func TestPrepareKConfuzzDisabled(t *testing.T) {
	req := &queue.Request{
		KConfuzzConfigDisabled: true,
		KConfuzzConfigContext: &prog.KConfuzzConfigContext{
			Actions: []prog.KConfuzzConfigAction{{BeforeCall: 0}},
		},
	}
	var fuzzer Fuzzer
	fuzzer.prepareKConfuzz(req)
	if len(req.KConfuzzConfigActions) != 0 {
		t.Fatalf("disabled request got actions: %+v", req.KConfuzzConfigActions)
	}
}
