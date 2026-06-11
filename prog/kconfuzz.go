// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"encoding/json"
	"sort"
)

const (
	KConfuzzConfigStrategySequence = "sequence"
	KConfuzzConfigStrategyCall     = "call"
	KConfuzzConfigStrategyBoth     = "both"
)

type KConfuzzConfigContext struct {
	Strategy        string
	Source          string
	ConfigDependent bool
	Actions         []KConfuzzConfigAction
}

func CloneKConfuzzConfigActions(actions []KConfuzzConfigAction) []KConfuzzConfigAction {
	return append([]KConfuzzConfigAction(nil), actions...)
}

func (ctx *KConfuzzConfigContext) Clone() *KConfuzzConfigContext {
	if ctx == nil {
		return nil
	}
	ret := *ctx
	ret.Actions = CloneKConfuzzConfigActions(ctx.Actions)
	return &ret
}

func (ctx *KConfuzzConfigContext) Empty() bool {
	return ctx == nil || len(ctx.Actions) == 0 && !ctx.ConfigDependent
}

func (ctx *KConfuzzConfigContext) CloneForProg(p *Prog) *KConfuzzConfigContext {
	if ctx == nil {
		return nil
	}
	ret := ctx.Clone()
	ret.Actions = NormalizeKConfuzzConfigActions(p, ret.Actions)
	if len(ret.Actions) == 0 && !ret.ConfigDependent {
		return nil
	}
	return ret
}

func NormalizeKConfuzzConfigActions(p *Prog, actions []KConfuzzConfigAction) []KConfuzzConfigAction {
	if len(actions) == 0 {
		return nil
	}
	ret := make([]KConfuzzConfigAction, 0, len(actions))
	maxCall := -1
	if p != nil {
		maxCall = len(p.Calls)
	}
	for _, action := range actions {
		if action.BeforeCall < 0 {
			continue
		}
		if maxCall >= 0 && action.BeforeCall > maxCall {
			continue
		}
		ret = append(ret, action)
	}
	sort.SliceStable(ret, func(i, j int) bool {
		if ret[i].BeforeCall != ret[j].BeforeCall {
			return ret[i].BeforeCall < ret[j].BeforeCall
		}
		if ret[i].ParamID != ret[j].ParamID {
			return ret[i].ParamID < ret[j].ParamID
		}
		if ret[i].ValueID != ret[j].ValueID {
			return ret[i].ValueID < ret[j].ValueID
		}
		return ret[i].Flags < ret[j].Flags
	})
	return ret
}

func (ctx *KConfuzzConfigContext) SignatureData() []byte {
	ctx = ctx.Clone()
	if ctx == nil || ctx.Empty() {
		return nil
	}
	ctx.Actions = NormalizeKConfuzzConfigActions(nil, ctx.Actions)
	data, err := json.Marshal(ctx)
	if err != nil {
		panic(err)
	}
	return append([]byte("kconfuzz:"), data...)
}

func KConfuzzConfigContextEqual(a, b *KConfuzzConfigContext) bool {
	return bytes.Equal(a.SignatureData(), b.SignatureData())
}
