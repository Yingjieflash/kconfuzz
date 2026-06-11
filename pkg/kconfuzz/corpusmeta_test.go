// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfuzz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/prog"
)

func TestCorpusMetadataStore(t *testing.T) {
	workdir := t.TempDir()
	store, err := OpenCorpusMetadataStore(workdir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &prog.KConfuzzConfigContext{
		Strategy:        prog.KConfuzzConfigStrategySequence,
		Source:          "test",
		ConfigDependent: true,
		Actions: []prog.KConfuzzConfigAction{{
			BeforeCall: 0,
			ParamID:    1,
			ValueID:    1,
			Flags:      prog.KConfuzzConfigFlagFlip,
		}},
	}
	if err := store.Save("sig0", []byte("prog0"), ctx); err != nil {
		t.Fatal(err)
	}

	store, err = OpenCorpusMetadataStore(workdir)
	if err != nil {
		t.Fatal(err)
	}
	got := store.Context("sig0", nil)
	if !prog.KConfuzzConfigContextEqual(got, ctx) {
		t.Fatalf("restored wrong context: %+v", got)
	}
	if err := store.Prune(map[string]struct{}{"other": {}}); err != nil {
		t.Fatal(err)
	}
	if got := store.Context("sig0", nil); got != nil {
		t.Fatalf("pruned context is still present: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(workdir, CorpusMetadataFile)); !os.IsNotExist(err) {
		t.Fatalf("metadata file still exists after pruning: %v", err)
	}
}
