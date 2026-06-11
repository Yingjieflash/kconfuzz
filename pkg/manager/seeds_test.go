// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/kconfuzz"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestRequires(t *testing.T) {
	{
		requires := parseRequires([]byte("# requires: manual arch=amd64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
	{
		requires := parseRequires([]byte("# requires: -arch=arm64 manual -arch=riscv64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
}

func TestLoadSeedsIgnoresKConfuzzMetadata(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}
	workdir := t.TempDir()
	cfg := &mgrconfig.Config{
		Workdir:   workdir,
		Syzkaller: t.TempDir(),
	}
	cfg.Target = target
	cfg.TargetOS = target.OS

	p := target.Generate(rand.NewSource(0), 1, target.DefaultChoiceTable())
	progData := p.Serialize()
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
	corpusSig := hash.String(progData)
	corpusDB, err := db.Open(filepath.Join(workdir, "corpus.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	corpusDB.Save(corpusSig, progData, 0)
	if err := corpusDB.Flush(); err != nil {
		t.Fatal(err)
	}
	store, err := kconfuzz.OpenCorpusMetadataStore(workdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(corpusSig, progData, ctx); err != nil {
		t.Fatal(err)
	}

	seeds, err := LoadSeeds(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(seeds.Candidates))
	}
	got := seeds.Candidates[0].KConfuzzConfig
	if got != nil {
		t.Fatalf("restored stale context in paper-style mode: %+v", got)
	}
}
