// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfuzz

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

const CorpusMetadataFile = "kconfuzz-corpus-meta.jsonl"

type CorpusMetadataStore struct {
	mu      sync.Mutex
	path    string
	records map[string]corpusMetadataRecord
}

type corpusMetadataRecord struct {
	CorpusSig       string                 `json:"corpus_sig"`
	ProgSig         string                 `json:"prog_sig"`
	ConfigSig       string                 `json:"config_sig"`
	Strategy        string                 `json:"strategy,omitempty"`
	Source          string                 `json:"source,omitempty"`
	ConfigDependent bool                   `json:"config_dependent,omitempty"`
	Actions         []corpusMetadataAction `json:"actions,omitempty"`
}

type corpusMetadataAction struct {
	BeforeCall int    `json:"before_call"`
	ParamID    uint64 `json:"param_id"`
	ValueID    uint64 `json:"value_id"`
	Flags      uint64 `json:"flags"`
}

func OpenCorpusMetadataStore(workdir string) (*CorpusMetadataStore, error) {
	store := &CorpusMetadataStore{
		path:    filepath.Join(workdir, CorpusMetadataFile),
		records: make(map[string]corpusMetadataRecord),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *CorpusMetadataStore) Context(corpusSig string, p *prog.Prog) *prog.KConfuzzConfigContext {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	rec, ok := store.records[corpusSig]
	if !ok {
		return nil
	}
	ctx := metadataRecordContext(rec)
	return ctx.CloneForProg(p)
}

func (store *CorpusMetadataStore) Save(corpusSig string, progData []byte, ctx *prog.KConfuzzConfigContext) error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	ctx = ctx.Clone()
	if ctx == nil || len(ctx.Actions) == 0 {
		delete(store.records, corpusSig)
		return store.flushLocked()
	}
	rec := contextMetadataRecord(corpusSig, progData, ctx)
	store.records[corpusSig] = rec
	return store.flushLocked()
}

func (store *CorpusMetadataStore) Delete(corpusSig string) error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.records, corpusSig)
	return store.flushLocked()
}

func (store *CorpusMetadataStore) Prune(keep map[string]struct{}) error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	changed := false
	for sig := range store.records {
		if _, ok := keep[sig]; ok {
			continue
		}
		delete(store.records, sig)
		changed = true
	}
	if !changed {
		return nil
	}
	return store.flushLocked()
}

func (store *CorpusMetadataStore) Len() int {
	if store == nil {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *CorpusMetadataStore) load() error {
	f, err := os.Open(store.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 16*1024*1024)
	for scanner.Scan() {
		var rec corpusMetadataRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			return err
		}
		if rec.CorpusSig == "" || len(rec.Actions) == 0 {
			continue
		}
		store.records[rec.CorpusSig] = rec
	}
	return scanner.Err()
}

func (store *CorpusMetadataStore) flushLocked() error {
	if len(store.records) == 0 {
		if err := os.Remove(store.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	keys := make([]string, 0, len(store.records))
	for key := range store.records {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	tmp := store.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, osutil.DefaultFilePerm)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, key := range keys {
		if err := enc.Encode(store.records[key]); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return osutil.Rename(tmp, store.path)
}

func contextMetadataRecord(corpusSig string, progData []byte,
	ctx *prog.KConfuzzConfigContext) corpusMetadataRecord {
	rec := corpusMetadataRecord{
		CorpusSig:       corpusSig,
		ProgSig:         hash.String(progData),
		ConfigSig:       hash.String(ctx.SignatureData()),
		Strategy:        ctx.Strategy,
		Source:          ctx.Source,
		ConfigDependent: ctx.ConfigDependent,
		Actions:         make([]corpusMetadataAction, 0, len(ctx.Actions)),
	}
	for _, action := range prog.NormalizeKConfuzzConfigActions(nil, ctx.Actions) {
		rec.Actions = append(rec.Actions, corpusMetadataAction{
			BeforeCall: action.BeforeCall,
			ParamID:    action.ParamID,
			ValueID:    action.ValueID,
			Flags:      action.Flags,
		})
	}
	return rec
}

func metadataRecordContext(rec corpusMetadataRecord) *prog.KConfuzzConfigContext {
	ctx := &prog.KConfuzzConfigContext{
		Strategy:        rec.Strategy,
		Source:          rec.Source,
		ConfigDependent: rec.ConfigDependent,
		Actions:         make([]prog.KConfuzzConfigAction, 0, len(rec.Actions)),
	}
	for _, action := range rec.Actions {
		ctx.Actions = append(ctx.Actions, prog.KConfuzzConfigAction{
			BeforeCall: action.BeforeCall,
			ParamID:    action.ParamID,
			ValueID:    action.ValueID,
			Flags:      action.Flags,
		})
	}
	return ctx
}
