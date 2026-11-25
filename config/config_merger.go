/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

var (
	ErrCircularInclude = fmt.Errorf("circular include is not allowed")
)

type Merger struct {
	entry             string
	entryDir          string
	entryToSectionMap map[string]map[string][]*config_parser.Item
	// overrides maps absolute cleaned paths to replacement bytes. An override
	// only replaces the bytes read for a file that already exists on disk.
	overrides map[string][]byte
	// origins records, per section name, every file-level occurrence parsed
	// during Merge. It is used by the managed-layout gate.
	origins map[string][]SectionOrigin
}

// SectionOrigin is one occurrence of a section in a parsed file.
type SectionOrigin struct {
	File      string
	StartLine int
	EndLine   int
}

func NewMerger(entry string) *Merger {
	return &Merger{
		entry:             entry,
		entryDir:          filepath.Dir(entry),
		entryToSectionMap: map[string]map[string][]*config_parser.Item{},
		origins:           map[string][]SectionOrigin{},
	}
}

// NewMergerWithOverrides behaves like NewMerger, but reads the files whose
// paths appear in overrides from the given bytes instead of disk. Resolution,
// the permission check and parsing are unchanged.
func NewMergerWithOverrides(entry string, overrides map[string][]byte) *Merger {
	m := NewMerger(entry)
	if len(overrides) > 0 {
		m.overrides = make(map[string][]byte, len(overrides))
		for p, b := range overrides {
			m.overrides[absCleanPath(p)] = b
		}
	}
	return m
}

func absCleanPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

func (m *Merger) Merge() (sections []*config_parser.Section, entries []string, err error) {
	err = m.dfsMerge(m.entry, "")
	if err != nil {
		return nil, nil, err
	}
	entries, err = common.MapKeys(m.entryToSectionMap)
	if err != nil {
		return nil, nil, err
	}
	return m.convertMapToSections(m.entryToSectionMap[m.entry]), entries, nil
}

// MergeWithOrigins behaves like Merge and additionally returns, per section
// name, the files and line ranges the section was parsed from.
func (m *Merger) MergeWithOrigins() (sections []*config_parser.Section, origins map[string][]SectionOrigin, err error) {
	sections, _, err = m.Merge()
	if err != nil {
		return nil, nil, err
	}
	return sections, m.origins, nil
}

func (m *Merger) readEntry(entry string) (err error) {
	// Check circular include.
	_, exist := m.entryToSectionMap[entry]
	if exist {
		return ErrCircularInclude
	}

	// Check filename
	if !strings.HasSuffix(entry, ".dae") {
		return fmt.Errorf("invalid config filename %v: must has suffix .dae", entry)
	}
	// Check file path security.
	if err = common.EnsureFileInSubDir(entry, m.entryDir); err != nil {
		return fmt.Errorf("failed in checking path of config file %v: %w", entry, err)
	}
	f, err := os.Open(entry)
	if err != nil {
		return fmt.Errorf("failed to read config file %v: %w", entry, err)
	}
	defer func() { _ = f.Close() }()
	// Check file access.
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("cannot include a directory: %v", entry)
	}
	if fi.Mode()&0037 > 0 {
		return fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", fi.Mode()&0777, entry)
	}
	// Read and parse.
	b, overridden := m.overrides[absCleanPath(entry)]
	if !overridden {
		if b, err = io.ReadAll(f); err != nil {
			return err
		}
	}
	entrySections, err := config_parser.Parse(string(b))
	if err != nil {
		return fmt.Errorf("failed to parse config file %v:\n%w", entry, err)
	}
	m.entryToSectionMap[entry] = m.convertSectionsToMap(entrySections)
	for _, sec := range entrySections {
		m.origins[sec.Name] = append(m.origins[sec.Name], SectionOrigin{
			File:      entry,
			StartLine: sec.StartLine,
			EndLine:   sec.EndLine,
		})
	}
	return nil
}

func unsqueezeEntries(patternEntries []string) (unsqueezed []string, err error) {
	unsqueezed = make([]string, 0, len(patternEntries))
	for _, pattern := range patternEntries {
		files, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			// We only support .dae
			if !strings.HasSuffix(file, ".dae") {
				continue
			}
			fi, err := os.Stat(file)
			if err != nil {
				return nil, err
			}
			if fi.IsDir() {
				continue
			}
			unsqueezed = append(unsqueezed, file)
		}
	}
	if len(unsqueezed) == 0 {
		unsqueezed = nil
	}
	return unsqueezed, nil
}

func (m *Merger) dfsMerge(entry string, fatherEntry string) (err error) {
	// Read entry and check circular include.
	if err = m.readEntry(entry); err != nil {
		if errors.Is(err, ErrCircularInclude) {
			return fmt.Errorf("%w: %v -> %v -> ... -> %v", err, fatherEntry, entry, fatherEntry)
		}
		return err
	}
	sectionMap := m.entryToSectionMap[entry]
	// Extract childEntries.
	includes := sectionMap["include"]
	var patterEntries = make([]string, 0, len(includes))
	for _, include := range includes {
		switch v := include.Value.(type) {
		case *config_parser.Param:
			nextEntry := v.String(true, false)
			if filepath.IsAbs(nextEntry) {
				patterEntries = append(patterEntries, nextEntry)
			} else {
				patterEntries = append(patterEntries, filepath.Join(m.entryDir, nextEntry))
			}
		default:
			return fmt.Errorf("unsupported include grammar in %v: %v", entry, include.String(false, false))
		}
	}
	// DFS and merge children recursively.
	childEntries, err := unsqueezeEntries(patterEntries)
	if err != nil {
		return err
	}
	for _, nextEntry := range childEntries {
		if err = m.dfsMerge(nextEntry, entry); err != nil {
			return err
		}
	}
	/// Merge into father. Do not need to retrieve sectionMap again because go map is a reference.
	if fatherEntry == "" {
		// We are already on the top.
		return nil
	}
	fatherSectionMap := m.entryToSectionMap[fatherEntry]
	for sec := range sectionMap {
		items := m.mergeItems(fatherSectionMap[sec], sectionMap[sec])
		fatherSectionMap[sec] = items
	}
	return nil
}

func (m *Merger) convertSectionsToMap(sections []*config_parser.Section) (sectionMap map[string][]*config_parser.Item) {
	sectionMap = make(map[string][]*config_parser.Item)
	for _, sec := range sections {
		items, ok := sectionMap[sec.Name]
		if ok {
			sectionMap[sec.Name] = m.mergeItems(items, sec.Items)
		} else {
			sectionMap[sec.Name] = sec.Items
		}
	}
	return sectionMap
}

func (m *Merger) convertMapToSections(sectionMap map[string][]*config_parser.Item) (sections []*config_parser.Section) {
	sections = make([]*config_parser.Section, 0, len(sectionMap))
	for name, items := range sectionMap {
		sections = append(sections, &config_parser.Section{
			Name:  name,
			Items: items,
		})
	}
	return sections
}

func (m *Merger) mergeItems(to, from []*config_parser.Item) (items []*config_parser.Item) {
	items = make([]*config_parser.Item, len(to)+len(from))
	copy(items, to)
	copy(items[len(to):], from)
	return items
}
