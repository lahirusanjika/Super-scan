package scanner

import (
    "crypto/sha1"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
)

type BaselineEntry struct {
    Fingerprint string `json:"fingerprint"`
    RuleID      string `json:"rule_id"`
    Comment     string `json:"comment,omitempty"`
}

type Baseline struct {
    Version int             `json:"version"`
    Entries []BaselineEntry `json:"entries"`
    lookup  map[string]BaselineEntry
}

func LoadBaseline(path string) (*Baseline, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var b Baseline
    if err := json.Unmarshal(data, &b); err != nil {
        return nil, err
    }
    b.lookup = make(map[string]BaselineEntry, len(b.Entries))
    for _, e := range b.Entries {
        b.lookup[e.Fingerprint] = e
    }
    return &b, nil
}

func (b *Baseline) IsIgnored(f Finding) bool {
    if b == nil {
        return false
    }
    _, ok := b.lookup[f.Fingerprint]
    return ok
}

func BuildFingerprint(f Finding) string {
    h := sha1.New()
    fmt.Fprintf(h, "%s|%d|%s|%s", f.File, f.Line, f.RuleID, f.Match)
    return hex.EncodeToString(h.Sum(nil))[:16]
}

func WriteBaseline(path string, findings []Finding) error {
    b := Baseline{
        Version: 1,
    }

    seen := make(map[string]bool)
    for _, f := range findings {
        fp := f.Fingerprint
        if fp == "" {
            fp = BuildFingerprint(f)
        }
        if seen[fp] {
            continue
        }
        seen[fp] = true
        b.Entries = append(b.Entries, BaselineEntry{
            Fingerprint: fp,
            RuleID:      f.RuleID,
        })
    }

    data, err := json.MarshalIndent(b, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0644)
}
