package scanner

import (
    "bufio"
    "bytes"
    "io/fs"
    "os"
    "path/filepath"
    "strings"
    "sync"

    "superscan/internal/rules"
)

type Options struct {
    IgnoreDirs       []string
    MaxFileSizeBytes int64
    Workers          int
}

type Finding struct {
    File        string   `json:"file"`
    Line        int      `json:"line"`
    RuleID      string   `json:"rule_id"`
    Description string   `json:"description"`
    Snippet     string   `json:"snippet"`
    Match       string   `json:"match,omitempty"`
    Entropy     float64  `json:"entropy,omitempty"`
    Type        string   `json:"type"` // pattern | entropy | filename | error
    Severity    string   `json:"severity"`
    Tags        []string `json:"tags,omitempty"`
    Fingerprint string   `json:"fingerprint"`
}

type job struct {
    path string
    info fs.FileInfo
}

func Scan(root string, rs *rules.RuleSet, opts Options) ([]Finding, error) {
    if opts.Workers <= 0 {
        opts.Workers = 4
    }
    var findingsMu sync.Mutex
    var findings []Finding

    jobCh := make(chan job, opts.Workers*2)
    var wg sync.WaitGroup

    for i := 0; i < opts.Workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := range jobCh {
                fs := scanFile(j.path, j.info, rs, opts)
                if len(fs) > 0 {
                    findingsMu.Lock()
                    findings = append(findings, fs...)
                    findingsMu.Unlock()
                }
            }
        }()
    }

    ignored := make(map[string]struct{})
    for _, d := range opts.IgnoreDirs {
        ignored[d] = struct{}{}
    }

    var walkErr error
    err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            walkErr = err
            return nil
        }
        if d.IsDir() {
            if _, ok := ignored[d.Name()]; ok {
                return filepath.SkipDir
            }
            return nil
        }

        info, err := d.Info()
        if err != nil {
            return nil
        }

        if opts.MaxFileSizeBytes > 0 && info.Size() > opts.MaxFileSizeBytes {
            return nil
        }

        jobCh <- job{path: path, info: info}
        return nil
    })

    close(jobCh)
    wg.Wait()

    if err != nil && err != fs.SkipDir {
        return findings, err
    }
    return findings, walkErr
}

func scanFile(path string, info fs.FileInfo, rs *rules.RuleSet, opts Options) []Finding {
    var out []Finding

    if rs.IsSensitiveFilename(info.Name()) {
        f := Finding{
            File:        path,
            Line:        0,
            RuleID:      "sensitive_filename",
            Description: "Suspicious filename",
            Snippet:     info.Name(),
            Type:        "filename",
            Severity:    "medium",
            Tags:        []string{"filename"},
        }
        out = append(out, f)
    }

    raw, err := os.ReadFile(path)
    if err != nil {
        out = append(out, Finding{
            File:        path,
            RuleID:      "read_error",
            Description: err.Error(),
            Type:        "error",
            Severity:    "low",
        })
        return out
    }

    if looksBinary(raw) {
        return out
    }

    scanner := bufio.NewScanner(bytes.NewReader(raw))
    lineNum := 0
    for scanner.Scan() {
        lineNum++
        line := scanner.Text()

        for _, m := range rs.MatchPatterns(line) {
            f := Finding{
                File:        path,
                Line:        lineNum,
                RuleID:      m.RuleID,
                Description: m.Description,
                Snippet:     trimLine(line),
                Match:       m.Match,
                Type:        "pattern",
                Severity:    m.Severity,
                Tags:        m.Tags,
            }
            out = append(out, f)
        }

        for _, em := range rs.MatchEntropy(line) {
            f := Finding{
                File:        path,
                Line:        lineNum,
                RuleID:      em.RuleID,
                Description: em.Description,
                Snippet:     trimLine(line),
                Match:       em.Value,
                Entropy:     em.Entropy,
                Type:        "entropy",
                Severity:    em.Severity,
                Tags:        em.Tags,
            }
            out = append(out, f)
        }
    }

    if err := scanner.Err(); err != nil {
        out = append(out, Finding{
            File:        path,
            RuleID:      "scan_error",
            Description: "Error scanning file: " + err.Error(),
            Type:        "error",
            Severity:    "low",
        })
    }

    return out
}

func looksBinary(b []byte) bool {
    if len(b) == 0 {
        return false
    }
    if bytes.IndexByte(b, 0x00) != -1 {
        return true
    }
    nonText := 0
    sample := b
    if len(sample) > 8000 {
        sample = sample[:8000]
    }
    for _, c := range sample {
        if c == 9 || c == 10 || c == 13 {
            continue
        }
        if c < 32 || c > 126 {
            nonText++
        }
    }
    return nonText > len(sample)/10
}

func trimLine(s string) string {
    s = strings.TrimSpace(s)
    if len(s) > 200 {
        return s[:200] + "..."
    }
    return s
}
