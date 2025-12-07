package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "strings"
    "time"

    "gopkg.in/yaml.v3"

    "superscan/internal/report"
    "superscan/internal/rules"
    "superscan/internal/scanner"
)

type Config struct {
    IgnoreDirs       []string                  `yaml:"ignore_dirs"`
    MaxFileSizeBytes int64                     `yaml:"max_file_size_bytes"`
    SensitiveFiles   []string                  `yaml:"sensitive_filenames"`
    PatternRules     []rules.PatternRuleConfig `yaml:"patterns"`
    EntropyRules     []rules.EntropyRuleConfig `yaml:"entropy_rules"`
}

func loadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    return &cfg, nil
}

func main() {
    var (
        configPath     string
        jsonOut        bool
        sarifOut       bool
        workers        int
        baselinePath   string
        createBaseline bool
    )

    flag.StringVar(&configPath, "config", "config.yml", "Path to YAML config")
    flag.BoolVar(&jsonOut, "json", false, "Output JSON instead of text")
    flag.BoolVar(&sarifOut, "sarif", false, "Output SARIF (GitHub Security) format")
    flag.IntVar(&workers, "workers", 8, "Number of concurrent workers")
    flag.StringVar(&baselinePath, "baseline", "", "Path to baseline JSON (ignore known findings)")
    flag.BoolVar(&createBaseline, "baseline-create", false, "Create baseline file from current scan (use with --baseline)")
    flag.Parse()

    if flag.NArg() < 1 {
        fmt.Println("Usage: superscan [options] <path>")
        flag.PrintDefaults()
        os.Exit(1)
    }

    rootPath := flag.Arg(0)

    cfg, err := loadConfig(configPath)
    if err != nil {
        log.Fatalf("failed to load config: %v", err)
    }

    ruleSet, err := rules.NewRuleSet(cfg.SensitiveFiles, cfg.PatternRules, cfg.EntropyRules)
    if err != nil {
        log.Fatalf("failed to build rule set: %v", err)
    }

    opts := scanner.Options{
        IgnoreDirs:       cfg.IgnoreDirs,
        MaxFileSizeBytes: cfg.MaxFileSizeBytes,
        Workers:          workers,
    }

    start := time.Now()
    findings, scanErr := scanner.Scan(rootPath, ruleSet, opts)
    duration := time.Since(start)

    if scanErr != nil {
        log.Printf("scan completed with errors: %v", scanErr)
    }

    // Attach fingerprints
    for i := range findings {
        findings[i].Fingerprint = scanner.BuildFingerprint(findings[i])
    }

    var baseline *scanner.Baseline
    if baselinePath != "" && !createBaseline {
        b, err := scanner.LoadBaseline(baselinePath)
        if err != nil {
            log.Fatalf("failed to load baseline: %v", err)
        }
        baseline = b
    }

    filtered := findings
    if baseline != nil && !createBaseline {
        var tmp []scanner.Finding
        for _, f := range filtered {
            if !baseline.IsIgnored(f) {
                tmp = append(tmp, f)
            }
        }
        filtered = tmp
    }

    if createBaseline {
        if baselinePath == "" {
            log.Fatalf("--baseline-create requires --baseline <path>")
        }
        if err := scanner.WriteBaseline(baselinePath, findings); err != nil {
            log.Fatalf("failed to write baseline: %v", err)
        }
        log.Printf("Baseline written to %s", baselinePath)
    }

    // Output
    if jsonOut {
        out := report.JSONReport{
            RootPath: rootPath,
            Duration: duration.String(),
            Findings: filtered,
        }
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        if err := enc.Encode(out); err != nil {
            log.Fatalf("failed to write JSON: %v", err)
        }
    } else if sarifOut {
        sarif := report.GenerateSARIF(filtered)
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        if err := enc.Encode(sarif); err != nil {
            log.Fatalf("failed to write SARIF: %v", err)
        }
    } else {
        report.PrintTextReport(rootPath, duration, filtered)
    }

    // Exit codes based on severity
    criticalCount := 0
    highCount := 0

    for _, f := range filtered {
        switch strings.ToLower(f.Severity) {
        case "critical":
            criticalCount++
        case "high":
            highCount++
        }
    }

    if criticalCount > 0 {
        os.Exit(2)
    }
    if highCount > 0 {
        os.Exit(1)
    }
}
