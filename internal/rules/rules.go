package rules

import (
    "errors"
    "math"
    "regexp"
    "strings"
)

type PatternRuleConfig struct {
    ID          string   `yaml:"id"`
    Description string   `yaml:"description"`
    Regex       string   `yaml:"regex"`
    Severity    string   `yaml:"severity"`
    Tags        []string `yaml:"tags"`
}

type EntropyRuleConfig struct {
    ID               string   `yaml:"id"`
    Description      string   `yaml:"description"`
    MinLength        int      `yaml:"min_length"`
    EntropyThreshold float64  `yaml:"entropy_threshold"`
    Severity         string   `yaml:"severity"`
    Tags             []string `yaml:"tags"`
}

type PatternRule struct {
    ID          string
    Description string
    Re          *regexp.Regexp
    Severity    string
    Tags        []string
}

type EntropyRule struct {
    ID               string
    Description      string
    MinLength        int
    EntropyThreshold float64
    Severity         string
    Tags             []string
}

type RuleSet struct {
    SensitiveFilenames []string
    PatternRules       []PatternRule
    EntropyRules       []EntropyRule
    entropyTokenRe     *regexp.Regexp
}

func NewRuleSet(files []string, patternCfgs []PatternRuleConfig, entropyCfgs []EntropyRuleConfig) (*RuleSet, error) {
    rs := &RuleSet{
        SensitiveFilenames: make([]string, len(files)),
        entropyTokenRe:     regexp.MustCompile(`[A-Za-z0-9+/=_\-]{8,}`),
    }
    for i, f := range files {
        rs.SensitiveFilenames[i] = strings.ToLower(f)
    }

    for _, cfg := range patternCfgs {
        if cfg.ID == "" || cfg.Regex == "" {
            return nil, errors.New("pattern rule missing id or regex")
        }
        re, err := regexp.Compile(cfg.Regex)
        if err != nil {
            return nil, err
        }
        rs.PatternRules = append(rs.PatternRules, PatternRule{
            ID:          cfg.ID,
            Description: cfg.Description,
            Re:          re,
            Severity:    cfg.Severity,
            Tags:        cfg.Tags,
        })
    }

    for _, cfg := range entropyCfgs {
        if cfg.ID == "" || cfg.MinLength <= 0 {
            return nil, errors.New("entropy rule missing id or min_length")
        }
        rs.EntropyRules = append(rs.EntropyRules, EntropyRule{
            ID:               cfg.ID,
            Description:      cfg.Description,
            MinLength:        cfg.MinLength,
            EntropyThreshold: cfg.EntropyThreshold,
            Severity:         cfg.Severity,
            Tags:             cfg.Tags,
        })
    }

    return rs, nil
}

func (rs *RuleSet) IsSensitiveFilename(name string) bool {
    name = strings.ToLower(name)
    for _, f := range rs.SensitiveFilenames {
        if strings.Contains(name, f) {
            return true
        }
    }
    return false
}

type PatternMatch struct {
    RuleID      string
    Description string
    Match       string
    Severity    string
    Tags        []string
}

type EntropyMatch struct {
    RuleID      string
    Description string
    Value       string
    Entropy     float64
    Severity    string
    Tags        []string
}

func (rs *RuleSet) MatchPatterns(line string) []PatternMatch {
    var out []PatternMatch
    for _, rule := range rs.PatternRules {
        matches := rule.Re.FindAllString(line, -1)
        for _, m := range matches {
            out = append(out, PatternMatch{
                RuleID:      rule.ID,
                Description: rule.Description,
                Match:       m,
                Severity:    rule.Severity,
                Tags:        rule.Tags,
            })
        }
    }
    return out
}

func (rs *RuleSet) MatchEntropy(line string) []EntropyMatch {
    var out []EntropyMatch
    tokens := rs.entropyTokenRe.FindAllString(line, -1)

    for _, rule := range rs.EntropyRules {
        for _, t := range tokens {
            if len(t) < rule.MinLength {
                continue
            }
            e := shannonEntropy(t)
            if e >= rule.EntropyThreshold {
                out = append(out, EntropyMatch{
                    RuleID:      rule.ID,
                    Description: rule.Description,
                    Value:       t,
                    Entropy:     e,
                    Severity:    rule.Severity,
                    Tags:        rule.Tags,
                })
            }
        }
    }
    return out
}

func shannonEntropy(s string) float64 {
    if len(s) == 0 {
        return 0.0
    }
    freq := make(map[rune]int)
    for _, ch := range s {
        freq[ch]++
    }
    var entropy float64
    l := float64(len(s))
    for _, c := range freq {
        p := float64(c) / l
        entropy -= p * math.Log2(p)
    }
    return entropy
}
