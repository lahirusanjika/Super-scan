package report

import (
	"fmt"
	"time"

	"superscan/internal/scanner"
)

type JSONReport struct {
	RootPath string            `json:"root_path"`
	Duration string            `json:"duration"`
	Findings []scanner.Finding `json:"findings"`
}

// SARIF Structures
type SarifReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name            string      `json:"name"`
	InformationUri  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string           `json:"id"`
	ShortDescription ShortDescription `json:"shortDescription"`
	Properties       Properties       `json:"properties"`
}

type ShortDescription struct {
	Text string `json:"text"`
}

type Properties struct {
	Tags     []string `json:"tags"`
	Severity string   `json:"severity"`
}

type Result struct {
	RuleID      string      `json:"ruleId"`
	Level       string      `json:"level"` // error, warning, note
	Message     Message     `json:"message"`
	Locations   []Location  `json:"locations"`
	Fingerprints Fingerprints `json:"fingerprints"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	Uri string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type Fingerprints struct {
    MatchSha1 string `json:"matchSha1"`
}

func GenerateSARIF(findings []scanner.Finding) SarifReport {
	rulesMap := make(map[string]scanner.Finding)
	for _, f := range findings {
		rulesMap[f.RuleID] = f
	}

	var sarifRules []SarifRule
	for _, f := range rulesMap {
		sarifRules = append(sarifRules, SarifRule{
			ID: f.RuleID,
			ShortDescription: ShortDescription{
				Text: f.Description,
			},
			Properties: Properties{
				Tags:     f.Tags,
				Severity: f.Severity,
			},
		})
	}

	var results []Result
	for _, f := range findings {
		level := "warning"
		if f.Severity == "critical" || f.Severity == "high" {
			level = "error"
		} else if f.Severity == "low" {
			level = "note"
		}

		results = append(results, Result{
			RuleID: f.RuleID,
			Level:  level,
			Message: Message{
				Text: fmt.Sprintf("Found potential secret: %s", f.Description),
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							Uri: f.File,
						},
						Region: Region{
							StartLine: f.Line,
						},
					},
				},
			},
            Fingerprints: Fingerprints{
                MatchSha1: f.Fingerprint,
            },
		})
	}

	return SarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:            "Superscan",
						InformationUri:  "https://github.com/yourusername/superscan",
						SemanticVersion: "1.0.0",
						Rules:           sarifRules,
					},
				},
				Results: results,
			},
		},
	}
}

func PrintTextReport(root string, duration time.Duration, findings []scanner.Finding) {
    fmt.Printf("Scan root: %s\n", root)
    fmt.Printf("Duration : %s\n", duration)
    fmt.Printf("Findings : %d\n\n", len(findings))

    if len(findings) == 0 {
        fmt.Println("No potential secrets found.")
        return
    }

    for _, f := range findings {
        loc := f.File
        if f.Line > 0 {
            loc = fmt.Sprintf("%s:%d", f.File, f.Line)
        }
        fmt.Printf("[%s] %s\n", f.Type, loc)
        fmt.Printf("  Rule     : %s\n", f.RuleID)
        fmt.Printf("  Severity : %s\n", f.Severity)
        fmt.Printf("  Desc     : %s\n", f.Description)
        if len(f.Tags) > 0 {
            fmt.Printf("  Tags     : %v\n", f.Tags)
        }
        if f.Match != "" {
            fmt.Printf("  Match    : %s\n", f.Match)
        }
        if f.Entropy > 0 {
            fmt.Printf("  Entropy  : %.2f\n", f.Entropy)
        }
        if f.Fingerprint != "" {
            fmt.Printf("  FP       : %s\n", f.Fingerprint)
        }
        fmt.Printf("  Line     : %s\n\n", f.Snippet)
    }
}
