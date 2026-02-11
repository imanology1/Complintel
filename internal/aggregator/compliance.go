package aggregator

import (
	"math"
	"strings"

	"github.com/imanology1/comply-intel/internal/executor"
)

// ComplianceReport is a framework-specific compliance assessment.
type ComplianceReport struct {
	Framework      string                    `json:"framework"`
	FrameworkName  string                    `json:"framework_name"`
	OverallScore   float64                   `json:"overall_score"`
	Status         string                    `json:"status"` // "COMPLIANT", "NON-COMPLIANT", "PARTIAL"
	TotalControls  int                       `json:"total_controls"`
	PassedControls int                       `json:"passed_controls"`
	FailedControls int                       `json:"failed_controls"`
	NotTested      int                       `json:"not_tested"`
	ControlResults []ControlResult           `json:"control_results"`
	GapAnalysis    []GapItem                 `json:"gap_analysis"`
}

// ControlResult maps a framework control to its compliance status.
type ControlResult struct {
	ControlID   string   `json:"control_id"`
	ControlName string   `json:"control_name"`
	Category    string   `json:"category"`
	Status      string   `json:"status"` // "PASS", "FAIL", "PARTIAL", "NOT_TESTED"
	Findings    int      `json:"findings"`
	PassCount   int      `json:"pass_count"`
	FailCount   int      `json:"fail_count"`
	Checks      []string `json:"checks"`
}

// GapItem identifies a specific compliance gap requiring attention.
type GapItem struct {
	ControlID   string   `json:"control_id"`
	ControlName string   `json:"control_name"`
	Gap         string   `json:"gap_description"`
	Checks      []string `json:"failing_checks"`
}

// GenerateComplianceReport produces a compliance report for a specific framework.
func GenerateComplianceReport(frameworkID string, findings []executor.EnrichedFinding) *ComplianceReport {
	var fw *FrameworkDefinition
	for _, f := range AllFrameworks() {
		if strings.EqualFold(f.ID, frameworkID) || strings.HasPrefix(strings.ToUpper(frameworkID), f.ID) {
			fCopy := f
			fw = &fCopy
			break
		}
	}

	if fw == nil {
		return &ComplianceReport{
			Framework: frameworkID,
			Status:    "UNKNOWN_FRAMEWORK",
		}
	}

	report := &ComplianceReport{
		Framework:     fw.ID,
		FrameworkName: fw.Name,
		TotalControls: len(fw.Controls),
	}

	// Build a mapping: control ID -> findings that reference it
	controlFindings := mapFindingsToControls(fw, findings)

	for _, ctrl := range fw.Controls {
		cr := ControlResult{
			ControlID:   ctrl.ID,
			ControlName: ctrl.Name,
			Category:    ctrl.Category,
		}

		matched := controlFindings[ctrl.ID]
		cr.Findings = len(matched)

		if len(matched) == 0 {
			cr.Status = "NOT_TESTED"
			report.NotTested++
		} else {
			for _, f := range matched {
				switch f.Status {
				case "PASS":
					cr.PassCount++
				case "FAIL":
					cr.FailCount++
					cr.Checks = append(cr.Checks, f.CheckID)
				}
			}

			if cr.FailCount == 0 {
				cr.Status = "PASS"
				report.PassedControls++
			} else if cr.PassCount > 0 {
				cr.Status = "PARTIAL"
				report.FailedControls++
			} else {
				cr.Status = "FAIL"
				report.FailedControls++
			}
		}

		report.ControlResults = append(report.ControlResults, cr)
	}

	// Calculate score (only over tested controls)
	tested := report.PassedControls + report.FailedControls
	if tested > 0 {
		report.OverallScore = math.Round(float64(report.PassedControls) / float64(tested) * 100)
	}

	switch {
	case report.OverallScore >= 95:
		report.Status = "COMPLIANT"
	case report.OverallScore >= 70:
		report.Status = "PARTIAL"
	default:
		report.Status = "NON-COMPLIANT"
	}

	// Build gap analysis
	for _, cr := range report.ControlResults {
		if cr.Status == "FAIL" || cr.Status == "PARTIAL" {
			report.GapAnalysis = append(report.GapAnalysis, GapItem{
				ControlID:   cr.ControlID,
				ControlName: cr.ControlName,
				Gap:         describeGap(cr),
				Checks:      cr.Checks,
			})
		}
	}

	return report
}

// GenerateAllReports produces compliance reports for all known frameworks.
func GenerateAllReports(findings []executor.EnrichedFinding) []*ComplianceReport {
	var reports []*ComplianceReport
	for _, fw := range AllFrameworks() {
		r := GenerateComplianceReport(fw.ID, findings)
		// Only include if there are any tested controls
		tested := r.PassedControls + r.FailedControls
		if tested > 0 {
			reports = append(reports, r)
		}
	}
	return reports
}

// mapFindingsToControls maps each framework control ID to findings whose
// Frameworks field references that control.
func mapFindingsToControls(fw *FrameworkDefinition, findings []executor.EnrichedFinding) map[string][]executor.EnrichedFinding {
	result := make(map[string][]executor.EnrichedFinding)

	// Build a set of control IDs in this framework, plus prefix matching
	controlIDs := make(map[string]bool)
	for _, ctrl := range fw.Controls {
		controlIDs[ctrl.ID] = true
	}

	for _, f := range findings {
		for _, fwRef := range f.Frameworks {
			// Direct match
			if controlIDs[fwRef] {
				result[fwRef] = append(result[fwRef], f)
				continue
			}

			// Prefix match: a finding tagged "SOC2-CC6.1" maps to control "SOC2-CC6.1"
			// Also: a finding tagged "SOC2" maps to all SOC2- controls
			for ctrlID := range controlIDs {
				if strings.HasPrefix(ctrlID, fwRef) || strings.HasPrefix(fwRef, ctrlID) {
					result[ctrlID] = append(result[ctrlID], f)
				}
			}
		}
	}

	return result
}

func describeGap(cr ControlResult) string {
	if cr.PassCount > 0 && cr.FailCount > 0 {
		return "Partially implemented — some checks pass but others fail. Review failing checks."
	}
	return "Not implemented — all related checks are failing. Requires immediate attention."
}
