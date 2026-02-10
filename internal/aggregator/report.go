package aggregator

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/imanology1/comply-intel/internal/executor"
)

// SecurityTeamReport is the full output combining all agent perspectives.
type SecurityTeamReport struct {
	GeneratedAt       string              `json:"generated_at"`
	RiskAssessment    *RiskAssessment     `json:"risk_assessment"`
	ComplianceReports []*ComplianceReport `json:"compliance_reports"`
}

// GenerateTeamReport runs all aggregation agents and produces the unified report.
func GenerateTeamReport(findings []executor.EnrichedFinding) *SecurityTeamReport {
	return &SecurityTeamReport{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		RiskAssessment:    AssessRisk(findings),
		ComplianceReports: GenerateAllReports(findings),
	}
}

// PrintTeamReport renders the full security team report to the writer.
func PrintTeamReport(w io.Writer, report *SecurityTeamReport) {
	fmt.Fprintf(w, "\n")
	printBanner(w)
	fmt.Fprintf(w, "  Generated: %s\n", report.GeneratedAt)
	fmt.Fprintf(w, "\n")

	printRiskDashboard(w, report.RiskAssessment)
	printTopRisks(w, report.RiskAssessment)
	printComplianceDashboard(w, report.ComplianceReports)
	printGapAnalysis(w, report.ComplianceReports)
	printRemediationPlan(w, report.RiskAssessment)
}

// PrintTeamReportJSON writes the full report as JSON.
func PrintTeamReportJSON(w io.Writer, report *SecurityTeamReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func printBanner(w io.Writer) {
	fmt.Fprintf(w, "=============================================================\n")
	fmt.Fprintf(w, "          COMPLY-INTEL :: SECURITY TEAM REPORT\n")
	fmt.Fprintf(w, "=============================================================\n")
}

func printRiskDashboard(w io.Writer, ra *RiskAssessment) {
	fmt.Fprintf(w, "--- RISK ASSESSMENT AGENT ---\n\n")

	riskIndicator := riskColorIndicator(ra.OverallRisk)

	fmt.Fprintf(w, "  Overall Compliance Score: %.0f%% %s\n", ra.OverallScore, riskIndicator)
	fmt.Fprintf(w, "  Risk Level:              %s\n", ra.OverallRisk)
	fmt.Fprintf(w, "  Total Findings:          %d\n", ra.TotalFindings)
	fmt.Fprintf(w, "  Passed:                  %d\n", ra.PassCount)
	fmt.Fprintf(w, "  Failed:                  %d\n", ra.FailCount)
	fmt.Fprintf(w, "  Errors:                  %d\n", ra.ErrorCount)
	fmt.Fprintf(w, "\n")

	if len(ra.CategoryScores) > 0 {
		fmt.Fprintf(w, "  Category Scores:\n")
		for cat, score := range ra.CategoryScores {
			bar := renderBar(score, 30)
			fmt.Fprintf(w, "    %-20s %s %.0f%%\n", cat, bar, score)
		}
		fmt.Fprintf(w, "\n")
	}
}

func printTopRisks(w io.Writer, ra *RiskAssessment) {
	if len(ra.TopRisks) == 0 {
		return
	}

	fmt.Fprintf(w, "--- TOP RISKS ---\n\n")

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  #\tSEVERITY\tPACK\tCHECK\tRESOURCE\tDESCRIPTION\n")
	fmt.Fprintf(tw, "  -\t--------\t----\t-----\t--------\t-----------\n")

	limit := len(ra.TopRisks)
	if limit > 10 {
		limit = 10
	}

	for _, r := range ra.TopRisks[:limit] {
		msg := r.Message
		if len(msg) > 60 {
			msg = msg[:57] + "..."
		}
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\t%s\n",
			r.Rank, r.Severity, r.Pack, r.CheckID, r.ResourceID, msg)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n")
}

func printComplianceDashboard(w io.Writer, reports []*ComplianceReport) {
	if len(reports) == 0 {
		return
	}

	fmt.Fprintf(w, "--- COMPLIANCE DASHBOARD ---\n\n")

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  FRAMEWORK\tSCORE\tSTATUS\tPASS\tFAIL\tNOT TESTED\n")
	fmt.Fprintf(tw, "  ---------\t-----\t------\t----\t----\t----------\n")

	for _, r := range reports {
		bar := renderBar(r.OverallScore, 15)
		fmt.Fprintf(tw, "  %s\t%s %.0f%%\t%s\t%d\t%d\t%d\n",
			r.FrameworkName, bar, r.OverallScore, r.Status,
			r.PassedControls, r.FailedControls, r.NotTested)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n")
}

func printGapAnalysis(w io.Writer, reports []*ComplianceReport) {
	hasGaps := false
	for _, r := range reports {
		if len(r.GapAnalysis) > 0 {
			hasGaps = true
			break
		}
	}
	if !hasGaps {
		return
	}

	fmt.Fprintf(w, "--- GAP ANALYSIS ---\n\n")

	for _, r := range reports {
		if len(r.GapAnalysis) == 0 {
			continue
		}

		fmt.Fprintf(w, "  [%s]\n", r.FrameworkName)

		for _, gap := range r.GapAnalysis {
			fmt.Fprintf(w, "    %s (%s)\n", gap.ControlID, gap.ControlName)
			fmt.Fprintf(w, "      Gap: %s\n", gap.Gap)
			if len(gap.Checks) > 0 {
				fmt.Fprintf(w, "      Failing checks: %s\n", strings.Join(gap.Checks, ", "))
			}
		}
		fmt.Fprintf(w, "\n")
	}
}

func printRemediationPlan(w io.Writer, ra *RiskAssessment) {
	if len(ra.RemediationPlan) == 0 {
		return
	}

	fmt.Fprintf(w, "--- REMEDIATION PLAN (Prioritized) ---\n\n")

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  #\tSEVERITY\tACTION\tIMPACT\n")
	fmt.Fprintf(tw, "  -\t--------\t------\t------\n")

	limit := len(ra.RemediationPlan)
	if limit > 15 {
		limit = 15
	}

	for _, item := range ra.RemediationPlan[:limit] {
		action := item.Action
		if len(action) > 70 {
			action = action[:67] + "..."
		}
		impact := item.Impact
		if len(impact) > 50 {
			impact = impact[:47] + "..."
		}
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n",
			item.Priority, item.Severity, action, impact)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n=============================================================\n")
	fmt.Fprintf(w, "                    END OF REPORT\n")
	fmt.Fprintf(w, "=============================================================\n")
}

func riskColorIndicator(level RiskLevel) string {
	switch level {
	case RiskCritical:
		return "[!!! CRITICAL !!!]"
	case RiskHigh:
		return "[!! HIGH !!]"
	case RiskMedium:
		return "[! MEDIUM]"
	case RiskLow:
		return "[OK]"
	default:
		return ""
	}
}

func renderBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	empty := width - filled
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", empty) + "]"
}
