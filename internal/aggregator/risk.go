package aggregator

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/imanology1/comply-intel/internal/executor"
)

// RiskLevel classifies the overall risk posture.
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
	RiskInfo     RiskLevel = "INFORMATIONAL"
)

// RiskAssessment is the top-level output of the risk assessment agent.
type RiskAssessment struct {
	OverallScore     float64            `json:"overall_score"`      // 0-100, higher is better
	OverallRisk      RiskLevel          `json:"overall_risk"`
	TotalFindings    int                `json:"total_findings"`
	PassCount        int                `json:"pass_count"`
	FailCount        int                `json:"fail_count"`
	ErrorCount       int                `json:"error_count"`
	CategoryScores   map[string]float64 `json:"category_scores"`
	TopRisks         []RiskItem         `json:"top_risks"`
	RemediationPlan  []RemediationItem  `json:"remediation_plan"`
}

// RiskItem represents a specific risk finding prioritized by severity.
type RiskItem struct {
	Rank         int    `json:"rank"`
	Severity     string `json:"severity"`
	Pack         string `json:"pack"`
	CheckID      string `json:"check_id"`
	ResourceID   string `json:"resource_id"`
	Message      string `json:"message"`
	RiskScore    float64 `json:"risk_score"`
}

// RemediationItem is a prioritized remediation action.
type RemediationItem struct {
	Priority     int      `json:"priority"`
	Action       string   `json:"action"`
	Impact       string   `json:"impact"`
	AffectedBy   []string `json:"affected_frameworks"`
	Severity     string   `json:"severity"`
	ResourceID   string   `json:"resource_id"`
}

// severity weights for risk calculation
var severityWeights = map[string]float64{
	"critical": 10.0,
	"high":     7.0,
	"medium":   4.0,
	"low":      1.0,
	"info":     0.0,
}

// AssessRisk produces a comprehensive risk assessment from enriched findings.
func AssessRisk(findings []executor.EnrichedFinding) *RiskAssessment {
	ra := &RiskAssessment{
		CategoryScores: make(map[string]float64),
	}

	ra.TotalFindings = len(findings)

	// Count statuses
	for _, f := range findings {
		switch f.Status {
		case "PASS":
			ra.PassCount++
		case "FAIL":
			ra.FailCount++
		case "ERROR":
			ra.ErrorCount++
		}
	}

	// Calculate overall compliance score (% passing)
	checkable := ra.PassCount + ra.FailCount
	if checkable > 0 {
		ra.OverallScore = math.Round(float64(ra.PassCount) / float64(checkable) * 100)
	}

	// Calculate weighted risk score accounting for severity
	var totalWeight, failWeight float64
	for _, f := range findings {
		sev := strings.ToLower(f.Severity)
		w := severityWeights[sev]
		if w == 0 && sev != "info" {
			w = 4.0 // default to medium
		}
		totalWeight += w
		if f.Status == "FAIL" {
			failWeight += w
		}
	}

	if totalWeight > 0 {
		weightedScore := math.Round((1 - failWeight/totalWeight) * 100)
		// Blend simple pass rate with weighted score
		ra.OverallScore = math.Round((ra.OverallScore + weightedScore) / 2)
	}

	ra.OverallRisk = scoreToRiskLevel(ra.OverallScore)

	// Category scores (by pack)
	packPass := make(map[string]int)
	packTotal := make(map[string]int)
	for _, f := range findings {
		if f.Status == "PASS" || f.Status == "FAIL" {
			packTotal[f.Pack]++
			if f.Status == "PASS" {
				packPass[f.Pack]++
			}
		}
	}
	for pack, total := range packTotal {
		if total > 0 {
			ra.CategoryScores[pack] = math.Round(float64(packPass[pack]) / float64(total) * 100)
		}
	}

	// Build top risks (sorted by severity weight)
	var risks []RiskItem
	for _, f := range findings {
		if f.Status == "FAIL" {
			sev := strings.ToLower(f.Severity)
			risks = append(risks, RiskItem{
				Severity:   f.Severity,
				Pack:       f.Pack,
				CheckID:    f.CheckID,
				ResourceID: f.ResourceID,
				Message:    f.Message,
				RiskScore:  severityWeights[sev],
			})
		}
	}
	sort.Slice(risks, func(i, j int) bool {
		return risks[i].RiskScore > risks[j].RiskScore
	})
	for i := range risks {
		risks[i].Rank = i + 1
	}
	if len(risks) > 20 {
		risks = risks[:20]
	}
	ra.TopRisks = risks

	// Build remediation plan
	ra.RemediationPlan = buildRemediationPlan(findings)

	return ra
}

func scoreToRiskLevel(score float64) RiskLevel {
	switch {
	case score >= 90:
		return RiskLow
	case score >= 70:
		return RiskMedium
	case score >= 50:
		return RiskHigh
	default:
		return RiskCritical
	}
}

func buildRemediationPlan(findings []executor.EnrichedFinding) []RemediationItem {
	var items []RemediationItem

	for _, f := range findings {
		if f.Status != "FAIL" {
			continue
		}

		action := generateRemediationAction(f)
		impact := generateImpactStatement(f)

		var frameworks []string
		for _, fw := range f.Frameworks {
			frameworks = append(frameworks, fw)
		}

		items = append(items, RemediationItem{
			Action:       action,
			Impact:       impact,
			AffectedBy:   frameworks,
			Severity:     f.Severity,
			ResourceID:   f.ResourceID,
		})
	}

	// Sort by severity
	sort.Slice(items, func(i, j int) bool {
		wi := severityWeights[strings.ToLower(items[i].Severity)]
		wj := severityWeights[strings.ToLower(items[j].Severity)]
		return wi > wj
	})

	for i := range items {
		items[i].Priority = i + 1
	}

	if len(items) > 30 {
		items = items[:30]
	}

	return items
}

func generateRemediationAction(f executor.EnrichedFinding) string {
	checkActions := map[string]string{
		// AWS
		"s3-encryption":          "Enable default encryption (AES-256 or aws:kms) on S3 bucket",
		"s3-public-access":       "Enable S3 Block Public Access on all four settings",
		"s3-versioning":          "Enable versioning on the S3 bucket for data recovery",
		"s3-logging":             "Enable server access logging on the S3 bucket",
		"iam-password-policy":    "Update IAM account password policy to meet minimum requirements",
		"iam-mfa-enabled":        "Enable MFA for the IAM user's console access",
		"iam-root-mfa":           "Enable MFA on the AWS root account immediately",
		"iam-unused-credentials": "Disable or delete the unused IAM credentials",
		"iam-access-key-rotation":"Rotate the IAM access key (create new key, update applications, delete old key)",
		"cloudtrail-enabled":     "Enable CloudTrail with multi-region logging",
		"cloudtrail-log-validation":"Enable log file validation on the CloudTrail trail",
		"sg-unrestricted-ssh":    "Restrict SSH (port 22) security group rule to specific CIDR ranges",
		"sg-unrestricted-rdp":    "Restrict RDP (port 3389) security group rule to specific CIDR ranges",
		"ebs-encryption":         "Enable encryption on the EBS volume (requires creating encrypted copy)",
		"rds-encryption":         "Enable encryption at rest on the RDS instance (requires recreation)",
		"rds-public-access":      "Disable public accessibility on the RDS instance",
		"rds-backup-enabled":     "Enable automated backups with appropriate retention period",
		// Linux
		"password-policy":        "Update /etc/login.defs and PAM configuration for stronger password policy",
		"ssh-config":             "Harden /etc/ssh/sshd_config and restart sshd",
		"file-permissions":       "Fix file permissions on the system configuration file",
		"firewall-status":        "Enable and configure firewall with default-deny policy",
		"audit-logging":          "Install and enable auditd with appropriate rules",
		"unnecessary-services":   "Disable or remove the unnecessary service",
		"kernel-hardening":       "Apply sysctl hardening parameters and persist in /etc/sysctl.d/",
		"filesystem-encryption":  "Implement disk encryption with LUKS or equivalent",
		"user-accounts":          "Remediate the user account security issue",
		"cron-permissions":       "Fix cron file permissions and ownership",
		// GitHub
		"branch-protection":      "Enable branch protection rules on the default branch",
		"secret-scanning":        "Enable secret scanning in repository security settings",
		"dependabot-alerts":      "Review and resolve Dependabot vulnerability alerts",
		"org-2fa":                "Enforce two-factor authentication for the GitHub organization",
		"repo-visibility":        "Review and update repository visibility settings",
		"actions-security":       "Restrict GitHub Actions permissions to read-only and limit allowed actions",
		// Docker
		"docker-daemon-config":   "Update Docker daemon configuration with security best practices",
		"container-privileges":   "Remove --privileged flag and run containers as non-root user",
		"image-vulnerabilities":  "Update container images to patched versions",
		"container-networking":   "Review and restrict container port mappings and network mode",
		"docker-logging":         "Configure logging driver for all containers",
		"docker-resource-limits": "Set CPU and memory limits on the container",
		// Network
		"tls-config":             "Upgrade TLS configuration to TLS 1.2+ with strong cipher suites",
		"open-ports":             "Close or restrict unexpected open ports",
		"dns-security":           "Enable DNSSEC and restrict zone transfers",
		"http-headers":           "Add missing HTTP security headers to the web server configuration",
		"certificate-expiry":     "Renew the TLS certificate before expiration",
	}

	if action, ok := checkActions[f.CheckID]; ok {
		return fmt.Sprintf("%s [%s]", action, f.ResourceID)
	}
	return fmt.Sprintf("Remediate failing check %s on %s: %s", f.CheckID, f.ResourceID, f.Message)
}

func generateImpactStatement(f executor.EnrichedFinding) string {
	sev := strings.ToLower(f.Severity)
	switch sev {
	case "critical":
		return "Immediate risk of data breach or unauthorized access. Must be addressed within 24 hours."
	case "high":
		return "Significant security gap that could lead to compromise. Address within 7 days."
	case "medium":
		return "Moderate risk that should be addressed in the next sprint cycle. Address within 30 days."
	case "low":
		return "Minor issue for continuous improvement. Address within 90 days."
	default:
		return "Review and address per organizational policy."
	}
}
