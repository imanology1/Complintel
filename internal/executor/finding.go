package executor

import "time"

// Finding represents a single compliance check result from an agent script.
type Finding struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Status       string `json:"status"` // "PASS", "FAIL", "ERROR"
	Message      string `json:"message"`
	Details      string `json:"details,omitempty"`
}

// EnrichedFinding adds engine-level metadata to a raw finding.
type EnrichedFinding struct {
	Timestamp    time.Time `json:"timestamp"`
	Pack         string    `json:"pack"`
	CheckID      string    `json:"check_id"`
	Severity     string    `json:"severity"`
	Frameworks   []string  `json:"frameworks,omitempty"`
	ResourceID   string    `json:"resource_id"`
	ResourceType string    `json:"resource_type"`
	Status       string    `json:"status"`
	Message      string    `json:"message"`
	Details      string    `json:"details,omitempty"`
}
