package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RunMode determines how the scheduler operates.
type RunMode int

const (
	RunOnce RunMode = iota
	RunCron
)

// Schedule represents a parsed schedule configuration.
type Schedule struct {
	Mode     RunMode
	Interval time.Duration // used for simple interval mode
	Cron     *CronExpr    // used for cron mode
}

// CronExpr holds parsed cron fields (minute, hour, day-of-month, month, day-of-week).
type CronExpr struct {
	Minute     []int
	Hour       []int
	DayOfMonth []int
	Month      []int
	DayOfWeek  []int
}

// Parse interprets a schedule string from config.
// Supported formats:
//   - "once" or "" — run a single scan and exit
//   - "every 5m", "every 1h" — simple interval
//   - "0 2 * * *" — cron expression (5 fields)
func Parse(s string) (*Schedule, error) {
	s = strings.TrimSpace(s)

	if s == "" || strings.EqualFold(s, "once") {
		return &Schedule{Mode: RunOnce}, nil
	}

	if strings.HasPrefix(s, "every ") {
		dur, err := time.ParseDuration(strings.TrimPrefix(s, "every "))
		if err != nil {
			return nil, fmt.Errorf("invalid interval %q: %w", s, err)
		}
		if dur < 10*time.Second {
			return nil, fmt.Errorf("interval %q is too short (minimum 10s)", s)
		}
		return &Schedule{Mode: RunCron, Interval: dur}, nil
	}

	// Try cron expression
	expr, err := parseCron(s)
	if err != nil {
		return nil, fmt.Errorf("invalid schedule %q: %w", s, err)
	}
	return &Schedule{Mode: RunCron, Cron: expr}, nil
}

// Run executes fn according to the schedule. For RunOnce it calls fn once and
// returns. For interval/cron modes it loops until stop is closed.
func (s *Schedule) Run(fn func() error, stop <-chan struct{}) error {
	// Always run immediately on first invocation
	if err := fn(); err != nil {
		return err
	}

	if s.Mode == RunOnce {
		return nil
	}

	if s.Interval > 0 {
		return s.runInterval(fn, stop)
	}
	return s.runCron(fn, stop)
}

func (s *Schedule) runInterval(fn func() error, stop <-chan struct{}) error {
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			if err := fn(); err != nil {
				fmt.Printf("scan error: %v\n", err)
			}
		}
	}
}

func (s *Schedule) runCron(fn func() error, stop <-chan struct{}) error {
	for {
		now := time.Now()
		next := s.Cron.Next(now)
		wait := next.Sub(now)

		select {
		case <-stop:
			return nil
		case <-time.After(wait):
			if err := fn(); err != nil {
				fmt.Printf("scan error: %v\n", err)
			}
		}
	}
}

func parseCron(s string) (*CronExpr, error) {
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return nil, fmt.Errorf("expected 5 fields, got %d", len(fields))
	}

	minute, err := parseCronField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("minute field: %w", err)
	}
	hour, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("hour field: %w", err)
	}
	dom, err := parseCronField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("day-of-month field: %w", err)
	}
	month, err := parseCronField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("month field: %w", err)
	}
	dow, err := parseCronField(fields[4], 0, 6)
	if err != nil {
		return nil, fmt.Errorf("day-of-week field: %w", err)
	}

	return &CronExpr{
		Minute:     minute,
		Hour:       hour,
		DayOfMonth: dom,
		Month:      month,
		DayOfWeek:  dow,
	}, nil
}

func parseCronField(field string, min, max int) ([]int, error) {
	if field == "*" {
		vals := make([]int, max-min+1)
		for i := range vals {
			vals[i] = min + i
		}
		return vals, nil
	}

	// Handle */step
	if strings.HasPrefix(field, "*/") {
		step, err := strconv.Atoi(strings.TrimPrefix(field, "*/"))
		if err != nil || step < 1 {
			return nil, fmt.Errorf("invalid step %q", field)
		}
		var vals []int
		for i := min; i <= max; i += step {
			vals = append(vals, i)
		}
		return vals, nil
	}

	// Handle comma-separated values
	parts := strings.Split(field, ",")
	var vals []int
	for _, p := range parts {
		// Handle ranges (e.g., 1-5)
		if strings.Contains(p, "-") {
			rangeParts := strings.SplitN(p, "-", 2)
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid range start %q", p)
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid range end %q", p)
			}
			if start < min || end > max || start > end {
				return nil, fmt.Errorf("range %q out of bounds [%d-%d]", p, min, max)
			}
			for i := start; i <= end; i++ {
				vals = append(vals, i)
			}
		} else {
			v, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", p)
			}
			if v < min || v > max {
				return nil, fmt.Errorf("value %d out of bounds [%d-%d]", v, min, max)
			}
			vals = append(vals, v)
		}
	}
	return vals, nil
}

// Next calculates the next time the cron expression matches after the given time.
func (c *CronExpr) Next(from time.Time) time.Time {
	t := from.Add(time.Minute).Truncate(time.Minute)

	for i := 0; i < 525600; i++ { // search up to 1 year
		if contains(c.Month, int(t.Month())) &&
			contains(c.DayOfMonth, t.Day()) &&
			contains(c.DayOfWeek, int(t.Weekday())) &&
			contains(c.Hour, t.Hour()) &&
			contains(c.Minute, t.Minute()) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return t
}

func contains(vals []int, v int) bool {
	for _, val := range vals {
		if val == v {
			return true
		}
	}
	return false
}
