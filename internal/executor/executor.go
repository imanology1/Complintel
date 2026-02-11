package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/imanology1/comply-intel/internal/config"
	"github.com/imanology1/comply-intel/internal/discovery"
)

// Job represents a single check execution to be dispatched.
type Job struct {
	Pack      *discovery.Pack
	Check     *discovery.Check
	Params    map[string]string
	Creds     map[string]string
	Timeout   time.Duration
}

// Result is the output of a single job execution.
type Result struct {
	Job      Job
	Findings []EnrichedFinding
	Error    error
	Duration time.Duration
}

// Run resolves all configured checks against discovered packs and dispatches
// them concurrently, returning enriched findings.
func Run(cfg *config.Config, packs map[string]*discovery.Pack) ([]EnrichedFinding, []error) {
	jobs, errs := buildJobs(cfg, packs)
	if len(jobs) == 0 && len(errs) > 0 {
		return nil, errs
	}

	results := dispatch(jobs, cfg.Concurrency)

	var allFindings []EnrichedFinding
	for _, r := range results {
		if r.Error != nil {
			errs = append(errs, fmt.Errorf("[%s/%s] %w", r.Job.Pack.Name, r.Job.Check.ID, r.Error))
			continue
		}
		allFindings = append(allFindings, r.Findings...)
	}

	return allFindings, errs
}

func buildJobs(cfg *config.Config, packs map[string]*discovery.Pack) ([]Job, []error) {
	var jobs []Job
	var errs []error
	timeout := cfg.ParsedTimeout()

	for _, cc := range cfg.Checks {
		pack, ok := packs[cc.Pack]
		if !ok {
			errs = append(errs, fmt.Errorf("pack %q not found (referenced by check config)", cc.Pack))
			continue
		}
		chk, err := discovery.FindCheck(pack, cc.Check)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// Merge default params with user-supplied params
		params := make(map[string]string)
		for _, p := range chk.Params {
			if p.Default != "" {
				params[p.Name] = p.Default
			}
		}
		for k, v := range cc.Params {
			params[k] = v
		}

		// Validate required params
		for _, p := range chk.Params {
			if p.Required {
				if _, ok := params[p.Name]; !ok {
					errs = append(errs, fmt.Errorf("[%s/%s] missing required parameter %q", pack.Name, chk.ID, p.Name))
					continue
				}
			}
		}

		jobs = append(jobs, Job{
			Pack:    pack,
			Check:   chk,
			Params:  params,
			Creds:   cfg.Credentials,
			Timeout: timeout,
		})
	}

	return jobs, errs
}

func dispatch(jobs []Job, concurrency int) []Result {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []Result
	)

	sem := make(chan struct{}, concurrency)

	for _, job := range jobs {
		wg.Add(1)
		go func(j Job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := executeJob(j)

			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(job)
	}

	wg.Wait()
	return results
}

func executeJob(j Job) Result {
	start := time.Now()

	scriptPath := filepath.Join(j.Pack.Dir, "scripts", j.Check.Script)

	// Build command-line arguments from params
	var args []string
	for k, v := range j.Params {
		args = append(args, fmt.Sprintf("--%s=%s", k, v))
	}

	ctx, cancel := context.WithTimeout(context.Background(), j.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, scriptPath, args...)

	// Set environment: inherit current env + inject credentials
	cmd.Env = os.Environ()
	for k, v := range j.Creds {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return Result{
				Job:      j,
				Error:    fmt.Errorf("timed out after %s", j.Timeout),
				Duration: time.Since(start),
			}
		}
		return Result{
			Job:      j,
			Error:    fmt.Errorf("script failed: %s (stderr: %s)", err, stderr.String()),
			Duration: time.Since(start),
		}
	}

	if stderr.Len() > 0 {
		return Result{
			Job:      j,
			Error:    fmt.Errorf("script produced stderr output: %s", stderr.String()),
			Duration: time.Since(start),
		}
	}

	var findings []Finding
	if err := json.Unmarshal(stdout.Bytes(), &findings); err != nil {
		return Result{
			Job:      j,
			Error:    fmt.Errorf("script output is not valid JSON array: %w (raw: %s)", err, stdout.String()),
			Duration: time.Since(start),
		}
	}

	enriched := make([]EnrichedFinding, len(findings))
	now := time.Now().UTC()
	for i, f := range findings {
		enriched[i] = EnrichedFinding{
			Timestamp:    now,
			Pack:         j.Pack.Name,
			CheckID:      j.Check.ID,
			Severity:     j.Check.Severity,
			Frameworks:   j.Check.Frameworks,
			ResourceID:   f.ResourceID,
			ResourceType: f.ResourceType,
			Status:       f.Status,
			Message:      f.Message,
			Details:      f.Details,
		}
	}

	return Result{
		Job:      j,
		Findings: enriched,
		Duration: time.Since(start),
	}
}
