package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/imanology1/comply-intel/internal/aggregator"
	"github.com/imanology1/comply-intel/internal/config"
	"github.com/imanology1/comply-intel/internal/discovery"
	"github.com/imanology1/comply-intel/internal/executor"
	"github.com/imanology1/comply-intel/internal/results"
	"github.com/imanology1/comply-intel/internal/scheduler"
)

var version = "2.0.0"

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	report := flag.Bool("report", false, "generate full security team report (risk + compliance)")
	reportJSON := flag.Bool("report-json", false, "generate full security team report as JSON")
	reportFramework := flag.String("framework", "", "generate report for a specific framework (SOC2, NIST-800-53, PCI-DSS, CIS)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("comply-intel %s\n", version)
		os.Exit(0)
	}

	opts := runOpts{
		Report:          *report,
		ReportJSON:      *reportJSON,
		ReportFramework: *reportFramework,
	}

	if err := run(*configPath, opts); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type runOpts struct {
	Report          bool
	ReportJSON      bool
	ReportFramework string
}

func run(configPath string, opts runOpts) error {
	// 1. Load configuration
	fmt.Printf("Loading configuration from %s...\n", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// 2. Discover agent packs
	fmt.Printf("Discovering agent packs in %s...\n", cfg.PacksDir)
	packs, warnings, err := discovery.LoadPacks(cfg.PacksDir)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  %s\n", w)
	}
	fmt.Printf("Loaded %d agent pack(s)\n", len(packs))
	for name := range packs {
		fmt.Printf("  - %s\n", name)
	}

	// 3. Parse schedule
	sched, err := scheduler.Parse(cfg.Schedule)
	if err != nil {
		return fmt.Errorf("schedule error: %w", err)
	}

	// 4. Set up signal handling for graceful shutdown
	stop := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived shutdown signal, stopping...")
		close(stop)
	}()

	// 5. Run scans on schedule
	scanFn := func() error {
		return runScan(cfg, packs, opts)
	}

	return sched.Run(scanFn, stop)
}

func runScan(cfg *config.Config, packs map[string]*discovery.Pack, opts runOpts) error {
	fmt.Println("\n=== Starting compliance scan ===")

	findings, errs := executor.Run(cfg, packs)

	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  CHECK ERROR: %v\n", e)
	}

	// Always write raw findings
	if err := results.Write(&cfg.Output, findings); err != nil {
		return fmt.Errorf("failed to write results: %w", err)
	}
	results.Summary(findings)

	// Generate security team report if requested
	if opts.Report || opts.ReportJSON || opts.ReportFramework != "" {
		fmt.Println()

		if opts.ReportFramework != "" {
			// Single framework report
			r := aggregator.GenerateComplianceReport(opts.ReportFramework, findings)
			if opts.ReportJSON {
				aggregator.PrintTeamReportJSON(os.Stdout, &aggregator.SecurityTeamReport{
					ComplianceReports: []*aggregator.ComplianceReport{r},
					RiskAssessment:    aggregator.AssessRisk(findings),
				})
			} else {
				report := &aggregator.SecurityTeamReport{
					RiskAssessment:    aggregator.AssessRisk(findings),
					ComplianceReports: []*aggregator.ComplianceReport{r},
				}
				aggregator.PrintTeamReport(os.Stdout, report)
			}
		} else {
			// Full team report
			teamReport := aggregator.GenerateTeamReport(findings)
			if opts.ReportJSON {
				aggregator.PrintTeamReportJSON(os.Stdout, teamReport)
			} else {
				aggregator.PrintTeamReport(os.Stdout, teamReport)
			}
		}
	}

	return nil
}
