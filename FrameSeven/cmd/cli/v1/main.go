// Package main implements the frameseven CLI v1 entry point. It parses flags,
// runs an optional interactive wizard, and orchestrates a scan via scanner.Scan.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
	scopepolicy "github.com/sayseven7/frameseven/internal/scopepolicy/v1"
	"github.com/sayseven7/frameseven/internal/tools/v1/auth"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

const defaultOutputDir = "reports"

var buildVersion = "development"

type scanFunc func(*config.Config) report.Report

type options struct {
	target               string
	timeout              time.Duration
	toolTimeout          time.Duration
	concurrency          int
	rate                 int
	userAgent            string
	outputDir            string
	interactive          bool
	yes                  bool
	quiet                bool
	verbose              bool
	version              bool
	listTools            bool
	authBrowser          bool
	authSessionOut       string
	authWaitAfterCapture bool
	activeScan           bool
	mergeFindings        string
	tools                []string
}

func main() {
	terminal := isTerminal(os.Stdin)
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, terminal, scanner.Scan)

	os.Exit(code)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, terminal bool, scan scanFunc) int {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}

	if err != nil {
		return 2
	}

	if opts.version {
		fmt.Fprintf(stdout, "frameseven %s (CLI v1)\n", buildVersion)
		return 0
	}

	if opts.listTools {
		writeTools(stdout)
		return 0
	}
	if opts.mergeFindings != "" {
		if err := mergeReport(opts.outputDir, opts.mergeFindings); err != nil {
			fmt.Fprintf(stderr, "error: merging report: %v\n", err)
			return 1
		}
		return 0
	}

	useWizard := opts.interactive || (opts.target == "" && terminal)
	if useWizard {
		if !terminal {
			fmt.Fprintln(stderr, "error: interactive mode requires a terminal")
			return 2
		}

		var confirmed bool
		opts, confirmed = runWizard(stdin, stdout, opts)
		if !confirmed {
			fmt.Fprintln(stderr, "scan cancelled")
			return 0
		}
	}

	if strings.TrimSpace(opts.userAgent) == "" {
		opts.userAgent = config.RandomUserAgent()
	}

	cfg := config.New(opts.target)
	cfg.Timeout = opts.timeout
	cfg.ToolTimeout = opts.toolTimeout
	cfg.ToolConcurrency = opts.concurrency
	cfg.RateRequests = opts.rate
	cfg.UserAgent = opts.userAgent
	cfg.NVDAPIKey = os.Getenv("NVD_API_KEY")
	cfg.SelectedTools = opts.tools
	cfg.ActiveScan = opts.activeScan

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	scopePolicy, err := scopepolicy.LoadFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "error: sealed scope policy: %v\n", err)
		return 2
	}
	if err := scopepolicy.AllowTarget(scopePolicy, cfg.Target); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	if opts.authBrowser {
		session, err := auth.Capture(cfg.Target)
		if err != nil {
			fmt.Fprintf(stderr, "error: browser auth failed: %v\n", err)
			return 1
		}

		cfg.AuthCookies = session.Cookies
		cfg.AuthHeaders = session.Headers
		cfg.SeedEndpoints = session.Endpoints

		if opts.authSessionOut != "" {
			if err := writeAuthSession(opts.authSessionOut, cfg.Target, session); err != nil {
				fmt.Fprintf(stderr, "error: writing browser auth session: %v\n", err)
				return 1
			}
			fmt.Fprintln(stdout, "FRAMESEVEN_AUTH_READY_V1")
		}

		if opts.authWaitAfterCapture {
			fmt.Fprintln(stdout, "Authentication captured. Press Enter to start the FrameSeven scan...")
			waitForConfirmation(stdin)
		}
	}

	logFile, err := openLogFile(opts.outputDir)
	if err != nil {
		fmt.Fprintf(stderr, "error creating scan log: %v\n", err)
		return 1
	}
	defer logFile.Close()

	logOutput := io.Writer(logFile)
	if !opts.quiet {
		logOutput = io.MultiWriter(stderr, logFile)
	}

	cfg.Logger = log.New(logOutput, "", log.Ltime)
	cfg.Verbose = opts.verbose
	if !opts.quiet {
		writeBanner(stderr)
	}

	cfg.Logger.Printf("INFO  %s", bannerTitle)
	cfg.Logger.Printf("INFO  scan started for %s", cfg.Target)
	cfg.Logger.Printf("INFO  output directory: %s", opts.outputDir)
	cfg.Logger.Printf("INFO  selected tools: %s", strings.Join(cfg.SelectedTools, ", "))
	cfg.Logger.Printf("INFO  tool timeout: %s", cfg.ToolTimeout)
	cfg.Logger.Printf("INFO  tool concurrency: %d", cfg.ToolConcurrency)
	cfg.Logger.Printf("INFO  active (destructive) scan: %t", cfg.ActiveScan)

	rep := scan(&cfg)

	report.WriteText(stdout, rep)

	files, err := report.WriteFiles(opts.outputDir, rep)
	if err != nil {
		cfg.Logger.Printf("ERROR could not write reports: %v", err)
		return 1
	}

	cfg.Logger.Printf("INFO  HTML report: %s", files.HTML)
	cfg.Logger.Printf("INFO  Markdown report: %s", files.Markdown)
	cfg.Logger.Printf("INFO  PDF report: %s", files.PDF)
	cfg.Logger.Printf("INFO  JSON report: %s", files.JSON)
	cfg.Logger.Printf("INFO  scan log: %s", filepath.Join(opts.outputDir, "scan.log"))

	if len(rep.Errors) > 0 {
		cfg.Logger.Printf("WARN  scan finished with %d recorded tool error(s)", len(rep.Errors))
		return 1
	}

	return 0
}

func waitForConfirmation(input io.Reader) {
	_, _ = bufio.NewReader(input).ReadString('\n')
}

func mergeReport(outputDir, findingsPath string) error {
	data, err := os.ReadFile(filepath.Join(outputDir, "report.json"))
	if err != nil {
		return err
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return err
	}
	extra, err := os.ReadFile(findingsPath)
	if err != nil {
		return err
	}
	var rows []struct {
		Title       string `json:"title"`
		Module      string `json:"module"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Endpoint    string `json:"endpoint"`
		Evidence    string `json:"evidence"`
	}
	if err := json.Unmarshal(extra, &rows); err != nil {
		return err
	}
	for _, row := range rows {
		rep.Findings = append(rep.Findings, finding.Finding{Title: row.Title, Module: row.Module, Severity: finding.Severity(strings.ToUpper(row.Severity)), Description: row.Description, Evidence: finding.Evidence{Request: row.Endpoint, Extracted: row.Evidence}})
	}
	_, err = report.WriteFiles(outputDir, rep)
	return err
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	opts := options{}
	flags := flag.NewFlagSet("frameseven", flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.StringVar(&opts.target, "url", "", "target URL to scan")
	flags.DurationVar(&opts.timeout, "timeout", config.DefaultTimeout, "per-request timeout")
	flags.DurationVar(&opts.toolTimeout, "tool-timeout", config.DefaultToolTimeout, "maximum runtime for each scanner tool")
	flags.IntVar(&opts.concurrency, "concurrency", config.DefaultToolConcurrency, "scanner tools to run in parallel after recon")
	flags.IntVar(&opts.rate, "rate", config.DefaultRateRequests, "requests for the rate-limit test")
	flags.StringVar(&opts.userAgent, "ua", "", "User-Agent header (default: random realistic browser agent)")
	flags.StringVar(&opts.outputDir, "out", defaultOutputDir, "directory for reports and scan logs")
	flags.StringVar(&opts.outputDir, "o", defaultOutputDir, "directory for reports and scan logs")
	flags.BoolVar(&opts.interactive, "interactive", false, "configure the scan interactively")
	flags.BoolVar(&opts.interactive, "i", false, "configure the scan interactively")
	flags.BoolVar(&opts.yes, "yes", false, "accept the interactive scan confirmation")
	flags.BoolVar(&opts.yes, "y", false, "accept the interactive scan confirmation")
	flags.BoolVar(&opts.quiet, "quiet", false, "hide progress messages")
	flags.BoolVar(&opts.quiet, "q", false, "hide progress messages")
	flags.BoolVar(&opts.verbose, "verbose", false, "show HTTP request and response debug logs")
	flags.BoolVar(&opts.verbose, "v", false, "show HTTP request and response debug logs")
	flags.BoolVar(&opts.version, "version", false, "show the installed version")
	flags.BoolVar(&opts.listTools, "list-tools", false, "list scanner tools")
	flags.BoolVar(&opts.authBrowser, "auth-browser", false, "open a browser to log in before the scan")
	flags.StringVar(&opts.authSessionOut, "auth-session-out", "", "write captured browser session to a protected JSON file")
	flags.BoolVar(&opts.authWaitAfterCapture, "auth-wait-after-capture", false, "wait for confirmation after exporting browser authentication")
	flags.BoolVar(&opts.activeScan, "active-scan", false, "enable destructive, state-changing probes (PUT/DELETE methods, IDOR identifier mutation)")
	flags.StringVar(&opts.mergeFindings, "merge-findings", "", "merge normalized findings JSON into an existing report directory")

	var toolList string
	flags.StringVar(&toolList, "tools", "", "comma-separated scanner tools to run, default, or all")

	flags.Usage = func() {
		writeBanner(stderr)
		fmt.Fprintln(stderr, "Usage: frameseven -url https://target.example [flags]")
		fmt.Fprintln(stderr, "       frameseven --interactive")
		fmt.Fprintln(stderr)
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return options{}, err
	}

	if flags.NArg() > 0 {
		err := fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
		fmt.Fprintf(stderr, "error: %v\n", err)

		return options{}, err
	}

	toolNames, err := parseToolList(toolList)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)

		return options{}, err
	}

	opts.tools = toolNames

	return opts, nil
}

func writeAuthSession(filePath, target string, session auth.SessionResult) error {
	payload := struct {
		Version   string            `json:"version"`
		Target    string            `json:"target"`
		Cookies   []string          `json:"cookies,omitempty"`
		Headers   map[string]string `json:"headers,omitempty"`
		Endpoints []string          `json:"endpoints,omitempty"`
	}{"v1", target, session.Cookies, session.Headers, session.Endpoints}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return err
	}
	temporary := filePath + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, filePath)
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

func openLogFile(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "scan.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // #nosec G304 - the operator selects the output directory
	if err != nil {
		return nil, err
	}

	return file, nil
}
