// Command tldhunt checks whether a keyword is available across a set of TLDs.
//
// It is a pure-stdlib port of tldhunt.sh. Rather than shelling out to whois(1)
// and curl(1) it speaks the WHOIS protocol (RFC 3912) over TCP/43 itself,
// resolving each TLD's registry server through whois.iana.org.
//
// tlds.txt is embedded at build time and used by default, so the binary is
// self-contained.
//
//	go run tldhunt.go -k linuxsec              # built-in TLD list
//	go run tldhunt.go -k linuxsec -e .com
//	go run tldhunt.go -k linuxsec -E tlds.txt  # override the built-in list
//	go run tldhunt.go --update-tld             # refresh tlds.txt, then rebuild
package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const banner = ` _____ _    ___  _  _          _
|_   _| |  |   \| || |_  _ _ _| |_
  | | | |__| |) | __ | || | ' \  _|
  |_| |____|___/|_||_|\_,_|_||_\__|
        Domain Availability Checker
`

// embeddedTLDs is tlds.txt baked into the binary at build time, so the tool
// runs standalone with no data file alongside it. It is the default TLD list;
// -E overrides it and --update-tld refreshes the on-disk copy for the next
// build. Rebuild after --update-tld to pick up a newer list.
//
//go:embed tlds.txt
var embeddedTLDs string

const (
	tldURL      = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	tldFile     = "tlds.txt"
	ianaServer  = "whois.iana.org"
	whoisPort   = "43"
	defaultJobs = 30
	// Registries throttle per source address, so the global cap matters far
	// less than how many of those lookups land on any one server at once.
	defaultPerHost = 2
	defaultRetries = 2
)

// Mirrors the greps in tldhunt.sh: a response mentioning nameservers (or an
// active status) means the domain is registered.
var (
	registeredRe = regexp.MustCompile(`(?i)name server|nserver|nameservers|status: active`)
	expiryLineRe = regexp.MustCompile(`(?i)expiry date|expiration date|expiration time`)
	dateRe       = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	// Anchored to the end of the line: some TLDs (.dev among them) publish an
	// empty "whois:" field, and \s* would otherwise run on into the next line.
	ianaWhoisRe = regexp.MustCompile(`(?im)^whois:[ \t]*(\S+)[ \t]*$`)
)

// Color definitions.
var (
	reset  = "\033[0m"
	orange = "\033[0;33m"
	bRed   = "\033[1;31m"
	bGreen = "\033[1;32m"
)

func disableColor() { reset, orange, bRed, bGreen = "", "", "", "" }

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func usage() {
	prog := os.Args[0]
	fmt.Fprintf(os.Stderr, "Usage: %s -k <keyword> [-e <tld> | -E <tld-file>] [-x] [--update-tld]\n", prog)
	fmt.Fprintf(os.Stderr, "Without -e or -E, the built-in TLD list (%d entries) is used.\n", len(embeddedList()))
	fmt.Fprintf(os.Stderr, "Example: %s -k linuxsec\n", prog)
	fmt.Fprintf(os.Stderr, "       : %s -k linuxsec -E tlds.txt\n", prog)
	fmt.Fprintf(os.Stderr, "       : %s --update-tld\n", prog)
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	var (
		keyword   string
		tld       string
		tldList   string
		nreg      bool
		updateTLD bool
		cfg       config
	)

	// Go's flag package accepts one or two leading dashes for every name, so
	// registering each flag twice yields both the short and long spellings.
	flag.StringVar(&keyword, "k", "", "keyword to check")
	flag.StringVar(&keyword, "keyword", "", "keyword to check")
	flag.StringVar(&tld, "e", "", "single TLD to check")
	flag.StringVar(&tld, "tld", "", "single TLD to check")
	flag.StringVar(&tldList, "E", "", "file with one TLD per line")
	flag.StringVar(&tldList, "tld-file", "", "file with one TLD per line")
	flag.BoolVar(&nreg, "x", false, "only report domains that are not registered")
	flag.BoolVar(&nreg, "not-registered", false, "only report domains that are not registered")
	flag.BoolVar(&updateTLD, "update-tld", false, "refresh "+tldFile+" from IANA and exit")
	flag.IntVar(&cfg.jobs, "j", defaultJobs, "total concurrent whois lookups")
	flag.IntVar(&cfg.perHost, "perhost", defaultPerHost, "concurrent lookups per whois server")
	flag.IntVar(&cfg.retries, "retries", defaultRetries, "retries per lookup on a transient failure")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-whois-query timeout")
	flag.Usage = usage
	flag.Parse()

	if !colorEnabled() {
		disableColor()
	}
	fmt.Print(banner)

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Unknown parameter passed: %s\n", flag.Arg(0))
		usage()
	}

	if updateTLD {
		if keyword != "" || tld != "" || tldList != "" || nreg {
			fmt.Fprintln(os.Stderr, "--update-tld cannot be used with other flags.")
			usage()
		}
		if err := updateTLDFile(tldFile); err != nil {
			fatalf("%v", err)
		}
		return
	}

	switch {
	case keyword == "":
		fmt.Fprintln(os.Stderr, "Keyword is required.")
		usage()
	case tld != "" && tldList != "":
		fmt.Fprintln(os.Stderr, "You can only specify one of -e or -E options.")
		usage()
	}
	cfg.nreg = nreg
	if cfg.jobs < 1 {
		cfg.jobs = 1
	}
	if cfg.perHost < 1 {
		cfg.perHost = 1
	}
	if cfg.retries < 0 {
		cfg.retries = 0
	}

	var tlds []string
	switch {
	case tld != "":
		tlds = []string{normalizeTLD(tld)}
	case tldList != "":
		f, err := os.Open(tldList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TLD file %s not found.\n", tldList)
			usage()
		}
		tlds, err = parseTLDs(f)
		f.Close()
		if err != nil {
			fatalf("reading %s: %v", tldList, err)
		}
	default:
		// Neither -e nor -E: fall back to the embedded list.
		tlds = embeddedList()
	}
	if len(tlds) == 0 {
		fatalf("no TLDs to check.")
	}

	hunt(strings.ToLower(keyword), tlds, cfg)
}

// normalizeTLD lowercases a TLD and gives it the leading dot that the entries
// in tlds.txt carry, so "-e com" and "-e .com" behave identically.
func normalizeTLD(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return s
	}
	return "." + strings.TrimPrefix(s, ".")
}

// embeddedList parses the baked-in tlds.txt. Reading from a string cannot
// fail, so the scanner error is discarded.
func embeddedList() []string {
	tlds, _ := parseTLDs(strings.NewReader(embeddedTLDs))
	return tlds
}

// parseTLDs reads one TLD per line, skipping blanks and comments.
func parseTLDs(r io.Reader) ([]string, error) {
	var tlds []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tlds = append(tlds, normalizeTLD(line))
	}
	return tlds, sc.Err()
}

func updateTLDFile(path string) error {
	fmt.Printf("Fetching TLD data from %s...\n", tldURL)
	resp, err := http.Get(tldURL)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", tldURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: %s", tldURL, resp.Status)
	}

	// Buffer the whole list before touching the file, so a mid-transfer
	// failure cannot leave a truncated tlds.txt behind.
	var buf strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		buf.WriteString(normalizeTLD(line))
		buf.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", tldURL, err)
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	fmt.Printf("TLDs have been saved to %s.\n", path)
	return nil
}

type config struct {
	jobs    int
	perHost int
	retries int
	timeout time.Duration
	nreg    bool
}

// printer serializes output so concurrent workers cannot interleave lines.
type printer struct{ mu sync.Mutex }

func (p *printer) out(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Printf(format+"\n", args...)
}

func (p *printer) err(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// hunt runs in two phases. Phase one resolves every TLD to its registry whois
// server; phase two groups the domains by that server and queries each group
// with a per-server concurrency cap.
//
// The grouping is the point: hundreds of gTLDs share a single whois host (all
// of Identity Digital's sit behind one IP), so a purely global worker pool
// aims most of its concurrency at one machine and gets rate-limited. Grouping
// first also avoids the head-of-line blocking a per-host semaphore would cause
// on a single shared queue, where workers parked on a busy host would starve
// the idle ones.
func hunt(keyword string, tlds []string, cfg config) {
	servers := &serverCache{entries: make(map[string]*serverEntry)}
	p := &printer{}

	byServer := resolveServers(keyword, tlds, servers, cfg, p)
	queryAll(byServer, cfg, p)
}

// resolveServers maps each domain to its registry whois server, reporting the
// TLDs that have none. whois.iana.org is a single well-provisioned host, so
// this phase uses the full global concurrency rather than the per-host cap.
func resolveServers(keyword string, tlds []string, servers *serverCache, cfg config, p *printer) map[string][]string {
	if len(tlds) > 1 {
		p.err("Resolving whois servers for %d TLDs...", len(tlds))
	}

	byServer := make(map[string][]string)
	var mu sync.Mutex

	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < cfg.jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range work {
				dot := strings.LastIndex(domain, ".")
				if dot < 0 || dot == len(domain)-1 {
					p.err("[%serror%s] %s - no TLD", orange, reset, domain)
					continue
				}
				server, err := servers.get(domain[dot+1:], cfg)
				if err != nil {
					// The shell version treats a failed lookup as
					// "available", which is a false positive; report it
					// separately instead.
					p.err("[%serror%s] %s - %v", orange, reset, domain, err)
					continue
				}
				mu.Lock()
				byServer[server] = append(byServer[server], domain)
				mu.Unlock()
			}
		}()
	}
	for _, ext := range tlds {
		work <- keyword + ext
	}
	close(work)
	wg.Wait()

	return byServer
}

// queryAll fans out over the servers, each group limited to cfg.perHost
// concurrent queries, with cfg.jobs bounding the total in flight.
func queryAll(byServer map[string][]string, cfg config, p *printer) {
	if n := len(byServer); n > 1 {
		p.err("Querying %d registries (max %d concurrent per server)...", n, cfg.perHost)
	}

	global := make(chan struct{}, cfg.jobs)
	var wg sync.WaitGroup

	for server, domains := range byServer {
		wg.Add(1)
		go func(server string, domains []string) {
			defer wg.Done()
			// Both semaphores are always taken in this order and released
			// together, so the fixed ordering rules out deadlock.
			host := make(chan struct{}, cfg.perHost)
			var group sync.WaitGroup
			for _, domain := range domains {
				host <- struct{}{}
				global <- struct{}{}
				group.Add(1)
				go func(domain string) {
					defer group.Done()
					defer func() { <-global; <-host }()
					checkDomain(domain, server, cfg, p)
				}(domain)
			}
			group.Wait()
		}(server, domains)
	}
	wg.Wait()
}

func checkDomain(domain, server string, cfg config, p *printer) {
	body, err := whoisQuery(server, domain, cfg)
	if err != nil {
		p.err("[%serror%s] %s - %v", orange, reset, domain, err)
		return
	}
	p.out("%s", formatResult(domain, body, cfg.nreg))
}

// formatResult renders the verdict for a whois response. An empty string means
// "print nothing" (a taken domain under -x).
func formatResult(domain, body string, nreg bool) string {
	if !registeredRe.MatchString(body) {
		return fmt.Sprintf("[%savail%s] %s", bGreen, reset, domain)
	}
	if nreg {
		return ""
	}
	if dates := expiryDates(body); len(dates) > 0 {
		return fmt.Sprintf("[%staken%s] %s - Exp Date: %s%s%s",
			bRed, reset, domain, orange, strings.Join(dates, " "), reset)
	}
	return fmt.Sprintf("[%staken%s] %s - No expiry date found", bRed, reset, domain)
}

// expiryDates pulls YYYY-MM-DD dates off any expiry-looking line, preserving
// order and dropping duplicates (whois responses often repeat them).
func expiryDates(body string) []string {
	var dates []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		if !expiryLineRe.MatchString(line) {
			continue
		}
		for _, d := range dateRe.FindAllString(line, -1) {
			if !seen[d] {
				seen[d] = true
				dates = append(dates, d)
			}
		}
	}
	return dates
}

// whoisQuery performs one lookup, retrying transient failures. Registries that
// consider us too chatty answer with a refused connection or a mid-read reset
// rather than an error document, so a short backoff recovers most of them.
func whoisQuery(server, query string, cfg config) (string, error) {
	var err error
	for attempt := 0; ; attempt++ {
		var body string
		if body, err = whoisQueryOnce(server, query, cfg.timeout); err == nil {
			return body, nil
		}
		if attempt >= cfg.retries || !retryable(err) {
			return "", err
		}
		time.Sleep(backoff(attempt))
	}
}

// retryable reports whether err is worth a second attempt. NXDOMAIN and a
// refused connection are settled answers: many registries have retired port 43
// for RDAP, and their whois.nic.<tld> records still resolve to a host with the
// port closed. Resets and timeouts are the throttling signals worth retrying.
func retryable(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound
	}
	return !errors.Is(err, syscall.ECONNREFUSED)
}

// backoff grows exponentially from ~1s, with jitter so that the many TLDs
// sharing one registry do not retry in lockstep.
func backoff(attempt int) time.Duration {
	d := time.Second << attempt
	return d + time.Duration(rand.Int64N(int64(d/2)))
}

func whoisQueryOnce(server, query string, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(server, whoisPort))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(string(body), "\r\n", "\n"), nil
}

// serverCache maps a TLD to its registry whois server, asking whois.iana.org
// at most once per TLD even when many goroutines want the same answer.
type serverCache struct {
	mu      sync.Mutex
	entries map[string]*serverEntry
}

type serverEntry struct {
	once   sync.Once
	server string
	err    error
}

func (c *serverCache) get(tld string, cfg config) (string, error) {
	c.mu.Lock()
	e, ok := c.entries[tld]
	if !ok {
		e = &serverEntry{}
		c.entries[tld] = e
	}
	c.mu.Unlock()

	e.once.Do(func() {
		var body string
		if body, e.err = whoisQuery(ianaServer, tld, cfg); e.err != nil {
			return
		}
		if m := ianaWhoisRe.FindStringSubmatch(body); m != nil {
			e.server = m[1]
			return
		}
		// IANA lists no server. Most such TLDs still answer on the
		// conventional whois.nic.<tld> host, so try that if it resolves.
		if fallback := "whois.nic." + tld; resolves(fallback, cfg.timeout) {
			e.server = fallback
			return
		}
		e.err = fmt.Errorf("no whois server published for .%s", tld)
	})
	return e.server, e.err
}

func resolves(host string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
}
