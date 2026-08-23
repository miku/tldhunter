// Command tldhunter checks whether a keyword is available across a set of TLDs.
//
// It is a pure-stdlib port of tldhunt.sh. Rather than shelling out to whois(1)
// and curl(1) it speaks the WHOIS protocol (RFC 3912) over TCP/43 itself,
// resolving each TLD's registry server through whois.iana.org.
//
// A growing number of registries publish no whois server at all -- .dev and the
// rest of Google's are the standard example -- and answer only over RDAP. Those
// TLDs fall back to RDAP (RFC 7480/9082), with endpoints taken from IANA's
// bootstrap registry (RFC 9224).
//
// tlds.txt is embedded at build time and used by default, so the binary is
// self-contained.
//
//	go run tldhunter.go -k linuxsec              # built-in TLD list
//	go run tldhunter.go -k delta.sh              # one domain, TLD detected
//	go run tldhunter.go -k linuxsec -e .com
//	go run tldhunter.go -k linuxsec -E tlds.txt  # override the built-in list
//	go run tldhunter.go --update-tld             # refresh tlds.txt, then rebuild
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const banner = `▄▖▖ ▄ ▖▖▖▖▖ ▖▄▖▄▖▄▖
▐ ▌ ▌▌▙▌▌▌▛▖▌▐ ▙▖▙▘
▐ ▙▖▙▘▌▌▙▌▌▝▌▐ ▙▖▌▌
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
	tldURL     = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	tldFile    = "tlds.txt"
	ianaServer = "whois.iana.org"
	whoisPort  = "43"
	// rdapBootstrapURL is IANA's RFC 9224 registry mapping TLDs to RDAP base
	// URLs. It is the machine-readable form of the "RDAP Server" line on each
	// root-zone database page, and covers roughly 1200 of the ~1440 TLDs --
	// nearly all gTLDs. The gaps are mostly ccTLDs, which have whois.
	rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"
	userAgent        = "tldhunter (+https://github.com/miku/tldhunter)"
	// rdapMaxBody caps how much of an RDAP response is decoded. Records run to
	// a few KB; anything far larger is a misbehaving server, not a domain.
	rdapMaxBody = 1 << 20
	// The bootstrap registry is one document covering every TLD, so it gets a
	// far looser cap: it is ~70KB today and only grows.
	bootstrapMaxBody = 16 << 20
	// maxRetryAfter bounds how long a Retry-After header can park a lookup.
	maxRetryAfter = 30 * time.Second
	defaultJobs   = 30
	// Registries throttle per source address, so the global cap matters far
	// less than how many of those lookups land on any one server at once.
	defaultPerHost = 2
	defaultRetries = 2
	defaultTTL     = 24 * time.Hour
	// Available results are the actionable ones and the ones that go stale
	// dangerously, so they expire far sooner than taken results.
	defaultTTLAvail = time.Hour
	cacheDirName    = "tldhunter"
)

// Availability is decided by looking for an explicit "no such domain" reply
// first, and only then for evidence of a registration. tldhunt.sh did the
// reverse -- it grepped for nameservers and called anything else available --
// which fails in the worst direction: a response it does not understand reads
// as a free domain. DENIC is the case in point. A plain query for a
// registered .de returns just "Domain: x.de / Status: connect", with no
// nameservers and no "active", so the old rule reported it available.
//
// Patterns are matched per line, after stripping the comment markers that
// registries use for their boilerplate. Field patterns are built by keyLine,
// which is where the tolerance for how a registry separates key from value
// lives.
var (
	availableRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^no match`),
		regexp.MustCompile(`(?i)^not found`),
		regexp.MustCompile(`(?i)^no data found`),
		regexp.MustCompile(`(?i)^no entries found`),
		regexp.MustCompile(`(?i)^no object found`),
		regexp.MustCompile(`(?i)^nothing found`),
		regexp.MustCompile(`(?i)^domain (name )?not found`),
		regexp.MustCompile(`(?i)^(the queried )?object does not exist`),
		keyLine(`(?:domain |registration )?(?:status|state)`, `\s*(?:free|available|no object found)`),
		regexp.MustCompile(`(?i)^no information (available about domain name|was found matching)`),
		regexp.MustCompile(`(?i)^available$`),
		regexp.MustCompile(`(?i)\b(is )?(available|free) for registration\b`),
		// "<domain> is free" as a whole line -- anchored at both ends so the
		// phrase cannot match inside a terms-of-use paragraph.
		regexp.MustCompile(`(?i)^\S+ is (free|available)$`),
		// NIC Argentina answers in Spanish.
		regexp.MustCompile(`(?i)^el dominio no se encuentra registrado`),
	}
	// A whois host may answer for a TLD it does not serve with a refusal
	// rather than a verdict: Identity Digital's shared server says so for the
	// many TLDs it moved to RDAP, and brand registries increasingly reply that
	// the service is retired. None of these is an availability answer.
	notServedRes = []*regexp.Regexp{
		regexp.MustCompile(`(?im)^[%#\s]*tld is not supported`),
		regexp.MustCompile(`(?im)^[%#\s]*this tld is not`),
		regexp.MustCompile(`(?im)^[%#\s]*no whois server is known`),
		regexp.MustCompile(`(?i)whois service has been retired`),
		regexp.MustCompile(`(?i)but this server does not have`),
	}
	registeredRes = []*regexp.Regexp{
		keyLine(`name ?servers?|nserver`, ``),
		keyLine(`(?:domain )?(?:status|state)`, `\s*(?:connect|active|ok|registered|client|server)`),
		keyLine(`creation date|created|registered(?: date)?|registration (?:date|time)|domain record activated`, ``),
		keyLine(`registrar|sponsoring registrar|registry domain id|registrant`, ``),
		keyLine(`expiry date|expiration date|registry expiry date|paid-till`, ``),
	}
	commentRe    = regexp.MustCompile(`^[%#>\s]+`)
	expiryLineRe = regexp.MustCompile(`(?i)expiry date|expiration date|expiration time`)
	dateRe       = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	// Anchored to the end of the line: some TLDs (.dev among them) publish an
	// empty "whois:" field, and \s* would otherwise run on into the next line.
	ianaWhoisRe = regexp.MustCompile(`(?im)^whois:[ \t]*(\S+)[ \t]*$`)
)

// keyLine builds a matcher for one whois field, anchored to the start of a
// line and followed by tail (usually empty; a value pattern for status fields).
//
// The separator is the permissive part, because registries write it three ways:
//
//	Name Server: ns1.example.com          the common form
//	nserver............: ns1.example.com  padded or dotted leaders (.fi, .kr)
//	[Name Server]        ns1.example.com  bracketed, no colon at all (JPRS)
//
// tldhunt.sh caught all three by accident -- it grepped anywhere in the line,
// which is also why an unrecognised response read as an available domain.
// Anchoring is what makes the avail-first rule in parseResult safe, so the
// separator absorbs the variation instead of the anchor.
func keyLine(keys, tail string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)^\[?(?:` + keys + `)(?:\][ \t]|[ \t.]*:)` + tail)
}

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
	fmt.Fprintf(os.Stderr, "Usage: %s -k <keyword|domain> [-e <tld> | -E <tld-file>] [-x] [--update-tld]\n", prog)
	fmt.Fprintf(os.Stderr, "Without -e or -E, the built-in TLD list (%d entries) is used,\n", len(embeddedList()))
	fmt.Fprintf(os.Stderr, "unless the keyword already ends in a known TLD, which checks just that domain.\n")
	if dir, err := xdgCacheDir(); err == nil {
		fmt.Fprintf(os.Stderr, "Results are cached in %s for %s (%s if available; -ttl 0 to disable).\n", dir, defaultTTL, defaultTTLAvail)
	}
	fmt.Fprintf(os.Stderr, "Example: %s -k linuxsec\n", prog)
	fmt.Fprintf(os.Stderr, "       : %s -k delta.sh\n", prog)
	fmt.Fprintf(os.Stderr, "       : %s -k linuxsec -E tlds.txt\n", prog)
	fmt.Fprintf(os.Stderr, "       : %s --update-tld\n", prog)
	fmt.Fprintf(os.Stderr, "       : %s --clear-cache\n", prog)
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
		clear     bool
		ttl       time.Duration
		ttlAvail  time.Duration
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
	flag.DurationVar(&ttl, "ttl", defaultTTL, "cache lifetime for results; 0 disables the cache")
	flag.DurationVar(&ttlAvail, "ttl-avail", defaultTTLAvail, "cache lifetime for available results; 0 to never cache them")
	flag.BoolVar(&clear, "clear-cache", false, "delete the cache directory and exit")
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

	if clear {
		if updateTLD || keyword != "" || tld != "" || tldList != "" || nreg {
			fmt.Fprintln(os.Stderr, "--clear-cache cannot be used with other flags.")
			usage()
		}
		if err := clearCache(); err != nil {
			fatalf("%v", err)
		}
		return
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
	cfg.cache = openCache(ttl, ttlAvail)

	keyword = strings.ToLower(strings.TrimSpace(keyword))
	// A leading, trailing, or doubled dot yields an invalid domain for every
	// TLD, so reject it rather than firing a whole scan of nonsense queries.
	if strings.HasPrefix(keyword, ".") || strings.HasSuffix(keyword, ".") || strings.Contains(keyword, "..") {
		fmt.Fprintf(os.Stderr, "Invalid keyword %q: empty label.\n", keyword)
		usage()
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
		// Neither -e nor -E. A keyword that already ends in a known TLD is a
		// request to check that one domain, not to append every TLD to it.
		if name, ext, ok := splitDomain(keyword); ok {
			fmt.Fprintf(os.Stderr, "%s ends in a known TLD; checking that domain only (-E %s to scan all).\n", keyword, tldFile)
			keyword, tlds = name, []string{ext}
		} else {
			tlds = embeddedList()
		}
	}
	if len(tlds) == 0 {
		fatalf("no TLDs to check.")
	}

	hunt(keyword, tlds, cfg)
}

// knownTLDs indexes the embedded list for suffix lookups. Built once, lazily,
// since only the no -e/-E path needs it.
var knownTLDs = sync.OnceValue(func() map[string]bool {
	set := make(map[string]bool)
	for _, ext := range embeddedList() {
		set[ext] = true
	}
	return set
})

// splitDomain reports whether keyword is already a complete domain name, and
// if so splits it into the part before the TLD and the TLD itself. Only the
// final label is tested, so "example.co.uk" splits on ".uk" and is checked as
// one domain. A keyword whose last label is not a real TLD ("blog.mysite") is
// left alone, and still gets scanned against every TLD.
func splitDomain(keyword string) (name, ext string, ok bool) {
	dot := strings.LastIndex(keyword, ".")
	if dot <= 0 || dot == len(keyword)-1 {
		return "", "", false
	}
	if ext = keyword[dot:]; !knownTLDs()[ext] {
		return "", "", false
	}
	return keyword[:dot], ext, true
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
	cache   *cache // nil when caching is disabled
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

// The on-disk cache lives under the XDG base directory, one small JSON file
// per entry, sharded two hex digits deep to keep directories small. Entries
// are written atomically (temp file + rename) so concurrent runs cannot see a
// half-written record.
//
// Three kinds are stored: "domains" holds a decided result for a full domain,
// "servers" holds a TLD's registry endpoint, and "rdap" holds the flattened
// bootstrap registry. Only definitive answers are cached — never a network
// failure, so a transient outage is not remembered as fact. A missing or
// unreadable cache is never fatal; it just means a lookup.
const (
	// Version 2 added RDAP. Bumping it discards v1 entries, which is the point:
	// a v1 "no whois server" record was written before RDAP was ever consulted,
	// so replaying it would keep .dev and friends erroring for a whole TTL.
	cacheVersion = 2
	cacheDomains = "domains"
	cacheServers = "servers"
	cacheRDAP    = "rdap"
	// The bootstrap registry is a single document, so it needs only one key.
	rdapBootstrapKey = "dns"
)

type cache struct {
	dir string
	// ttl covers taken domains and server mappings, both of which are stable.
	ttl time.Duration
	// ttlAvail covers available domains, which go stale in the direction that
	// costs something: a name registered an hour after we cached it keeps
	// reading "avail" for the rest of its lifetime. Kept short by default.
	ttlAvail time.Duration
	// Hits are counted per kind, only to report a summary at the end of a run.
	// The two are tracked separately because they answer different questions:
	// verdicts saved a registry query, servers saved an IANA lookup.
	hits map[string]*atomic.Int64
}

func (c *cache) hit(kind string) {
	if c == nil {
		return
	}
	if n, ok := c.hits[kind]; ok {
		n.Add(1)
	}
}

func (c *cache) hitCount(kind string) int64 {
	if c == nil {
		return 0
	}
	if n, ok := c.hits[kind]; ok {
		return n.Load()
	}
	return 0
}

// ttlFor returns the lifetime that applies to a cached verdict.
func (c *cache) ttlFor(status string) time.Duration {
	if c == nil {
		return 0
	}
	switch status {
	case statusAvail:
		return c.ttlAvail
	case statusTaken:
		return c.ttl
	default:
		return 0 // never cache uncertainty
	}
}

type cacheEntry struct {
	Version int             `json:"v"`
	Key     string          `json:"key"`
	At      time.Time       `json:"at"`
	Data    json.RawMessage `json:"data"`
}

// cachedServer records where a TLD's verdicts come from. An empty Server is a
// positive finding: neither whois nor RDAP serves this TLD.
type cachedServer struct {
	Server string `json:"server"`
	RDAP   bool   `json:"rdap,omitempty"`
}

// cachedBootstrap is the RDAP bootstrap registry flattened to TLD -> base URL.
// Storing the derived map rather than the document keeps re-reads cheap.
type cachedBootstrap struct {
	Servers map[string]string `json:"servers"`
}

// xdgCacheDir returns $XDG_CACHE_HOME/tldhunter, defaulting the base to
// ~/.cache per the XDG Base Directory spec. This deliberately does not use
// os.UserCacheDir, which resolves to ~/Library/Caches on macOS.
func xdgCacheDir() (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, cacheDirName), nil
}

// openCache returns nil when caching is disabled or unavailable; every cache
// method tolerates a nil receiver, so callers need no special case. A ttl of
// zero disables the cache outright; ttlAvail may be zero on its own to cache
// only the taken verdicts.
func openCache(ttl, ttlAvail time.Duration) *cache {
	if ttl <= 0 {
		return nil
	}
	if ttlAvail < 0 {
		ttlAvail = 0
	}
	dir, err := xdgCacheDir()
	if err != nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	return &cache{
		dir:      dir,
		ttl:      ttl,
		ttlAvail: ttlAvail,
		hits: map[string]*atomic.Int64{
			cacheDomains: new(atomic.Int64),
			cacheServers: new(atomic.Int64),
			cacheRDAP:    new(atomic.Int64),
		},
	}
}

func (c *cache) path(kind, key string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + key))
	name := hex.EncodeToString(sum[:])
	return filepath.Join(c.dir, kind, name[:2], name+".json")
}

// get decodes a stored entry into out and reports its age. Freshness is left
// to the caller: which TTL applies depends on what was decoded, so the entry
// has to be read before it can be judged.
func (c *cache) get(kind, key string, out any) (age time.Duration, ok bool) {
	if c == nil {
		return 0, false
	}
	raw, err := os.ReadFile(c.path(kind, key))
	if err != nil {
		return 0, false
	}
	var e cacheEntry
	// Key is re-checked so a hash collision cannot serve the wrong answer.
	if json.Unmarshal(raw, &e) != nil || e.Version != cacheVersion || e.Key != key {
		return 0, false
	}
	if json.Unmarshal(e.Data, out) != nil {
		return 0, false
	}
	return time.Since(e.At), true
}

// getFresh reads an entry and accepts it only if it is within ttl, counting a
// hit when it is used.
func (c *cache) getFresh(kind, key string, out any, ttl time.Duration) bool {
	age, ok := c.get(kind, key, out)
	if !ok || ttl <= 0 || age > ttl {
		return false
	}
	c.hit(kind)
	return true
}

func (c *cache) put(kind, key string, in any) {
	if c == nil {
		return
	}
	data, err := json.Marshal(in)
	if err != nil {
		return
	}
	raw, err := json.Marshal(cacheEntry{
		Version: cacheVersion,
		Key:     key,
		At:      time.Now(),
		Data:    data,
	})
	if err != nil {
		return
	}

	path := c.path(kind, key)
	dir := filepath.Dir(path)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return
	}
	if os.Rename(tmp, path) != nil {
		os.Remove(tmp)
	}
}

func clearCache() error {
	dir, err := xdgCacheDir()
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Printf("No cache at %s.\n", dir)
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing %s: %w", dir, err)
	}
	fmt.Printf("Removed cache at %s.\n", dir)
	return nil
}

// hunt runs in two phases. Phase one resolves every TLD to its registry
// endpoint; phase two groups the domains by that endpoint and queries each
// group with a per-server concurrency cap.
//
// The grouping is the point: hundreds of gTLDs share a single whois host (all
// of Identity Digital's sit behind one IP), so a purely global worker pool
// aims most of its concurrency at one machine and gets rate-limited. Grouping
// first also avoids the head-of-line blocking a per-host semaphore would cause
// on a single shared queue, where workers parked on a busy host would starve
// the idle ones.
//
// Phase two can discover that a whois server is the wrong place to ask, and
// hand those domains to RDAP. That regrouping matters for the same reason: the
// concentration is even higher on the RDAP side, where a single Identity
// Digital endpoint serves 451 of the TLDs in the list. So the handed-off
// domains go through a second round rather than being queried in place, which
// would aim every whois group at that one endpoint at once.
func hunt(keyword string, tlds []string, cfg config) {
	servers := &serverCache{entries: make(map[string]*serverEntry), disk: cfg.cache}
	p := &printer{}

	byServer := resolveServers(keyword, tlds, servers, cfg, p)
	if n := len(byServer); n > 1 {
		p.err("Querying %d registries (max %d concurrent per server)...", n, cfg.perHost)
	}
	// One extra round settles everything: only whois hands off, and it hands
	// off only to RDAP, so the second round's own retries are always empty.
	if retry := queryAll(byServer, servers, cfg, p); len(retry) > 0 {
		p.err("Falling back to RDAP for %d domains across %d endpoints...", countDomains(retry), len(retry))
		queryAll(retry, servers, cfg, p)
	}

	if d, s := cfg.cache.hitCount(cacheDomains), cfg.cache.hitCount(cacheServers); d+s > 0 {
		p.err("From cache: %d verdicts (TTL %s, %s for available), %d server lookups.",
			d, cfg.cache.ttl, cfg.cache.ttlAvail, s)
	}
}

// resolveServers serves any domain whose result is already cached, and maps
// the rest to their registry whois server. Checking the domain cache here,
// before the server lookup, means a fully cached run touches the network zero
// times. whois.iana.org is a single well-provisioned host, so this phase uses
// the full global concurrency rather than the per-host cap.
func resolveServers(keyword string, tlds []string, servers *serverCache, cfg config, p *printer) map[endpoint][]string {
	if len(tlds) > 1 {
		p.err("Resolving whois servers for %d TLDs...", len(tlds))
	}

	byServer := make(map[endpoint][]string)
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
				// The entry has to be decoded before its TTL is known, since
				// avail and taken verdicts expire on different clocks.
				var cached result
				if age, ok := cfg.cache.get(cacheDomains, domain, &cached); ok && age <= cfg.cache.ttlFor(cached.Status) {
					cfg.cache.hit(cacheDomains)
					if line := cached.format(domain, cfg.nreg); line != "" {
						p.out("%s", line)
					}
					continue
				}
				ep, err := servers.get(domain[dot+1:], cfg)
				if err != nil {
					// The shell version treats a failed lookup as
					// "available", which is a false positive; report it
					// separately instead.
					p.err("[%serror%s] %s - %v", orange, reset, domain, err)
					continue
				}
				mu.Lock()
				byServer[ep] = append(byServer[ep], domain)
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
// queryAll returns the domains whose endpoint turned out to be the wrong one,
// regrouped under the RDAP endpoint that should have them.
func queryAll(byServer map[endpoint][]string, servers *serverCache, cfg config, p *printer) map[endpoint][]string {
	global := make(chan struct{}, cfg.jobs)
	var wg sync.WaitGroup

	retry := make(map[endpoint][]string)
	var rmu sync.Mutex

	for server, domains := range byServer {
		wg.Add(1)
		go func(ep endpoint, domains []string) {
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
					alt, again := checkDomain(domain, ep, servers, cfg, p)
					if !again {
						return
					}
					rmu.Lock()
					retry[alt] = append(retry[alt], domain)
					rmu.Unlock()
				}(domain)
			}
			group.Wait()
		}(server, domains)
	}
	wg.Wait()

	return retry
}

func countDomains(byServer map[endpoint][]string) int {
	n := 0
	for _, domains := range byServer {
		n += len(domains)
	}
	return n
}

// checkDomain queries one domain and prints the outcome — unless ep turns out
// not to be the server for this TLD, in which case it returns that TLD's RDAP
// endpoint for the caller to requeue rather than querying it here.
func checkDomain(domain string, ep endpoint, servers *serverCache, cfg config, p *printer) (endpoint, bool) {
	res, wrong, err := query(domain, ep, cfg)
	if wrong {
		tld := tldOf(domain)
		if base := servers.rdapBase(tld, cfg); base != "" {
			servers.learnRDAP(tld, base)
			return endpoint{addr: base, rdap: true}, true
		}
		if err == nil {
			err = fmt.Errorf("%s does not serve this TLD, which has no RDAP endpoint either", ep.addr)
		}
	}
	if err != nil {
		// Failures are never cached: a timeout today must not be replayed as
		// a verdict for the rest of the TTL.
		p.err("[%serror%s] %s - %v", orange, reset, domain, err)
		return endpoint{}, false
	}
	if res.Status == statusUnknown {
		// Report it instead of guessing. Reaching here means the registry
		// answered in a shape neither pattern set recognises, which is a gap
		// in the patterns worth seeing rather than a verdict.
		p.err("[%sunknown%s] %s - unrecognised response from %s", orange, reset, domain, ep.addr)
		return endpoint{}, false
	}
	// A zero TTL for this verdict means don't store it at all.
	if cfg.cache.ttlFor(res.Status) > 0 {
		cfg.cache.put(cacheDomains, domain, res)
	}
	if line := res.format(domain, cfg.nreg); line != "" {
		p.out("%s", line)
	}
	return endpoint{}, false
}

// query asks one endpoint about one domain. A true wrong return means the
// endpoint is not the one serving this TLD, so the caller should look for an
// RDAP endpoint instead. A TLD that IANA still lists a whois server for can
// nonetheless be RDAP-only, in two ways:
//
//   - The host answers on port 43 only to disown the TLD. Identity Digital's
//     shared server does this for everything it moved to RDAP.
//   - Port 43 is gone entirely -- connection refused, or a whois.nic.<tld>
//     that no longer resolves -- while the registry answers fine over RDAP.
//
// The second is told apart from throttling by retryable: a refusal or NXDOMAIN
// is the registry stating there is no whois service here, whereas a reset or
// timeout is congestion, already retried, and worth reporting as the failure it
// is rather than routing around.
func query(domain string, ep endpoint, cfg config) (res result, wrong bool, err error) {
	if ep.rdap {
		res, err = rdapQuery(ep.addr, domain, cfg)
		return res, false, err
	}
	body, err := whoisQuery(ep.addr, domain, cfg)
	if err != nil {
		return result{}, !retryable(err), err
	}
	if matchesAny(notServedRes, body) {
		return result{}, true, nil
	}
	return parseResult(body), false, nil
}

// tldOf returns a domain's final label. Callers reach it only with names that
// resolveServers already split on a dot, so no validation is needed.
func tldOf(domain string) string {
	return domain[strings.LastIndex(domain, ".")+1:]
}

const (
	statusAvail = "avail"
	statusTaken = "taken"
	// statusUnknown is a response that matched neither set of patterns. It is
	// reported rather than guessed at, and never cached.
	statusUnknown = "unknown"
)

// result is the decided verdict for a domain. The whois body itself is not
// cached, only what was concluded from it; cacheVersion guards the shape.
type result struct {
	Status string   `json:"status"` // statusAvail or statusTaken
	Expiry []string `json:"expiry,omitempty"`
}

// parseResult classifies a whois response. The "not found" reply is checked
// first because it is the unambiguous one; registries answer it in a handful
// of well-known phrasings, whereas a registered domain's record varies wildly.
func parseResult(body string) result {
	var registered bool
	for _, line := range strings.Split(body, "\n") {
		line = commentRe.ReplaceAllString(strings.TrimSpace(line), "")
		if line == "" {
			continue
		}
		if matchesAny(availableRes, line) {
			return result{Status: statusAvail}
		}
		if !registered && matchesAny(registeredRes, line) {
			registered = true
		}
	}
	if registered {
		return result{Status: statusTaken, Expiry: expiryDates(body)}
	}
	return result{Status: statusUnknown}
}

func matchesAny(res []*regexp.Regexp, line string) bool {
	for _, re := range res {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// format renders the verdict. An empty string means "print nothing" (a taken
// domain under -x).
func (r result) format(domain string, nreg bool) string {
	if r.Status == statusAvail {
		return fmt.Sprintf("[%savail%s] %s", bGreen, reset, domain)
	}
	if nreg {
		return ""
	}
	if len(r.Expiry) > 0 {
		return fmt.Sprintf("[%staken%s] %s - Exp Date: %s%s%s",
			bRed, reset, domain, orange, strings.Join(r.Expiry, " "), reset)
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

// endpoint is where a TLD's verdicts come from: a whois host queried on port
// 43, or an RDAP base URL queried over HTTPS. It is comparable, so it doubles
// as the grouping key that keeps concurrent queries off any one server.
type endpoint struct {
	addr string // whois hostname, or RDAP base URL
	rdap bool
}

// serverCache maps a TLD to its registry endpoint, asking whois.iana.org at
// most once per TLD even when many goroutines want the same answer.
type serverCache struct {
	mu      sync.Mutex
	entries map[string]*serverEntry
	disk    *cache

	// The RDAP bootstrap registry is fetched at most once per run, and only if
	// some TLD actually turns out to need it. A nil map means "no RDAP this
	// run", which is a normal outcome when the fetch fails.
	bootOnce sync.Once
	boot     map[string]string
}

type serverEntry struct {
	once sync.Once
	ep   endpoint
	err  error
}

func (c *serverCache) get(tld string, cfg config) (endpoint, error) {
	c.mu.Lock()
	e, ok := c.entries[tld]
	if !ok {
		e = &serverEntry{}
		c.entries[tld] = e
	}
	c.mu.Unlock()

	e.once.Do(func() {
		// Endpoint mappings change rarely, so they ride the long TTL.
		var cached cachedServer
		if c.disk.getFresh(cacheServers, tld, &cached, c.disk.ttlFor(statusTaken)) {
			e.ep = endpoint{addr: cached.Server, rdap: cached.RDAP}
			if e.ep.addr == "" {
				e.err = noServer(tld)
			}
			return
		}

		var body string
		if body, e.err = whoisQuery(ianaServer, tld, cfg); e.err != nil {
			// IANA itself was unreachable; that is not a fact about the TLD.
			return
		}
		switch m := ianaWhoisRe.FindStringSubmatch(body); {
		case m != nil:
			e.ep = endpoint{addr: m[1]}
		case resolves("whois.nic."+tld, cfg.timeout):
			// IANA lists no server. Many such TLDs still answer on the
			// conventional whois.nic.<tld> host, so try that if it resolves.
			e.ep = endpoint{addr: "whois.nic." + tld}
		default:
			// No whois at all. RDAP is the modern answer and, unlike the guess
			// above, it is published rather than inferred -- but it is tried
			// last so that a TLD with a working port 43 keeps using it.
			if base := c.rdapBase(tld, cfg); base != "" {
				e.ep = endpoint{addr: base, rdap: true}
			} else {
				e.err = noServer(tld)
			}
		}
		// Every outcome here is a definitive answer, so all are worth
		// remembering; an empty server records "this TLD has neither".
		c.disk.put(cacheServers, tld, cachedServer{Server: e.ep.addr, RDAP: e.ep.rdap})
	})
	return e.ep, e.err
}

// rdapBase returns the RDAP base URL for a TLD, or "" if it has none, loading
// the bootstrap registry on first use.
func (c *serverCache) rdapBase(tld string, cfg config) string {
	c.bootOnce.Do(func() { c.boot = loadBootstrap(c.disk, cfg) })
	return c.boot[tld]
}

// learnRDAP records that a TLD's published whois server does not actually
// serve it, so the next run goes straight to RDAP rather than rediscovering
// this one dead query at a time. Only the disk cache is updated: this run has
// already handed the affected domains to the RDAP round, and the in-memory
// entry is published to other goroutines that would race on a write.
//
// Worth doing even though the entry is a downgrade of a published record: the
// TTL bounds it to a day, and the failure mode if a registry restores port 43
// early is using RDAP for the rest of that day, which works.
func (c *serverCache) learnRDAP(tld, base string) {
	c.disk.put(cacheServers, tld, cachedServer{Server: base, RDAP: true})
}

func noServer(tld string) error {
	return fmt.Errorf("no whois or RDAP server published for .%s", tld)
}

func resolves(host string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
}

// httpClient is shared so the many TLDs behind one RDAP service reuse
// connections. Per-request deadlines come from the context rather than
// Client.Timeout, which would apply to the whole client.
var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
	},
}

// loadBootstrap returns the bootstrap registry flattened to TLD -> base URL. A
// failure is deliberately not fatal and not cached: it just means no RDAP
// fallback for this run, leaving the affected TLDs reported as unserved.
func loadBootstrap(disk *cache, cfg config) map[string]string {
	var cached cachedBootstrap
	if disk.getFresh(cacheRDAP, rdapBootstrapKey, &cached, disk.ttlFor(statusTaken)) {
		return cached.Servers
	}
	servers, err := fetchBootstrap(cfg.timeout)
	if err != nil {
		return nil
	}
	disk.put(cacheRDAP, rdapBootstrapKey, cachedBootstrap{Servers: servers})
	return servers
}

func fetchBootstrap(timeout time.Duration) (map[string]string, error) {
	body, err := httpGet(rdapBootstrapURL, "application/json", timeout)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	// Each service entry is a pair of arrays: the TLDs it covers, then the base
	// URLs serving them. Decoding into a fixed-size array tolerates a registry
	// that grows a third element without breaking the parse.
	var doc struct {
		Services [][2][]string `json:"services"`
	}
	if err := json.NewDecoder(io.LimitReader(body, bootstrapMaxBody)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", rdapBootstrapURL, err)
	}
	servers := make(map[string]string, 1500)
	for _, svc := range doc.Services {
		base := preferHTTPS(svc[1])
		if base == "" {
			continue
		}
		for _, tld := range svc[0] {
			servers[strings.ToLower(tld)] = base
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("%s listed no RDAP servers", rdapBootstrapURL)
	}
	return servers, nil
}

// preferHTTPS picks the https base URL when a service publishes both.
func preferHTTPS(urls []string) string {
	for _, u := range urls {
		if strings.HasPrefix(u, "https://") {
			return u
		}
	}
	if len(urls) > 0 {
		return urls[0]
	}
	return ""
}

// rdapDomain is the slice of an RDAP domain object that a verdict needs.
type rdapDomain struct {
	ObjectClassName string `json:"objectClassName"`
	LDHName         string `json:"ldhName"`
	// Present when the server returns an error document; RFC 7480 pairs it
	// with a matching HTTP status, but not every implementation does.
	ErrorCode int `json:"errorCode"`
	Events    []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

// expiry pulls the date out of the expiration event, trimmed to YYYY-MM-DD so
// RDAP and whois verdicts print and cache identically. RDAP timestamps are
// RFC 3339, so the date is always the leading component.
func (d rdapDomain) expiry() []string {
	var dates []string
	seen := make(map[string]bool)
	for _, ev := range d.Events {
		if !strings.EqualFold(ev.Action, "expiration") {
			continue
		}
		if s := dateRe.FindString(ev.Date); s != "" && !seen[s] {
			seen[s] = true
			dates = append(dates, s)
		}
	}
	return dates
}

// rdapStatusError is an HTTP status that is neither a verdict nor a transport
// failure, kept as a type so retryability and delay can be read off the reply.
type rdapStatusError struct {
	code int
	// after carries a Retry-After header, if the server sent one.
	after time.Duration
}

func (e rdapStatusError) Error() string {
	return fmt.Sprintf("RDAP server returned %d %s", e.code, http.StatusText(e.code))
}

// rdapQuery performs one RDAP domain lookup, retrying transient failures the
// way whoisQuery does. Unlike whois there is nothing to pattern-match: RFC 7480
// puts the answer in the status code, where 404 means the name is unregistered.
func rdapQuery(base, domain string, cfg config) (result, error) {
	url := strings.TrimSuffix(base, "/") + "/domain/" + domain
	var err error
	for attempt := 0; ; attempt++ {
		var res result
		if res, err = rdapQueryOnce(url, cfg.timeout); err == nil {
			return res, nil
		}
		if attempt >= cfg.retries || !retryableRDAP(err) {
			return result{}, err
		}
		time.Sleep(rdapBackoff(err, attempt))
	}
}

// retryableRDAP treats throttling and server faults as worth another attempt.
//
// 403 counts as throttling here, against its usual meaning. Identity Digital's
// endpoint -- which serves 451 of the TLDs in the list, so it takes by far the
// most load -- answers a rate-limited query with 403 rather than 429, and the
// same query succeeds once the burst passes. A genuine refusal costs only the
// remaining retries.
func retryableRDAP(err error) bool {
	var se rdapStatusError
	if errors.As(err, &se) {
		switch se.code {
		case http.StatusTooManyRequests, http.StatusForbidden:
			return true
		}
		return se.code >= 500
	}
	return retryable(err)
}

// rdapBackoff prefers the server's own Retry-After over a guess, capped so one
// unreasonable header cannot stall a scan.
func rdapBackoff(err error, attempt int) time.Duration {
	var se rdapStatusError
	if errors.As(err, &se) && se.after > 0 {
		return min(se.after, maxRetryAfter)
	}
	return backoff(attempt)
}

// retryAfter parses the header in both forms RFC 9110 allows: a delay in
// seconds, or an absolute date. An unparseable value yields 0, meaning "fall
// back to the usual backoff".
func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func rdapQueryOnce(url string, timeout time.Duration) (result, error) {
	body, err := httpGet(url, "application/rdap+json", timeout)
	if err != nil {
		var se rdapStatusError
		// A 404 is the whole point of the protocol here, not a failure.
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return result{Status: statusAvail}, nil
		}
		return result{}, err
	}
	defer body.Close()

	var d rdapDomain
	if err := json.NewDecoder(io.LimitReader(body, rdapMaxBody)).Decode(&d); err != nil {
		return result{}, fmt.Errorf("decoding RDAP response: %w", err)
	}
	// A 200 carrying an error document, or one carrying no domain at all, is
	// not an answer; let the caller report it rather than guess a verdict.
	if d.ErrorCode != 0 || (d.LDHName == "" && !strings.EqualFold(d.ObjectClassName, "domain")) {
		return result{Status: statusUnknown}, nil
	}
	return result{Status: statusTaken, Expiry: d.expiry()}, nil
}

// httpGet issues a GET with a per-request deadline and returns the body for a
// 2xx, or an rdapStatusError otherwise. The caller closes the body.
func httpGet(url, accept string, timeout time.Duration) (io.ReadCloser, error) {
	// The context outlives this call: cancelling it on return would kill the
	// body the caller is about to read, so closing the body is what releases it.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		// Drain before closing so the connection can be reused for the next
		// TLD on this host; error bodies are small.
		io.Copy(io.Discard, io.LimitReader(resp.Body, rdapMaxBody))
		resp.Body.Close()
		cancel()
		return nil, rdapStatusError{code: resp.StatusCode, after: retryAfter(resp.Header)}
	}
	return &cancelReader{ReadCloser: resp.Body, cancel: cancel}, nil
}

// cancelReader releases a request's context once its body is closed.
type cancelReader struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReader) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
