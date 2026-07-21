package asn

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/text/cases"
)

type Database interface {
	Lookup(address string) (Record, error)
	Close() error
}

type Record struct {
	ASN          uint32
	Organization string
}

type MaxMindDatabase struct{ reader *maxminddb.Reader }

type maxMindRecord struct {
	ASN          uint32 `maxminddb:"autonomous_system_number"`
	Organization string `maxminddb:"autonomous_system_organization"`
}

func OpenDatabase(path string) (*MaxMindDatabase, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ASN database: %w", err)
	}
	return &MaxMindDatabase{reader: reader}, nil
}

func (db *MaxMindDatabase) Lookup(address string) (Record, error) {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return Record{}, fmt.Errorf("invalid IPv4 address %q", address)
	}
	var value maxMindRecord
	if err := db.reader.Lookup(ip.To4(), &value); err != nil {
		return Record{}, fmt.Errorf("lookup ASN for %s: %w", address, err)
	}
	return Record{ASN: value.ASN, Organization: value.Organization}, nil
}

func (db *MaxMindDatabase) Close() error { return db.reader.Close() }

type SubstringRule struct {
	Text   string
	folded string
}

type RegexRule struct {
	Text  string
	Regex *regexp.Regexp
}

type Rules struct {
	ASN        map[uint32]string
	Substrings []SubstringRule
	Regexes    []RegexRule
}

func (r Rules) Counts() (int, int) { return len(r.ASN), len(r.Substrings) + len(r.Regexes) }

var folder = cases.Fold()

func fold(value string) string { return folder.String(value) }

func ParseFile(path string) (Rules, error) {
	file, err := os.Open(path)
	if err != nil {
		return Rules{}, fmt.Errorf("open ASN list %q: %w", path, err)
	}
	defer file.Close()

	rules := Rules{ASN: make(map[uint32]string)}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		asnText := strings.TrimPrefix(upper, "AS")
		if (strings.HasPrefix(upper, "AS") && digits(asnText)) || digits(line) {
			if strings.HasPrefix(upper, "AS") {
				asnText = line[2:]
			}
			value, parseErr := strconv.ParseUint(asnText, 10, 32)
			if parseErr != nil {
				return Rules{}, fmt.Errorf("invalid ASN on line %d: %w", lineNumber, parseErr)
			}
			rules.ASN[uint32(value)] = line
			continue
		}
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
			if line == "/" {
				return Rules{}, fmt.Errorf("empty organization regex on line %d", lineNumber)
			}
			pattern := line[1 : len(line)-1]
			if pattern == "" {
				return Rules{}, fmt.Errorf("empty organization regex on line %d", lineNumber)
			}
			compiled, compileErr := regexp.Compile("(?i)" + pattern)
			if compileErr != nil {
				return Rules{}, fmt.Errorf("invalid organization regex %q on line %d: %w", line, lineNumber, compileErr)
			}
			rules.Regexes = append(rules.Regexes, RegexRule{Text: line, Regex: compiled})
			continue
		}
		rules.Substrings = append(rules.Substrings, SubstringRule{Text: line, folded: fold(line)})
	}
	if err := scanner.Err(); err != nil {
		return Rules{}, fmt.Errorf("read ASN list %q: %w", path, err)
	}
	return rules, nil
}

func digits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type Match struct {
	Address      string
	ASN          uint32
	Organization string
	Rule         string
}

type Matcher struct {
	database Database
	path     string
	mu       sync.RWMutex
	rules    Rules
}

func NewMatcher(path string, database Database) (*Matcher, int, int, error) {
	rules, err := ParseFile(path)
	if err != nil {
		return nil, 0, 0, err
	}
	a, o := rules.Counts()
	return &Matcher{database: database, path: path, rules: rules}, a, o, nil
}

func (m *Matcher) Reload() (int, int, error) {
	rules, err := ParseFile(m.path)
	if err != nil {
		return 0, 0, err
	}
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
	a, o := rules.Counts()
	return a, o, nil
}

func (m *Matcher) Match(address string) (Match, bool, error) {
	record, err := m.database.Lookup(address)
	if err != nil {
		return Match{}, false, err
	}
	m.mu.RLock()
	rules := m.rules
	if text, ok := rules.ASN[record.ASN]; ok {
		m.mu.RUnlock()
		return Match{Address: address, ASN: record.ASN, Organization: record.Organization, Rule: text}, true, nil
	}
	folded := fold(record.Organization)
	for _, rule := range rules.Substrings {
		if strings.Contains(folded, rule.folded) {
			m.mu.RUnlock()
			return Match{Address: address, ASN: record.ASN, Organization: record.Organization, Rule: rule.Text}, true, nil
		}
	}
	for _, rule := range rules.Regexes {
		if rule.Regex.MatchString(record.Organization) {
			m.mu.RUnlock()
			return Match{Address: address, ASN: record.ASN, Organization: record.Organization, Rule: rule.Text}, true, nil
		}
	}
	m.mu.RUnlock()
	return Match{}, false, nil
}

func (m *Matcher) Close() error { return m.database.Close() }
