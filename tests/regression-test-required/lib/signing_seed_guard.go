// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Command signing_seed_guard refuses a tree that carries the private seed of a
// licence-verification key the shipped binaries trust (#4470).
//
// WHY. From 2026-02-10 to 2026-09 the PRODUCTION evaluation and enterprise
// signing seeds sat in platform/agent test helpers as "test seeds", and the
// community-mirror sync published them. Anyone could mint a licence every
// deployment accepted. No scanner saw it: gitleaks keys its Ed25519 rule on a
// `*_SIGNING_KEY=` assignment and allowlists every `_test.go` path, and a
// base64 string labelled "test seed" reads as test-only in review.
//
// WHAT IT CHECKS, with zero false positives BY CONSTRUCTION: it never guesses
// whether a string "looks like" a key. It
//
//  1. parses the trusted public keys out of the verifier sources themselves
//     (the evaluationPublicKey / enterprisePublicKey byte literals at the sites
//     in trustedKeySites), so a rotation needs no edit here;
//  2. collects every literal in every file (any type: Go, shell, YAML,
//     Markdown, JSON, ...) that decodes to key material - base64 std or url,
//     padded or not; hex; Go/Python/JSON integer lists in braces or brackets;
//     `\xHH` escape runs - of 32 bytes (a seed), 64 bytes (a Go
//     ed25519.PrivateKey, seed||public), or 48 bytes carrying the PKCS#8
//     Ed25519 prefix (a PEM/DER private key body);
//  3. derives the Ed25519 public key of each candidate seed; and
//  4. fails, naming file:line and the encoding, if a derived key EQUALS a
//     trusted key. The literal is never printed.
//
// A candidate that is not a trusted key's seed cannot match (that would be an
// Ed25519 preimage), so nothing needs an allowlist and nothing ever will.
//
// Two more views are scanned: the raw bytes of a PKCS#8 Ed25519 DER key (a
// binary .der or a key embedded in any file), and, in a file holding `\/`, the
// text with `\/` read as `/` (JSON-escaped base64).
//
// KNOWN BLIND SPOTS, deliberately out of scope (each would need a sliding
// window over long runs or a per-format decoder, and none is how a seed has
// ever been committed here):
//   - a base64url seed glued to a prefix of url-alphabet characters
//     (`seed-<url>`: the hyphen cannot be told from the literal's own); a
//     std literal glued to `-` or `_` IS found;
//   - a std literal glued to a path (`a/b/<std>`), for the same reason;
//   - colon- or space-separated hex (`08:11:...`, openssl's dump);
//   - a seed split across lines, concatenated from pieces, or held in a
//     binary file as 32 raw bytes with no PKCS#8 prefix;
//   - any encoding not listed above (base32, base58, decimal strings, ...).
//
// USAGE
//
//	go run signing_seed_guard.go [-root DIR] [-keys-root DIR]... [-walk]
//
// -root is the tree to scan (default "."). -keys-root is where the verifier
// sources are read (default: -root); it may be repeated, and every root's keys
// are trusted. The community-mirror sync scans the staged public tree with the
// keys read from the enterprise checkout. The local pre-commit hook scans the
// staged files with a pinned copy's keys (-keys-root) and the work tree's
// (-keys-root-union), minus the pin's list of retired, known-public keys
// (-retired), and with -require-known, so a work tree trusting a key the pin
// has never heard of (a pin gone stale across a rotation) fails loudly. Within
// one keys root every site must declare the SAME pair; sites that disagree
// are an instrument failure (exit 2), because a verifier trusting a key the
// others do not is itself the defect. -keys-root-union DIR (repeatable) trusts
// every key its sites declare WITHOUT that agreement check: the pre-commit hook
// uses it for the work tree being committed, because a branch cut before a
// rotation can carry disagreeing sites (before #4470 the Lambda still trusted
// the pre-April enterprise key), and the hook's job is to refuse seeds, not to
// audit the verifiers - CI and the mirror paths do that with -keys-root.
//
// -retired FILE lists public keys (hex, one per line, `#` comments) that are
// NEVER trusted, whichever root declares them: keys a rotation retired, whose
// seeds are already public. A -keys-root that declares one is an instrument
// failure. -require-known makes every key a -keys-root-union root declares
// either a -keys-root key or a retired one; anything else exits 2 naming the
// site, because it means the strict roots (the hook's pin) are out of date.
// In a git
// work tree the scanned set is `git ls-files -co --exclude-standard` (tracked
// plus untracked-not-ignored, which is what a commit can add); -walk, or a
// root that is not a git work tree, walks every regular file except .git.
//
//	go run signing_seed_guard.go -control-keypair
//
// prints a FRESH random seed and its public key, hex, space-separated, for the
// planted-positive controls in signing_seed_guard_test.sh. It never prints a
// trusted key's seed: it has none.
//
// Exit status: 0 clean, 1 a trusted key's seed was found, 2 the instrument
// could not run (a site missing or unparsable, nothing scanned, git failed).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// trustedKeySites are the verifier sources whose keys a shipped binary trusts.
// On an enterprise tree (an ee/ directory exists at -keys-root) every site is
// REQUIRED. The community mirror carries no ee/ and the sync strips the
// enterprise-tagged platform/agent/license/validation.go, so there only the
// community build's tier.go is required; a site that is present is always
// parsed.
var trustedKeySites = []struct {
	path      string
	community bool // required on a tree with no ee/ directory
}{
	{"ee/platform/agent/license/validation.go", false},
	{"platform/agent/license/validation.go", false},
	{"platform/agent/license/tier.go", true},
	{"ee/platform/aws-marketplace/license-validator/validation.go", false},
}

var keyVarNames = []string{"evaluationPublicKey", "enterprisePublicKey"}

// pkcs8Ed25519Prefix is the DER prefix of a PKCS#8 Ed25519 private key; the 32
// bytes after it are the seed.
var pkcs8Ed25519Prefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}

type trustedKey struct {
	pub  ed25519.PublicKey
	name string // e.g. "enterprisePublicKey (platform/agent/license/tier.go)"
}

type finding struct {
	file     string
	line     int
	encoding string
	key      string
}

type scanner struct {
	trusted  []trustedKey
	derived  map[[32]byte]int // seed -> index into trusted, or -1
	findings []finding
	// reported holds file\x00line\x00key for every finding, so one literal
	// that several decoders or views accept (a base64 string with no '+/-_' is
	// valid in both alphabets, padded and raw) is reported once.
	reported map[string]bool
	files    int
	derives  int
}

func main() {
	root := flag.String("root", ".", "tree to scan")
	var keysRoots multiFlag
	flag.Var(&keysRoots, "keys-root", "tree whose verifier sources name the trusted keys; its sites must agree (repeatable; default: -root)")
	var unionRoots multiFlag
	flag.Var(&unionRoots, "keys-root-union", "like -keys-root, but trusts every site's keys without requiring the sites to agree (repeatable)")
	retiredFile := flag.String("retired", "", "file of retired public keys (hex, one per line) that are never trusted")
	requireKnown := flag.Bool("require-known", false, "every -keys-root-union key must be a -keys-root key or a retired one, else exit 2")
	walk := flag.Bool("walk", false, "walk every regular file instead of asking git for the file list")
	control := flag.Bool("control-keypair", false, "print a fresh random seed and its public key (hex) for the test's planted positives, and exit")
	flag.Parse()

	if *control {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			instrumentFail("generating a control key pair: %v", err)
		}
		fmt.Printf("%s %s\n", hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub))
		return
	}
	if len(keysRoots) == 0 && len(unionRoots) == 0 {
		keysRoots = multiFlag{*root}
	}

	retired := map[string]bool{}
	if *retiredFile != "" {
		var err error
		if retired, err = loadRetired(*retiredFile); err != nil {
			instrumentFail("%v", err)
		}
	}

	var trusted []trustedKey
	strict := map[string]bool{}
	for _, kr := range keysRoots {
		keys, err := loadTrustedKeys(kr, true)
		if err != nil {
			instrumentFail("%v", err)
		}
		for _, k := range keys {
			h := hex.EncodeToString(k.pub)
			if retired[h] {
				instrumentFail("%s trusts %s..., which %s lists as RETIRED; a keys root must not trust a retired key", k.name, h[:8], *retiredFile)
			}
			strict[h] = true
		}
		trusted = append(trusted, keys...)
	}
	for _, kr := range unionRoots {
		keys, err := loadTrustedKeys(kr, false)
		if err != nil {
			instrumentFail("%v", err)
		}
		for _, k := range keys {
			h := hex.EncodeToString(k.pub)
			switch {
			case retired[h]:
				continue // known public; its seed is no longer a secret worth refusing
			case *requireKnown && !strict[h]:
				instrumentFail("STALE PIN: %s under %s trusts %s..., which is neither a key of %s nor listed in %s. "+
					"The work tree is ahead of (or apart from) the pinned keys: refresh the pin "+
					"(technical-docs/runbooks/ED25519_KEY_ROTATION.md, \"Enabling the pre-commit check\") before committing",
					k.name, kr, h[:8], strings.Join(keysRoots, ","), *retiredFile)
			}
			trusted = append(trusted, k)
		}
	}
	if len(trusted) == 0 {
		instrumentFail("no key is trusted (every declared key is retired); the guard would check nothing")
	}
	files, mode, err := listFiles(*root, *walk)
	if err != nil {
		instrumentFail("%v", err)
	}
	if len(files) == 0 {
		instrumentFail("no files to scan under %s (%s): a guard that scans nothing has checked nothing", *root, mode)
	}

	s := &scanner{trusted: trusted, derived: map[[32]byte]int{}, reported: map[string]bool{}}
	for _, rel := range files {
		data, err := readRegular(filepath.Join(*root, rel))
		if err != nil {
			instrumentFail("reading %s: %v", rel, err)
		}
		if data == nil {
			continue
		}
		s.files++
		s.scan(filepath.ToSlash(rel), data)
	}

	fps := make([]string, 0, len(trusted))
	seen := map[string]bool{}
	for _, k := range trusted {
		fp := hex.EncodeToString(k.pub[:4])
		if !seen[fp] {
			seen[fp] = true
			fps = append(fps, fp)
		}
	}
	fmt.Printf("signing-seed guard: %d trusted key literal(s) (%d distinct, first bytes %s) from %s; %d file(s) scanned (%s); %d candidate seed(s) derived\n",
		len(trusted), len(fps), strings.Join(fps, ","), strings.Join(append(append([]string{}, keysRoots...), unionRoots...), ","), s.files, mode, s.derives)

	if len(s.findings) == 0 {
		fmt.Println("  PASS: no literal in the tree is the private seed of a trusted licence-verification key")
		return
	}
	sort.Slice(s.findings, func(i, j int) bool {
		a, b := s.findings[i], s.findings[j]
		if a.file != b.file {
			return a.file < b.file
		}
		return a.line < b.line
	})
	for _, f := range s.findings {
		fmt.Printf("  FAIL: %s:%d: a %s literal is the PRIVATE SEED of trusted key %s\n", f.file, f.line, f.encoding, f.key)
	}
	fmt.Printf("  %d occurrence(s). The literal is not printed. A trusted key's seed must never be committed:\n", len(s.findings))
	fmt.Println("  sign test licences with an ephemeral pair installed by license.OverridePublicKeysForTest (#4470),")
	fmt.Println("  and treat the key as EXPOSED - rotate it (technical-docs/runbooks/ED25519_KEY_ROTATION.md).")
	os.Exit(1)
}

// loadRetired reads a retired-keys file: one 64-hex public key per line;
// blank lines and `#` comments are ignored; anything else is an error.
func loadRetired(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("retired-keys file: %v", err)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if b, err := hex.DecodeString(line); err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s:%d is not a 64-hex Ed25519 public key", path, i+1)
		}
		out[line] = true
	}
	return out, nil
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func instrumentFail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "signing-seed guard: INSTRUMENT FAILURE: "+format+"\n", args...)
	os.Exit(2)
}

// loadTrustedKeys parses both key variables out of every trusted site.
func loadTrustedKeys(keysRoot string, requireAgreement bool) ([]trustedKey, error) {
	enterpriseTree := false
	if st, err := os.Stat(filepath.Join(keysRoot, "ee")); err == nil && st.IsDir() {
		enterpriseTree = true
	}
	var out []trustedKey
	first := map[string]trustedKey{} // variable -> the first site's key
	for _, site := range trustedKeySites {
		p := filepath.Join(keysRoot, site.path)
		if _, err := os.Stat(p); err != nil {
			if errors.Is(err, fs.ErrNotExist) && !enterpriseTree && !site.community {
				continue // not carried by the community mirror
			}
			return nil, fmt.Errorf("trusted-key site %s: %v", site.path, err)
		}
		keys, err := parseKeySite(p)
		if err != nil {
			return nil, fmt.Errorf("trusted-key site %s: %v", site.path, err)
		}
		for _, name := range keyVarNames {
			pub, ok := keys[name]
			if !ok {
				return nil, fmt.Errorf("trusted-key site %s declares no %s byte literal; the guard cannot know what it protects", site.path, name)
			}
			k := trustedKey{pub: pub, name: name + " (" + site.path + ")"}
			if f, seen := first[name]; !seen {
				first[name] = k
			} else if requireAgreement && !f.pub.Equal(pub) {
				return nil, fmt.Errorf("the verifier sites under %s disagree on %s: %s has %s..., %s has %s...; every site must trust the same pair",
					keysRoot, name, f.name, hex.EncodeToString(f.pub[:4]), k.name, hex.EncodeToString(pub[:4]))
			}
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no trusted keys parsed")
	}
	return out, nil
}

// parseKeySite returns the 32-byte composite literals assigned to the key
// variables in a Go source file.
func parseKeySite(path string) (map[string]ed25519.PublicKey, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, n := range keyVarNames {
		want[n] = true
	}
	out := map[string]ed25519.PublicKey{}
	var perr error
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, id := range vs.Names {
			if !want[id.Name] || i >= len(vs.Values) {
				continue
			}
			cl, ok := vs.Values[i].(*ast.CompositeLit)
			if !ok {
				perr = fmt.Errorf("%s is not a composite byte literal", id.Name)
				return false
			}
			var b []byte
			for _, e := range cl.Elts {
				bl, ok := e.(*ast.BasicLit)
				if !ok || bl.Kind != token.INT {
					perr = fmt.Errorf("%s has a non-integer element", id.Name)
					return false
				}
				v, err := strconv.ParseUint(bl.Value, 0, 8)
				if err != nil {
					perr = fmt.Errorf("%s element %q: %v", id.Name, bl.Value, err)
					return false
				}
				b = append(b, byte(v))
			}
			if len(b) != ed25519.PublicKeySize {
				perr = fmt.Errorf("%s has %d bytes, want %d", id.Name, len(b), ed25519.PublicKeySize)
				return false
			}
			if _, dup := out[id.Name]; dup {
				perr = fmt.Errorf("%s is declared twice", id.Name)
				return false
			}
			out[id.Name] = ed25519.PublicKey(b)
		}
		return true
	})
	return out, perr
}

func listFiles(root string, walk bool) ([]string, string, error) {
	if !walk {
		cmd := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree")
		if out, err := cmd.Output(); err == nil && strings.TrimSpace(string(out)) == "true" {
			top, err := exec.Command("git", "-C", root, "rev-parse", "--show-prefix").Output()
			if err != nil {
				return nil, "", fmt.Errorf("git rev-parse --show-prefix: %v", err)
			}
			if p := strings.TrimSpace(string(top)); p != "" {
				return nil, "", fmt.Errorf("-root %s is a subdirectory (%s) of a git work tree; pass the top level or -walk", root, p)
			}
			out, err := exec.Command("git", "-C", root, "ls-files", "-z", "-co", "--exclude-standard").Output()
			if err != nil {
				return nil, "", fmt.Errorf("git ls-files: %v", err)
			}
			var files []string
			for _, f := range bytes.Split(out, []byte{0}) {
				if len(f) > 0 {
					files = append(files, string(f))
				}
			}
			return files, "git ls-files -co --exclude-standard", nil
		}
	}
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	return files, "walk", err
}

// readRegular returns a regular file's bytes, or nil for anything else (a
// symlink, a submodule directory, a path deleted from the work tree).
func readRegular(p string) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil
	}
	return os.ReadFile(p)
}

// check derives the public key of every seed the decoded material can carry
// and records a finding for one that is trusted.
func (s *scanner) check(file string, data []byte, off int, encoding string, raw []byte) {
	var seed []byte
	switch {
	case len(raw) == 32:
		seed = raw
	case len(raw) == 64:
		seed = raw[:32]
		encoding += " (64-byte private key)"
	case len(raw) == 48 && bytes.HasPrefix(raw, pkcs8Ed25519Prefix):
		seed = raw[16:]
		encoding += " (PKCS#8 private key)"
	default:
		return
	}
	var k [32]byte
	copy(k[:], seed)
	idx, ok := s.derived[k]
	if !ok {
		s.derives++
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		idx = -1
		for i, t := range s.trusted {
			if pub.Equal(t.pub) {
				idx = i
				break
			}
		}
		s.derived[k] = idx
	}
	if idx >= 0 {
		line := 1 + bytes.Count(data[:off], []byte{'\n'})
		at := file + "\x00" + strconv.Itoa(line) + "\x00" + s.trusted[idx].name
		if s.reported[at] {
			return
		}
		s.reported[at] = true
		s.findings = append(s.findings, finding{
			file:     file,
			line:     line,
			encoding: encoding,
			key:      s.trusted[idx].name,
		})
	}
}

func (s *scanner) scan(file string, data []byte) {
	s.scanBase64(file, data)
	s.scanHex(file, data)
	s.scanEscapes(file, data)
	s.scanIntLists(file, data)
	s.scanRawPKCS8(file, data)
	// JSON escapes '/' as '\/', which splits a std base64 literal into runs
	// the base64 view never sees whole. Removing the backslash keeps every
	// newline, so line numbers in this view are the file's own.
	if bytes.Contains(data, []byte(`\/`)) {
		s.scanBase64(file, bytes.ReplaceAll(data, []byte(`\/`), []byte("/")))
	}
}

// scanRawPKCS8 finds the raw DER of a PKCS#8 Ed25519 private key: the 16-byte
// prefix followed by the 32-byte seed.
func (s *scanner) scanRawPKCS8(file string, data []byte) {
	for from := 0; ; {
		i := bytes.Index(data[from:], pkcs8Ed25519Prefix)
		if i < 0 {
			return
		}
		i += from
		if i+48 <= len(data) {
			s.check(file, data, i, "raw DER", data[i:i+48])
		}
		from = i + 1
	}
}

func isB64Union(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// b64Lengths are the encoded lengths (padded and not) of 32, 48 and 64 bytes.
var b64Lengths = map[int]bool{43: true, 44: true, 64: true, 86: true, 88: true}

// scanBase64 takes each maximal run of the union of both base64 alphabets
// (plus up to two '=' of padding). A std literal cannot contain '-' or '_' and
// a url literal cannot contain '+' or '/', so each view also splits the run at
// the other alphabet's characters: a seed glued to a hyphenated or pathed
// prefix is still found.
func (s *scanner) scanBase64(file string, data []byte) {
	n := len(data)
	for i := 0; i < n; {
		if !isB64Union(data[i]) {
			i++
			continue
		}
		start := i
		for i < n && isB64Union(data[i]) {
			i++
		}
		end := i
		pad := 0
		for pad < 2 && end+pad < n && data[end+pad] == '=' {
			pad++
		}
		if end-start < 43 {
			continue
		}
		s.b64View(file, data, start, end, pad, "-_", "base64 std", base64.StdEncoding, base64.RawStdEncoding)
		s.b64View(file, data, start, end, pad, "+/", "base64 url", base64.URLEncoding, base64.RawURLEncoding)
	}
}

func (s *scanner) b64View(file string, data []byte, start, end, pad int, splitOn, label string, padded, rawEnc *base64.Encoding) {
	subStart := start
	for j := start; j <= end; j++ {
		if j < end && !strings.ContainsRune(splitOn, rune(data[j])) {
			continue
		}
		if l := j - subStart; l >= 43 {
			cands := []string{string(data[subStart:j])}
			if j == end && pad > 0 {
				cands = append(cands, string(data[subStart:j+pad]))
			}
			for _, c := range cands {
				if !b64Lengths[len(c)] {
					continue
				}
				for _, enc := range []*base64.Encoding{padded, rawEnc} {
					if raw, err := enc.DecodeString(c); err == nil {
						s.check(file, data, subStart, label, raw)
					}
				}
			}
		}
		subStart = j + 1
	}
}

// scanHex takes maximal runs of hex digits of 64, 96 or 128 characters.
func (s *scanner) scanHex(file string, data []byte) {
	n := len(data)
	for i := 0; i < n; {
		if !isHex(data[i]) {
			i++
			continue
		}
		start := i
		for i < n && isHex(data[i]) {
			i++
		}
		switch i - start {
		case 64, 96, 128:
			raw := make([]byte, (i-start)/2)
			if _, err := hex.Decode(raw, data[start:i]); err == nil {
				s.check(file, data, start, "hex", raw)
			}
		}
	}
}

// scanEscapes takes maximal runs of `\xHH` escapes (a Go, Python or C string).
func (s *scanner) scanEscapes(file string, data []byte) {
	n := len(data)
	for i := 0; i+3 < n; {
		if !(data[i] == '\\' && data[i+1] == 'x' && isHex(data[i+2]) && isHex(data[i+3])) {
			i++
			continue
		}
		start := i
		var raw []byte
		for i+3 < n && data[i] == '\\' && data[i+1] == 'x' && isHex(data[i+2]) && isHex(data[i+3]) {
			v, _ := strconv.ParseUint(string(data[i+2:i+4]), 16, 8)
			raw = append(raw, byte(v))
			i += 4
		}
		s.check(file, data, start, `\x-escaped`, raw)
	}
}

// scanIntLists takes every brace or bracket group whose content is only
// integer literals (0x.., decimal, octal) of at most 255, separated by commas,
// whitespace and comments: a Go []byte / [32]byte / ed25519.PrivateKey
// literal, a Python or JSON list. Every 32-byte window is a candidate seed, so
// a seed inside a longer array is found too.
func (s *scanner) scanIntLists(file string, data []byte) {
	n := len(data)
	for i := 0; i < n; i++ {
		open := data[i]
		if open != '{' && open != '[' {
			continue
		}
		closeCh := byte('}')
		if open == '[' {
			closeCh = ']'
		}
		vals, offs, ok := parseIntList(data, i+1, closeCh)
		if !ok || len(vals) < 32 {
			continue
		}
		for w := 0; w+32 <= len(vals); w++ {
			s.check(file, data, offs[w], "integer byte-list", vals[w:w+32])
		}
	}
}

func parseIntList(data []byte, i int, closeCh byte) ([]byte, []int, bool) {
	n := len(data)
	var vals []byte
	var offs []int
	for i < n {
		c := data[i]
		switch {
		case c == closeCh:
			return vals, offs, true
		case c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '/' && i+1 < n && data[i+1] == '/':
			for i < n && data[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && data[i+1] == '*':
			j := bytes.Index(data[i+2:], []byte("*/"))
			if j < 0 {
				return nil, nil, false
			}
			i += j + 4
		case c >= '0' && c <= '9':
			start := i
			for i < n && (isHex(data[i]) || data[i] == 'x' || data[i] == 'X' || data[i] == 'o' || data[i] == 'O' || data[i] == '_') {
				i++
			}
			v, err := strconv.ParseUint(string(data[start:i]), 0, 8)
			if err != nil {
				// "08" is not octal to base 0; a zero-padded decimal list is.
				if v, err = strconv.ParseUint(string(data[start:i]), 10, 8); err != nil {
					return nil, nil, false
				}
			}
			vals = append(vals, byte(v))
			offs = append(offs, start)
		default:
			return nil, nil, false
		}
	}
	return nil, nil, false
}
