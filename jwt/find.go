package jwt

import (
	"io"
	"regexp"
	"strings"
)

// jwtFindRegex matches JWT-shaped strings (header.payload.signature) embedded
// anywhere in arbitrary text. The signature part is optional (alg=none tokens
// have an empty or absent third segment).
var jwtFindRegex = regexp.MustCompile(`\bey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// FindAll scans text and returns every unique JWT found within it, preserving
// discovery order. Only structurally valid JWTs (parseable header and payload)
// are returned; look-alikes that cannot be decoded are silently skipped.
func FindAll(text string) []string {
	matches := jwtFindRegex.FindAllString(text, -1)

	seen := make(map[string]struct{}, len(matches))
	var results []string
	for _, m := range matches {
		if _, dup := seen[m]; dup {
			continue
		}
		if IsJWT(m) {
			seen[m] = struct{}{}
			results = append(results, m)
		}
	}
	return results
}

// FindAllReader reads all content from r and delegates to FindAll.
func FindAllReader(r io.Reader) ([]string, error) {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, r); err != nil {
		return nil, err
	}
	return FindAll(buf.String()), nil
}
