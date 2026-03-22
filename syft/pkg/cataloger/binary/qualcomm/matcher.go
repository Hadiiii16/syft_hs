package qualcomm

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/file"
)

type matchResult struct {
	Name       string
	Version    string
	SONAME     string
	PURL       string
	SHA256     string
	Confidence float64
	Evidence   []string
}

type Matcher struct {
	db      *signatureDB
	regexps []*regexp.Regexp
}

func newMatcher() (*Matcher, error) {
	db := loadDB()
	if dbLoadErr != nil {
		return nil, dbLoadErr
	}

	compiled := make([]*regexp.Regexp, len(db.Patterns))
	for i, p := range db.Patterns {
		re, err := regexp.Compile("(?i)" + p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p.Pattern, err)
		}
		compiled[i] = re
	}
	return &Matcher{db: db, regexps: compiled}, nil
}

func (m *Matcher) analyze(reader file.LocationReadCloser) (*matchResult, error) {
	info, err := extractELFInfo(reader)
	if err != nil || info == nil {
		return nil, nil
	}

	result := &matchResult{
		SHA256:  info.SHA256,
		SONAME:  info.SONAME,
		Version: "NOASSERTION",
	}

	// Layer 1: 해시 완전 일치 (신뢰도 1.0)
	if entry, ok := m.db.HashDB[info.SHA256]; ok {
		result.Name       = entry.Name
		result.Version    = entry.Version
		result.Confidence = 1.0
		result.Evidence   = append(result.Evidence,
			fmt.Sprintf("hash_match:%s...", info.SHA256[:12]))
		result.PURL = buildPURL(result.Name, result.Version)
		return result, nil
	}

	// Layer 2: SONAME 매칭 (신뢰도 0.9)
	if info.SONAME != "" {
		if entry, ok := m.db.SONAME[info.SONAME]; ok {
			result.Name       = entry.Name
			result.Confidence += 0.9
			result.Evidence   = append(result.Evidence,
				fmt.Sprintf("soname_exact:%s", info.SONAME))
		} else {
			for pattern, entry := range m.db.SONAME {
				if matched, _ := filepath.Match(pattern, info.SONAME); matched {
					result.Name       = entry.Name
					result.Confidence += 0.85
					result.Evidence   = append(result.Evidence,
						fmt.Sprintf("soname_glob:%s", pattern))
					break
				}
			}
		}
	}

	// Layer 3: 문자열 패턴 매칭
	combined := strings.Join(info.Strings, "\n")
	for i, re := range m.regexps {
		pat := m.db.Patterns[i]
		matches := re.FindStringSubmatch(combined)
		if matches == nil {
			continue
		}
		result.Confidence = math.Min(1.0,
			result.Confidence+pat.Confidence*0.35)
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("str_%s:%s", pat.Field, truncate(matches[0], 40)))
		if pat.Field == "version" && len(matches) > 1 &&
			result.Version == "NOASSERTION" {
			result.Version = matches[1]
		}
	}

	// Layer 4: .ko modinfo
	if author, ok := info.ModInfo["author"]; ok {
		if strings.Contains(strings.ToLower(author), "qualcomm") {
			result.Confidence = math.Min(1.0, result.Confidence+0.8)
			result.Evidence   = append(result.Evidence,
				fmt.Sprintf("modinfo_author:%s", truncate(author, 40)))
			if result.Name == "" {
				if desc, ok := info.ModInfo["description"]; ok {
					result.Name = desc
				}
			}
			if result.Version == "NOASSERTION" {
				if ver, ok := info.ModInfo["version"]; ok {
					result.Version = ver
				}
			}
		}
	}

	// Layer 5: 빌드 경로 힌트
	pathHints := []struct {
		hint  string
		score float64
	}{
		{"/vendor/qcom/", 0.5},
		{"/hardware/qcom/", 0.5},
		{"/proprietary/qcom/", 0.55},
		{"qcom-opensource", 0.45},
	}
	for _, ph := range pathHints {
		if strings.Contains(info.FilePath, ph.hint) {
			result.Confidence = math.Min(1.0, result.Confidence+ph.score*0.3)
			result.Evidence   = append(result.Evidence, "build_path:"+ph.hint)
			break
		}
	}

	// 이름 미결정 → 파일명 fallback
	if result.Name == "" {
		base := filepath.Base(info.FilePath)
		name := base
		if idx := strings.Index(name, ".so"); idx != -1 {
			name = name[:idx]
		}
		name = strings.TrimSuffix(name, ".ko")
		result.Name = name
	}

	result.PURL = buildPURL(result.Name, result.Version)

	if result.Confidence < 0.4 {
		return nil, nil
	}
	return result, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}