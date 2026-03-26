// syft/pkg/cataloger/binary/qualcomm/matcher.go
package qualcomm

import (
	"bytes"
	"encoding/hex"
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
	Chipset    string
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

	// ── Layer 1: 해시 완전 일치 (신뢰도 1.0) ─────────────────────────
	if entry, ok := m.db.HashDB[info.SHA256]; ok {
		result.Name       = entry.Name
		result.Version    = entry.Version
		result.Confidence = 1.0
		result.Evidence   = append(result.Evidence,
			fmt.Sprintf("hash_match:%s...", info.SHA256[:12]))
		result.PURL = buildPURL(result.Name, result.Version)
		return result, nil
	}

	// ── Layer 2: SONAME 매칭 (신뢰도 0.85~0.9) ───────────────────────
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

	// ── Layer 3: signatures.json 매칭 ────────────────────────────────
	if sigResult := m.matchSignatures(info.RawBytes, info.Strings); sigResult != nil {
		if result.Name == "" {
			result.Name = sigResult.Name
		}
		if sigResult.Version != "" && sigResult.Version != "NOASSERTION" &&
			result.Version == "NOASSERTION" {
			result.Version = sigResult.Version
		}
		result.Confidence = math.Min(1.0,
			result.Confidence+sigResult.Confidence*0.5)
		result.Evidence = append(result.Evidence, sigResult.Evidence...)
	}

	// ── Layer 4: patterns.json 문자열 패턴 매칭 ──────────────────────
	combined := strings.Join(info.Strings, "\n")

	// chipset 빈도 카운팅 (여러 칩셋 문자열 중 가장 많이 등장하는 것 선택)
	chipsetCount := make(map[string]int)

	for i, re := range m.regexps {
		pat     := m.db.Patterns[i]
		matches := re.FindAllString(combined, -1)
		if len(matches) == 0 {
			continue
		}
		firstMatch := re.FindStringSubmatch(combined)
		result.Confidence = math.Min(1.0,
			result.Confidence+pat.Confidence*0.35)
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("str_%s:%s", pat.Field, truncate(firstMatch[0], 40)))
		if pat.Field == "version" && len(firstMatch) > 1 &&
			result.Version == "NOASSERTION" {
			result.Version = firstMatch[1]
		}
		// chipset은 빈도 집계 (나중에 가장 많은 것 선택)
		if pat.Field == "chipset" {
			for _, m := range matches {
				chipsetCount[strings.ToUpper(m)]++
			}
		}
	}

	// chipset 결정 우선순위:
	// 1. modinfo vermagic (가장 정확 - 커널 빌드 타겟)
	// 2. 빌드경로 (두 번째로 정확)
	// 3. strings 빈도 기반 (가장 많이 등장하는 chipset)
	if vermagic, ok := info.ModInfo["vermagic"]; ok && vermagic != "" {
		if chip := extractChipsetFromVermagic(vermagic); chip != "" {
			result.Chipset = chip
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("chipset_vermagic:%s", chip))
		}
	}
	if result.Chipset == "" {
		// 빌드경로에서 chipset 추출
		// 예: linux-ipq_ipq807x_64 → IPQ807X
		buildPathRe := regexp.MustCompile(`(?i)linux-[a-z]+_(ipq[0-9][0-9a-z]+|qca[0-9][0-9a-z]+|msm[0-9][0-9a-z]+)`)
		if m := buildPathRe.FindStringSubmatch(combined); len(m) > 1 {
			result.Chipset = strings.ToUpper(m[1])
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("chipset_buildpath:%s", result.Chipset))
		}
	}
	if result.Chipset == "" && len(chipsetCount) > 0 {
		// 빈도 기반: 가장 많이 등장한 chipset 선택
		bestChip, bestCnt := "", 0
		for chip, cnt := range chipsetCount {
			if cnt > bestCnt {
				bestChip, bestCnt = chip, cnt
			}
		}
		result.Chipset = bestChip
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("chipset_freq:%s(x%d)", bestChip, bestCnt))
	}

	// ── Layer 5: modinfo 보조 (.ko 전용) ──────────────────────────────
	if lic := info.ModInfo["license"]; strings.EqualFold(lic, "Proprietary") {
		result.Confidence = math.Min(1.0, result.Confidence+0.5)
		result.Evidence   = append(result.Evidence, "license=Proprietary")
	}
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
	for _, dep := range strings.Split(info.ModInfo["depends"], ",") {
		dep = strings.TrimSpace(dep)
		if strings.HasPrefix(dep, "qca") || dep == "qdf" {
			result.Confidence = math.Min(1.0, result.Confidence+0.4)
			result.Evidence   = append(result.Evidence,
				fmt.Sprintf("depends=%s", dep))
		}
	}

	// ── Layer 6: 빌드경로 힌트 ────────────────────────────────────────
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
			result.Confidence = math.Min(1.0,
				result.Confidence+ph.score*0.3)
			result.Evidence = append(result.Evidence,
				"build_path:"+ph.hint)
			break
		}
	}

	// ── 이름 미결정 → 파일명 fallback ────────────────────────────────
	if result.Name == "" {
		base := filepath.Base(info.FilePath)
		name := strings.TrimSuffix(base, ".ko")
		if idx := strings.Index(name, ".so"); idx != -1 {
			name = name[:idx]
		}
		result.Name = name
	}

	result.PURL = buildPURL(result.Name, result.Version)

	if result.Confidence < 0.4 {
		return nil, nil
	}
	return result, nil
}

// matchSignatures는 signatures.json 항목을 source별로 다르게 매칭합니다.
//   source="ghidra_needed" → 스킵
//   source="ghidra"        → scoreBytes() 만 사용
//   source="nm"            → scoreStrings() 만 사용 (min_match 포함)
//   그 외                  → 두 가지 모두 시도, 높은 점수 채택
func (m *Matcher) matchSignatures(raw []byte, stringsList []string) *matchResult {
	combined := strings.Join(stringsList, "\n")

	for _, sig := range m.db.Signatures {
		var score float64
		var evTag string

		switch sig.Source {
		case "ghidra_needed":
			continue
		case "ghidra":
			if len(sig.UniqueBytes) == 0 {
				continue
			}
			byteScore := m.scoreBytes(sig, raw)
			if byteScore == 0 {
				continue
			}
			score = byteScore
			evTag = fmt.Sprintf("sig_bytes:%s byte=%.2f", sig.Name, byteScore)
		case "nm":
			if len(sig.UniqueStrings) == 0 {
				continue
			}
			strScore := m.scoreStrings(sig, combined)
			if strScore == 0 {
				continue
			}
			score = strScore
			evTag = fmt.Sprintf("sig_str:%s str=%.2f", sig.Name, strScore)
		default:
			strScore  := m.scoreStrings(sig, combined)
			byteScore := m.scoreBytes(sig, raw)
			if strScore == 0 && byteScore == 0 {
				continue
			}
			score = math.Max(strScore, byteScore)
			evTag = fmt.Sprintf("sig:%s str=%.2f byte=%.2f",
				sig.Name, strScore, byteScore)
		}

		return &matchResult{
			Name:       sig.Name,
			Version:    sig.Version,
			Confidence: sig.Confidence * score,
			Evidence:   []string{evTag},
		}
	}
	return nil
}

// scoreStrings는 unique_strings 매칭 비율을 반환합니다 (0.0~1.0).
func (m *Matcher) scoreStrings(sig sigEntry, combined string) float64 {
	if len(sig.UniqueStrings) == 0 {
		return 0
	}
	matched := 0
	for _, s := range sig.UniqueStrings {
		if strings.Contains(combined, s) {
			matched++
		}
	}
	if sig.MatchAllStrings {
		if matched == len(sig.UniqueStrings) {
			return 1.0
		}
		return 0
	}
	minMatch := sig.MinMatch
	if minMatch <= 0 {
		minMatch = len(sig.UniqueStrings)/2 + 1
	}
	if matched < minMatch {
		return 0
	}
	return float64(matched) / float64(len(sig.UniqueStrings))
}

// scoreBytes는 unique_bytes 매칭 비율을 반환합니다 (0.0~1.0).
func (m *Matcher) scoreBytes(sig sigEntry, raw []byte) float64 {
	if len(sig.UniqueBytes) == 0 || len(raw) == 0 {
		return 0
	}
	matched := 0
	for _, be := range sig.UniqueBytes {
		hexStr := strings.ReplaceAll(be.Hex, " ", "")
		pattern, err := hex.DecodeString(hexStr)
		if err != nil || len(pattern) == 0 {
			continue
		}
		if bytes.Contains(raw, pattern) {
			matched++
		}
	}
	if matched == 0 {
		return 0
	}
	return float64(matched) / float64(len(sig.UniqueBytes))
}

func buildPURL(name, version string) string {
	return fmt.Sprintf("pkg:generic/qualcomm/%s@%s", name, version)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}