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

// // JSON에서 파싱될 복합 룰(YARA Style) 구조체
// type CompositePattern struct {
// 	RuleName   string   `json:"rule_name"`
// 	Field      string   `json:"field"`
// 	Patterns   []string `json:"patterns"`
// 	MinMatch   int      `json:"min_match"`
// 	Confidence float64  `json:"confidence"`
// 	Note       string   `json:"note"`
// }

// 성능 최적화를 위해 미리 컴파일해 둔 정규식 컨테이너
type compiledRule struct {
	Rule    CompositePattern
	Regexps []*regexp.Regexp
}

type Matcher struct {
	db    *signatureDB
	rules []compiledRule
}

func newMatcher() (*Matcher, error) {
	db := loadDB()
	if db == nil {
		return nil, fmt.Errorf("failed to load signature DB")
	}

	var compiledRules []compiledRule

	// JSON에 정의된 모든 룰과 그 안의 패턴들을 순회하며 컴파일
	for _, p := range db.Patterns {
		var regexps []*regexp.Regexp
		for _, patStr := range p.Patterns {
			re, err := regexp.Compile("(?i)" + patStr)
			if err != nil {
				return nil, fmt.Errorf("invalid pattern %q in rule %s: %w", patStr, p.RuleName, err)
			}
			regexps = append(regexps, re)
		}

		compiledRules = append(compiledRules, compiledRule{
			Rule:    p,
			Regexps: regexps,
		})
	}
	return &Matcher{db: db, rules: compiledRules}, nil
}

func (m *Matcher) analyze(reader file.LocationReadCloser) (*matchResult, error) {
	info, err := extractELFInfo(reader)
	if err != nil || info == nil {
		return nil, nil
	}

	// 🛡️ [추가 로직] 명백한 범용 및 오픈소스 파일명은 퀄컴 카탈로거 스캔을 면제함
	baseName := strings.ToLower(filepath.Base(info.FilePath))
	baseName = strings.TrimSuffix(baseName, ".ko") 
	baseName = strings.Split(baseName, ".so")[0]   
	baseName = strings.TrimPrefix(baseName, "lib") 

	// 우리가 찾아낸 오탐 파일들을 여기에 등록합니다.
	knownOpenSource := map[string]bool{
		"iwinfo":        true, // libiwinfo.so, iwinfo.so
		"ieee1905":      true, // libieee1905.so
		"pluginmanager": true, // libpluginManager.so
		"psservice":     true, // libpsService.so
		"configdb":      true, // libconfigdb.so
	}

	if knownOpenSource[baseName] {
		// 퀄컴 카탈로거는 무시하고, 다른 범용 카탈로거(dpkg 등)에게 양보함
		return nil, nil 
	}

	result := &matchResult{
		SHA256:  info.SHA256,
		SONAME:  info.SONAME,
		Version: "NOASSERTION",
	}

	// Layer 1: 해시 완전 일치 (신뢰도 1.0)
	if entry, ok := m.db.HashDB[info.SHA256]; ok {
		result.Name = entry.Name
		result.Version = entry.Version
		result.Confidence = 1.0
		result.Evidence = append(result.Evidence, fmt.Sprintf("hash_match:%s...", info.SHA256[:12]))
		result.PURL = buildPURL(result.Name, result.Version)
		return result, nil
	}

	// Layer 2: SONAME 매칭 (신뢰도 0.9)
	if info.SONAME != "" {
		if entry, ok := m.db.SONAME[info.SONAME]; ok {
			result.Name = entry.Name
			result.Confidence += 0.9
			result.Evidence = append(result.Evidence, fmt.Sprintf("soname_exact:%s", info.SONAME))
		} else {
			for pattern, entry := range m.db.SONAME {
				if matched, _ := filepath.Match(pattern, info.SONAME); matched {
					result.Name = entry.Name
					result.Confidence += 0.85
					result.Evidence = append(result.Evidence, fmt.Sprintf("soname_glob:%s", pattern))
					break
				}
			}
		}
	}

	// Layer 3: 복합 문자열 패턴 (YARA Style Engine)
	combined := strings.Join(info.Strings, "\n")

	for _, cRule := range m.rules {
		// 중복 없는 고유한(Distinct) 매칭을 카운트하기 위한 Set
		distinctMatches := make(map[string]bool)
		var extractedVersion string

		// 해당 룰에 속한 모든 정규식을 돌리며 매칭 확인
		for _, re := range cRule.Regexps {
			// FindAllStringSubmatch로 문서 전체에서 발생하는 모든 매칭을 가져옴
			allMatches := re.FindAllStringSubmatch(combined, -1)
			
			for _, matchGroup := range allMatches {
				fullMatch := matchGroup[0]
				distinctMatches[fullMatch] = true

				// 캡처 그룹이 있는 버전 추출용 룰인 경우
				if cRule.Rule.Field == "version" && len(matchGroup) > 1 && extractedVersion == "" {
					extractedVersion = matchGroup[1]
				}
			}
		}

		// 조건 검사: 고유 매칭 횟수가 min_match를 달성했는가?
		if len(distinctMatches) >= cRule.Rule.MinMatch {
			// 신뢰도 점수 합산
			result.Confidence = math.Min(1.0, result.Confidence+(cRule.Rule.Confidence*0.35))

			// Evidence 생성을 위해 추출된 매칭 문자열 일부를 가져옴 (스팸 방지를 위해 최대 3개)
			var matchedList []string
			count := 0
			for k := range distinctMatches {
				if count >= 3 {
					matchedList = append(matchedList, "...")
					break
				}
				matchedList = append(matchedList, truncate(k, 25))
				count++
			}

			evidenceStr := fmt.Sprintf("rule:%s(%d/%d):[%s]",
				cRule.Rule.RuleName, len(distinctMatches), cRule.Rule.MinMatch, strings.Join(matchedList, ","))
			result.Evidence = append(result.Evidence, evidenceStr)

			// 버전 덮어쓰기 로직
			if cRule.Rule.Field == "version" && extractedVersion != "" && result.Version == "NOASSERTION" {
				result.Version = extractedVersion
			}
		}
	}

	// 이름 미결정 시 파일명 Fallback
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

// func buildPURL(name, version string) string {
// 	// PURL 생성 로직 (생략된 기존 구현체 재사용)
// 	return fmt.Sprintf("pkg:generic/%s@%s", name, version)
// }