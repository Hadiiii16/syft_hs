// syft/pkg/cataloger/binary/qualcomm/db.go
package qualcomm

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// ── 임베드 ────────────────────────────────────────────────────────────────

//go:embed db/hash.json
var rawHashDB []byte

//go:embed db/soname.json
var rawSONAMEDB []byte

//go:embed db/patterns.json
var rawPatternDB []byte

//go:embed db/signatures.json
var rawSignatureDB []byte

// ── 타입 정의 ─────────────────────────────────────────────────────────────

type hashEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sonameEntry struct {
	Name string `json:"name"`
}

type patternEntry struct {
	Pattern    string  `json:"pattern"`
	Field      string  `json:"field"`
	Confidence float64 `json:"confidence"`
	Note       string  `json:"note,omitempty"`
}

// bytePattern은 Ghidra로 추출한 바이트 시그니처입니다.
type bytePattern struct {
	Hex  string `json:"hex"`  // "51 43 41 4E" 형식
	Note string `json:"note,omitempty"`
}

// sigEntry는 signatures.json 항목입니다.
//
// source 값에 따라 매칭 방법이 달라집니다:
//   - "nm"           : unique_strings 매칭 (min_match 적용)
//   - "ghidra"       : unique_bytes 매칭
//   - "ghidra_needed": 아직 분석 안 됨 → 매칭 스킵
type sigEntry struct {
	Name            string        `json:"name"`
	Version         string        `json:"version"`
	Supplier        string        `json:"supplier"`
	Confidence      float64       `json:"confidence"`
	UniqueStrings   []string      `json:"unique_strings"`
	MinMatch        int           `json:"min_match"`          // nm 기반: 최소 매칭 개수
	MatchAllStrings bool          `json:"match_all_strings"`  // true: AND 조건
	UniqueBytes     []bytePattern `json:"unique_bytes"`        // Ghidra 추출 바이트 패턴
	Source          string        `json:"source"`
	Note            string        `json:"note,omitempty"`
}

type signatureDB struct {
	HashDB     map[string]hashEntry
	SONAME     map[string]sonameEntry
	Patterns   []patternEntry
	Signatures []sigEntry
}

// ── 싱글톤 로딩 ───────────────────────────────────────────────────────────

var (
	dbOnce    sync.Once
	globalDB  *signatureDB
	dbLoadErr error
)

func loadDB() *signatureDB {
	dbOnce.Do(func() {
		db := &signatureDB{
			HashDB: make(map[string]hashEntry),
			SONAME: make(map[string]sonameEntry),
		}
		if err := json.Unmarshal(rawHashDB, &db.HashDB); err != nil {
			dbLoadErr = err
			return
		}
		if err := json.Unmarshal(rawSONAMEDB, &db.SONAME); err != nil {
			dbLoadErr = err
			return
		}
		if err := json.Unmarshal(rawPatternDB, &db.Patterns); err != nil {
			dbLoadErr = err
			return
		}
		if err := json.Unmarshal(rawSignatureDB, &db.Signatures); err != nil {
			dbLoadErr = err
			return
		}
		globalDB = db
	})
	return globalDB
}