package qualcomm

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed db/hash.json
var rawHashDB []byte

//go:embed db/soname.json
var rawSONAMEDB []byte

//go:embed db/patterns.json
var rawPatternDB []byte

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

type signatureDB struct {
	HashDB   map[string]hashEntry
	SONAME   map[string]sonameEntry
	Patterns []patternEntry
}

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
		globalDB = db
	})
	return globalDB
}