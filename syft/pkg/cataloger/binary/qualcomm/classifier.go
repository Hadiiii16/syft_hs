// syft/pkg/cataloger/binary/qualcomm/classifier.go
package qualcomm

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"io"
	"strings"

	"github.com/anchore/syft/syft/file"
)

type elfInfo struct {
	SHA256   string
	SONAME   string
	Strings  []string
	ModInfo  map[string]string // .ko 전용: modinfo 섹션 key=value
	FilePath string
}

// extractELFInfo는 LocationReadCloser에서 ELF 메타데이터를 추출합니다.
// ELF가 아닌 파일이면 nil, nil을 반환합니다.
func extractELFInfo(reader file.LocationReadCloser) (*elfInfo, error) {
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// SHA256 계산
	sum := sha256.Sum256(raw)
	info := &elfInfo{
		SHA256:   hex.EncodeToString(sum[:]),
		FilePath: reader.Location.RealPath,
		ModInfo:  make(map[string]string),
	}

	// ELF 파싱 — ELF가 아니면 nil 반환 (에러 아님)
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, nil
	}
	defer ef.Close()

	// SONAME (.so 전용)
	if libs, _ := ef.DynString(elf.DT_SONAME); len(libs) > 0 {
		info.SONAME = libs[0]
	}

	// 출력 가능한 문자열 추출 (minLen=8)
	info.Strings = extractPrintableStrings(raw, 8)

	// .modinfo 섹션 파싱 (.ko 전용)
	if sec := ef.Section(".modinfo"); sec != nil {
		if data, err := sec.Data(); err == nil {
			info.ModInfo = parseModInfo(data)
		}
	}

	return info, nil
}

// extractPrintableStrings는 바이너리에서 minLen 이상의
// 연속된 출력 가능한 ASCII 문자열을 추출합니다.
func extractPrintableStrings(data []byte, minLen int) []string {
	var results []string
	var cur strings.Builder

	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			cur.WriteByte(b)
		} else {
			if cur.Len() >= minLen {
				results = append(results, cur.String())
			}
			cur.Reset()
		}
	}
	if cur.Len() >= minLen {
		results = append(results, cur.String())
	}
	return results
}

// parseModInfo는 null로 구분된 .modinfo 섹션을 key=value 맵으로 변환합니다.
func parseModInfo(raw []byte) map[string]string {
	result := make(map[string]string)
	for _, entry := range bytes.Split(raw, []byte{0x00}) {
		parts := bytes.SplitN(entry, []byte("="), 2)
		if len(parts) == 2 && len(parts[0]) > 0 {
			result[string(parts[0])] = string(parts[1])
		}
	}
	return result
}