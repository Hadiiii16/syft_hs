// syft/pkg/cataloger/binary/qualcomm/classifier.go
package qualcomm

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/file"
)

type elfInfo struct {
	SHA256   string
	SONAME   string
	Strings  []string
	ModInfo  map[string]string
	FilePath string
	RawBytes []byte // ← signatures.json 바이트 매칭에 필요
}

// extractELFInfo는 LocationReadCloser에서 ELF 메타데이터를 추출합니다.
func extractELFInfo(reader file.LocationReadCloser) (*elfInfo, error) {
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(raw)
	info := &elfInfo{
		SHA256:   hex.EncodeToString(sum[:]),
		FilePath: reader.Location.RealPath,
		ModInfo:  make(map[string]string),
		RawBytes: raw, // 바이트 시그니처 매칭용으로 보존
	}

	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, nil // ELF 아닌 파일 → 조용히 nil
	}
	defer ef.Close()

	if libs, _ := ef.DynString(elf.DT_SONAME); len(libs) > 0 {
		info.SONAME = libs[0]
	}

	info.Strings = extractPrintableStrings(raw, 8)

	if sec := ef.Section(".modinfo"); sec != nil {
		if data, err := sec.Data(); err == nil {
			info.ModInfo = parseModInfo(data)
		}
	}

	return info, nil
}

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

// extractChipsetFromVermagic는 modinfo vermagic 필드에서 칩셋을 추출합니다.
// vermagic 예: "4.4.60 SMP preempt mod_unload modversions aarch64 ipq807x"
// → "ipq807x" 반환
func extractChipsetFromVermagic(vermagic string) string {
	// ipq, qca, msm 패턴 탐색
	patterns := []string{
		`ipq[0-9][0-9a-z]+`,
		`qca[0-9][0-9a-z]+`,
		`msm[0-9][0-9a-z]+`,
	}
	for _, pat := range patterns {
		re := regexp.MustCompile(`(?i)` + pat)
		if m := re.FindString(vermagic); m != "" {
			return strings.ToUpper(m)
		}
	}
	return ""
}