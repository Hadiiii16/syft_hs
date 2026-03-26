// syft/pkg/cataloger/binary/qualcomm/cataloger.go
package qualcomm

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "qualcomm-binary-cataloger"

// qualcommCataloger는 펌웨어 레벨 chipset을 캐싱하는 상태 있는 카탈로거입니다.
type qualcommCataloger struct {
	// firmwareChipsets는 펌웨어에서 확실하게 탐지된 chipset 목록입니다.
	// 한 번 결정되면 모든 컴포넌트에 동일하게 적용됩니다.
	firmwareChipsets []string
	detectOnce       sync.Once
}

func NewCataloger() pkg.Cataloger {
	c := &qualcommCataloger{}
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(
			c.parseQualcommBinary,
			"**/*.so",
			"**/*.so.*",
			"**/*.ko",
		)
}

func (c *qualcommCataloger) parseQualcommBinary(
	_ context.Context,
	resolver file.Resolver,
	_ *generic.Environment,
	reader file.LocationReadCloser,
) ([]pkg.Package, []artifact.Relationship, error) {

	// 펌웨어 chipset을 최초 1회만 결정
	c.detectOnce.Do(func() {
		c.firmwareChipsets = detectFirmwareChipsets(resolver)
	})

	m, err := newMatcher()
	if err != nil {
		return nil, nil, fmt.Errorf("qualcomm matcher init: %w", err)
	}

	result, err := m.analyze(reader)
	if err != nil || result == nil {
		return nil, nil, nil
	}

	// 펌웨어 레벨 chipset으로 덮어쓰기
	// 파일별 chipset 탐지보다 펌웨어 레벨이 항상 우선
	if len(c.firmwareChipsets) > 0 {
		result.Chipset = strings.Join(c.firmwareChipsets, ",")
	}

	p := pkg.Package{
		Name:      result.Name,
		Version:   result.Version,
		Locations: file.NewLocationSet(reader.Location),
		Type:      resolvePackageType(reader.Location.RealPath),
		PURL:      result.PURL,
		CPEs:      buildCPEs(result, c.firmwareChipsets),
		Metadata: pkg.QualcommBinaryEntry{
			Supplier:   "Qualcomm Technologies Inc.",
			SHA256:     result.SHA256,
			SONAME:     result.SONAME,
			Chipset:    result.Chipset,
			Confidence: result.Confidence,
			Evidence:   result.Evidence,
		},
	}

	p.SetID()
	return []pkg.Package{p}, nil, nil
}

// detectFirmwareChipsets는 펌웨어에서 확실하게 탐지 가능한 chipset만 반환합니다.
//
// 탐지 경로:
//   OpenWrt  → /etc/openwrt_release (DISTRIB_TARGET)
//              예: ipq/ipq807x_64 → IPQ807X
//
//   QTI Linux→ /etc/os-release (VERSION)
//              예: LE.UM.6.2.3.r1-06300-SDX65.0 → SDX65
//            + /lib/wifi/qcawificfg80211.sh (stop_wifi_fw)
//              예: stop_wifi_fw "IPQ5018" → IPQ5018
//
// 탐지 불가 → firmware_profile.json으로 수동 입력 필요
//   - PCIe 연결 외장 모뎀 (SDX62 등)
//   - IPQ 변형 모델 (IPQ8072A vs IPQ8074)
func detectFirmwareChipsets(resolver file.Resolver) []string {
	if resolver == nil {
		return nil
	}

	var chipsets []string

	// ── OpenWrt: /etc/openwrt_release ─────────────────────────────
	// DISTRIB_TARGET='ipq/ipq807x_64' → IPQ807X
	if chip := readOpenwrtRelease(resolver); chip != "" {
		chipsets = append(chipsets, chip)
		// OpenWrt는 DISTRIB_TARGET이 메인 SoC를 정확히 나타냄
		// 추가 탐지 없이 반환
		return chipsets
	}

	// ── QTI Linux: /etc/os-release ────────────────────────────────
	// VERSION="LE.UM.6.2.3.r1-06300-SDX65.0" → SDX65
	if chip := readOsRelease(resolver); chip != "" {
		chipsets = append(chipsets, chip)
	}

	// ── WiFi SoC: /lib/wifi/qcawificfg80211.sh ────────────────────
	// stop_wifi_fw "IPQ5018" → IPQ5018
	// QTI Linux 기반 펌웨어에서만 의미 있음
	if len(chipsets) > 0 {
		if chip := readWifiCfgScript(resolver); chip != "" {
			chipsets = append(chipsets, chip)
		}
	}

	return chipsets
}

// readOpenwrtRelease는 /etc/openwrt_release에서 chipset을 추출합니다.
func readOpenwrtRelease(resolver file.Resolver) string {
	locations, err := resolver.FilesByPath("/etc/openwrt_release")
	if err != nil || len(locations) == 0 {
		return ""
	}
	reader, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return ""
	}
	defer reader.Close()

	chipRe := regexp.MustCompile(`(?i)(ipq[0-9][0-9a-z]+|qca[0-9][0-9a-z]+|msm[0-9][0-9a-z]+)`)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "DISTRIB_TARGET=") {
			val := strings.Trim(strings.TrimPrefix(line, "DISTRIB_TARGET="), `"'`)
			if m := chipRe.FindString(val); m != "" {
				return strings.ToUpper(m)
			}
		}
	}
	return ""
}

// readOsRelease는 /etc/os-release에서 chipset을 추출합니다.
// QTI Linux: VERSION="LE.UM.6.2.3.r1-06300-SDX65.0" → SDX65
func readOsRelease(resolver file.Resolver) string {
	locations, err := resolver.FilesByPath("/etc/os-release")
	if err != nil || len(locations) == 0 {
		return ""
	}
	reader, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return ""
	}
	defer reader.Close()

	// SDX, IPQ, QCA, MSM, MDM 계열
	chipRe := regexp.MustCompile(`(?i)(sdx[0-9][0-9a-z]+|ipq[0-9][0-9a-z]+|qca[0-9][0-9a-z]+|msm[0-9][0-9a-z]+|mdm[0-9][0-9a-z]+)`)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VERSION=") || strings.HasPrefix(line, "VERSION_ID=") {
			if m := chipRe.FindString(line); m != "" {
				return strings.ToUpper(m)
			}
		}
	}
	return ""
}

// readWifiCfgScript는 /lib/wifi/qcawificfg80211.sh에서 WiFi SoC를 추출합니다.
// stop_wifi_fw "IPQ5018" → IPQ5018
// 이 스크립트에 명시된 경우에만 탐지 (범용 드라이버 코드는 무시)
func readWifiCfgScript(resolver file.Resolver) string {
	locations, err := resolver.FilesByPath("/lib/wifi/qcawificfg80211.sh")
	if err != nil || len(locations) == 0 {
		return ""
	}
	reader, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return ""
	}
	defer reader.Close()

	// stop_wifi_fw "IPQ5018" 패턴만 탐지
	// 범용 드라이버의 QCN9000, QCN9100 등은 제외
	stopFwRe := regexp.MustCompile(`(?i)stop_wifi_fw\s+"(ipq[0-9][0-9a-z]+)"`)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if m := stopFwRe.FindStringSubmatch(line); len(m) > 1 {
			return strings.ToUpper(m[1])
		}
	}
	return ""
}

// buildCPEs는 컴포넌트 CPE와 chipset CPE를 생성합니다.
func buildCPEs(result *matchResult, chipsets []string) []cpe.CPE {
	var cpes []cpe.CPE

	// 컴포넌트 CPE
	compName := strings.ReplaceAll(result.Name, "-", "_")
	ver := result.Version
	if ver == "" {
		ver = "*"
	}
	if c, err := cpe.New(fmt.Sprintf(
		"cpe:2.3:a:qualcomm:%s:%s:*:*:*:*:*:*:*",
		compName, ver), cpe.NVDDictionaryLookupSource); err == nil {
		cpes = append(cpes, c)
	}

	// chipset CPE (펌웨어 레벨에서 확실히 탐지된 것만)
	for _, chip := range chipsets {
		chipLower := strings.ToLower(chip)
		if c, err := cpe.New(fmt.Sprintf(
			"cpe:2.3:h:qualcomm:%s:-:*:*:*:*:*:*:*",
			chipLower), cpe.NVDDictionaryLookupSource); err == nil {
			cpes = append(cpes, c)
		}
	}

	return cpes
}

func resolvePackageType(path string) pkg.Type {
	if len(path) > 3 && path[len(path)-3:] == ".ko" {
		return pkg.LinuxKernelModulePkg
	}
	return pkg.BinaryPkg
}