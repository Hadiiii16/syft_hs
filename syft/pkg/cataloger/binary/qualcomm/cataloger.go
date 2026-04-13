// syft/pkg/cataloger/binary/qualcomm/cataloger.go
package qualcomm

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "qualcomm-binary-cataloger"

func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(
			parseQualcommBinary,
			"**/*.so",
			"**/*.so.*",
			"**/*.ko",
		).
		// 모든 파일 스캔 완료 후 플랫폼 컴포넌트 1개 추가
		// chipset CPE는 개별 컴포넌트가 아닌 플랫폼 컴포넌트에만 포함
		WithResolvingProcessors(addPlatformComponent)
}

// parseQualcommBinary는 단일 바이너리 파일을 분석합니다.
// chipset CPE는 여기서 추가하지 않고 addPlatformComponent에서 처리합니다.
func parseQualcommBinary(
	_ context.Context,
	_ file.Resolver,
	_ *generic.Environment,
	reader file.LocationReadCloser,
) ([]pkg.Package, []artifact.Relationship, error) {
	m, err := newMatcher()
	if err != nil {
		return nil, nil, fmt.Errorf("qualcomm matcher init: %w", err)
	}

	result, err := m.analyze(reader)
	if err != nil || result == nil {
		return nil, nil, nil
	}

	p := pkg.Package{
		Name:      result.Name,
		Version:   result.Version,
		Locations: file.NewLocationSet(reader.Location),
		Type:      resolvePackageType(reader.Location.RealPath),
		PURL:      result.PURL,
		CPEs:      buildComponentCPEs(result), // 소프트웨어 CPE만
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

// addPlatformComponent는 모든 파일 스캔 완료 후 실행되는 후처리기입니다.
// 펌웨어에서 탐지된 chipset을 하드웨어 플랫폼 컴포넌트로 SBOM에 추가합니다.
//
// 이렇게 하면:
//   - 플랫폼 CVE가 모든 소프트웨어 컴포넌트에 중복 매핑되는 것을 방지
//   - CycloneDX 스펙에 맞게 하드웨어/소프트웨어 컴포넌트를 분리
func addPlatformComponent(
	_ context.Context,
	resolver file.Resolver,
	pkgs []pkg.Package,
	rels []artifact.Relationship,
	err error,
) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil {
		return pkgs, rels, err
	}

	chipsets := detectFirmwareChipsets(resolver)
	if len(chipsets) == 0 {
		return pkgs, rels, nil
	}

	// chipset별 플랫폼 컴포넌트 생성
	// 각 chipset을 독립적인 hardware 컴포넌트로 추가
	for _, chip := range chipsets {
		platformPkg := buildPlatformPackage(chip)
		pkgs = append(pkgs, platformPkg)
	}

	return pkgs, rels, nil
}

// buildPlatformPackage는 chipset에 대한 하드웨어 플랫폼 컴포넌트를 생성합니다.
// type: hardware, CPE: cpe:2.3:h:qualcomm:<chip>:-
func buildPlatformPackage(chip string) pkg.Package {
	chipLower := strings.ToLower(chip)
	chipUpper := strings.ToUpper(chip)

	var cpes []cpe.CPE
	if c, err := cpe.New(fmt.Sprintf(
		"cpe:2.3:h:qualcomm:%s:-:*:*:*:*:*:*:*",
		chipLower), cpe.NVDDictionaryLookupSource); err == nil {
		cpes = append(cpes, c)
	}

	p := pkg.Package{
		Name:    chipUpper,
		Version: "-",
		Type:    pkg.Type("hardware"),
		PURL:    fmt.Sprintf("pkg:generic/qualcomm/%s@-", chipLower),
		CPEs:    cpes,
		Metadata: pkg.QualcommBinaryEntry{
			Supplier: "Qualcomm Technologies Inc.",
			Chipset:  chipUpper,
			Evidence: []string{"platform_component"},
		},
	}

	p.SetID()
	return p
}

// buildComponentCPEs는 소프트웨어 컴포넌트 CPE만 생성합니다.
// chipset CPE는 포함하지 않습니다 (addPlatformComponent에서 별도 처리).
func buildComponentCPEs(result *matchResult) []cpe.CPE {
	var cpes []cpe.CPE

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

	return cpes
}

// ── 펌웨어 chipset 탐지 ───────────────────────────────────────────────────

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
// 탐지 불가 (firmware_profile.json으로 수동 입력 필요):
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
		// OpenWrt는 DISTRIB_TARGET이 메인 SoC를 정확히 나타냄
		return []string{chip}
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
	stopFwRe := regexp.MustCompile(`(?i)stop_wifi_fw\s+"(ipq[0-9][0-9a-z]+)"`)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if m := stopFwRe.FindStringSubmatch(scanner.Text()); len(m) > 1 {
			return strings.ToUpper(m[1])
		}
	}
	return ""
}

func resolvePackageType(path string) pkg.Type {
	if len(path) > 3 && path[len(path)-3:] == ".ko" {
		return pkg.LinuxKernelModulePkg
	}
	return pkg.BinaryPkg
}