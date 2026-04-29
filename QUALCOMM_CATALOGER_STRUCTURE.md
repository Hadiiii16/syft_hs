# 프로젝트 코드 구조 도식

SYFT에 퀄컴 소프트웨어 탐지 카탈로그를 통합한 구조를 정리한 문서입니다.

---

## 1. 전체 데이터 흐름

```
┌─────────────────────────────────────────────────────────────────┐
│                     syft scan <대상>                             │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  [syft/create_sbom.go]  CreateSBOM()                             │
│   └─ 모든 카탈로거 실행 → SBOM 조립                                │
│       └─ ★ deduplicateBinaryAndOpkg(&s)  ← 후처리 추가             │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  [internal/task/package_tasks.go]                                │
│   카탈로거 레지스트리 — 여기에 qualcomm 등록                          │
│     newSimplePackageTaskFactory(qualcommbinary.NewCataloger,    │
│       Installed/Image/DirectoryTag, "binary", "qualcomm")        │
└─────────┬───────────────────────────────┬───────────────────────┘
          │                               │
          ▼                               ▼
   기존 카탈로거들                   ★ Qualcomm Cataloger (신규)
   (debian/dpkg, opkg 등)            (syft/pkg/cataloger/binary/qualcomm)
```

---

## 2. Qualcomm 카탈로거 내부 구조

```
syft/pkg/cataloger/binary/qualcomm/
│
├── cataloger.go      ← 진입점 + 플랫폼 후처리
│   ├── NewCataloger()
│   │     globs: **/*.so, **/*.so.*, **/*.ko
│   │     parser:    parseQualcommBinary  (파일별)
│   │     processor: addPlatformComponent (전체 후처리)
│   │
│   ├── parseQualcommBinary()      → 단일 ELF 파일 분석 → pkg.Package
│   ├── addPlatformComponent()     → 펌웨어 chipset → hardware 컴포넌트 1개 추가
│   ├── detectFirmwareChipsets()   ─┐
│   │   ├ readOpenwrtRelease()      │ /etc/openwrt_release, /etc/os-release,
│   │   ├ readOsRelease()           │ /lib/wifi/qcawificfg80211.sh 에서 SoC 추출
│   │   └ readWifiCfgScript()      ─┘
│   ├── buildPlatformPackage()     → cpe:2.3:h:qualcomm:<chip>:- (하드웨어)
│   └── buildComponentCPEs()       → cpe:2.3:a:qualcomm:<sw>:<ver> (소프트웨어)
│
├── classifier.go     ← ELF 메타데이터 추출
│   ├── extractELFInfo()           → SHA256, SONAME, strings, .modinfo, raw bytes
│   ├── extractPrintableStrings()
│   ├── parseModInfo()
│   └── extractChipsetFromVermagic()  → vermagic에서 SoC명 추출
│
├── matcher.go        ← 6단계 매칭 엔진
│   newMatcher() → Matcher.analyze() 가 다음 순서로 점수 누적:
│
│     Layer 1: HashDB        SHA256 완전일치  (신뢰도 1.0, 즉시 반환)
│     Layer 2: SONAME        정확/glob 매칭   (+0.85~0.9)
│     Layer 3: signatures    ghidra(bytes) / nm(strings) 시그니처
│     Layer 4: patterns      regex (version/chipset/supplier_confirm)
│                            ↑ chipset은 빈도 카운팅으로 best 선택
│     Layer 5: .modinfo      license=Proprietary, author=qualcomm, depends=qca*
│     Layer 6: 빌드경로      /vendor/qcom/, /hardware/qcom/, qcom-opensource
│
│     최종 Confidence < 0.4  → drop
│
├── db.go             ← 4개 JSON 임베드 + 싱글톤 로딩
│   //go:embed db/{hash,soname,patterns,signatures}.json
│   loadDB() → *signatureDB { HashDB, SONAME, Patterns, Signatures }
│
└── db/
    ├── hash.json        SHA256 → {name, version}              (197줄)
    ├── soname.json      libxxx.so → {name}                    (확장 예정)
    ├── patterns.json    regex 기반 version/chipset/supplier   (143줄)
    └── signatures.json  unique_strings + unique_bytes (Ghidra/nm) (1907줄)
```

---

## 3. 새로 추가/수정된 syft 코어 파일

```
syft/
├── pkg/
│   ├── qualcomm_binary_entry.go            ★ NEW
│   │   type QualcommBinaryEntry {
│   │     Supplier, SHA256, SONAME, Chipset, Confidence, Evidence
│   │   }
│   │
│   ├── dpkg.go                             ◇ MOD: DpkgDBEntry.CPEID 필드 추가
│   │
│   └── cataloger/
│       └── debian/
│           ├── cataloger.go                ◇ MOD: opkg .control glob 제거
│           │   (status 파일만 파싱하도록 단일화)
│           │
│           └── package.go                  ◇ MOD: opkg 환경 처리 강화
│               · Type을 "opkg"로 덮어씀
│               · 버전 정규화 (-rN, epoch 제거)
│               · .control 파일에서 CPE-ID 직접 추적
│               · CPE 첫 번째 슬롯에 우선 주입
│
└── create_sbom.go                          ◇ MOD: 후처리 추가
    deduplicateBinaryAndOpkg()
       binary-classifier ⊕ opkg 중복 패키지 → opkg 측 제거
```

---

## 4. 매칭 결과 → SBOM 매핑

```
ELF 파일 1개
    │
    ▼ parseQualcommBinary
┌─────────────────────────────────┐
│ pkg.Package (개별 컴포넌트)        │
│  Name/Version  ← 6 layer 매칭     │
│  Type          ← .ko / .so 분기   │
│  PURL          ← pkg:generic/...  │
│  CPEs          ← a:qualcomm:...   │  (소프트웨어 CPE만)
│  Metadata      ← QualcommBinaryEntry
│                  (chipset 포함, 단 CPE는 미포함)
└─────────────────────────────────┘

스캔 종료 후 (resolver 사용)
    │
    ▼ addPlatformComponent
┌─────────────────────────────────┐
│ pkg.Package (플랫폼 컴포넌트, 1+개) │
│  Type = "hardware"               │
│  CPEs = h:qualcomm:<chip>:-      │  (CycloneDX 분리 원칙)
│  → 모든 SW에 chipset CVE가 중복   │
│    매핑되는 것을 방지              │
└─────────────────────────────────┘
```

---

## 핵심 설계 포인트

- **6-Layer 누적 신뢰도**: 단일 시그니처가 아니라 hash → SONAME → signatures(ghidra/nm) → regex → modinfo → path 순으로 점수를 합산하고 0.4 미만이면 폐기.
- **Chipset 결정 우선순위**: `modinfo vermagic` > `빌드경로` > `strings 빈도` 순. 펌웨어 전체에서는 별도로 `/etc/openwrt_release`, `/etc/os-release`, `qcawificfg80211.sh`를 본다.
- **하드웨어/소프트웨어 분리**: chipset CPE는 개별 `.so/.ko`에 붙이지 않고 별도 `hardware` 타입 패키지로 한 번만 추가 → CycloneDX 호환 + 중복 CVE 방지.
- **opkg 통합**: dpkg 카탈로거를 opkg에도 재사용하면서 `.control`의 `CPE-ID` 필드를 끌어와 첫 슬롯에 주입하고, 마지막에 `binary-classifier-cataloger`와 이름이 겹치면 opkg 쪽을 제거.
