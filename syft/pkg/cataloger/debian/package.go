package debian

import (
	"context"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/cpe"
)

const (
	md5sumsExt   = ".md5sums"
	conffilesExt = ".conffiles"
	docsPath     = "/usr/share/doc"
)

func newDpkgPackage(ctx context.Context, d pkg.DpkgDBEntry, dbLocation file.Location, resolver file.Resolver, release *linux.Release, evidence ...file.Location) pkg.Package {
	// TODO: separate pr to license refactor, but explore extracting dpkg-specific license parsing into a separate function
	var licenses []pkg.License

	locations := file.NewLocationSet(dbLocation)
	locations.Add(evidence...)

	p := pkg.Package{
		Name:      d.Package,
		Version:   d.Version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		Locations: locations,
		PURL:      packageURL(d, release),
		Type:      pkg.DebPkg,
		Metadata:  d,
	}

if resolver != nil {
		// the current entry only has what may have been listed in the status file, however, there are additional
		// files that are listed in multiple other locations. We should retrieve them all and merge the file lists
		// together.
		mergeFileListing(resolver, dbLocation, &p)

		// fetch additional data from the copyright file to derive the license information
		addLicenses(ctx, resolver, dbLocation, &p)
	}

	// 👇 ====== 여기서부터 추가/수정 ====== 👇
	cpeID := d.CPEID

	// 1. 파일 경로에 "opkg"가 포함되어 있는지 확인하여 opkg 환경인지 판별 (안전장치)
	isOpkgEnv := strings.Contains(dbLocation.RealPath, "opkg")

	// 2. opkg 환경인 경우에만 패키지 타입을 변경하고 .control 파일 추적 로직 실행
	if isOpkgEnv {
		p.Type = pkg.Type("opkg") // 데비안 환경을 건드리지 않고 opkg만 타입 덮어쓰기

		// status 파일이라 CPE-ID가 유실된 경우, 원본 .control 파일을 찾아 직접 읽어오기
		if cpeID == "" && resolver != nil {
			parentDir := filepath.Dir(dbLocation.RealPath)
			// /usr/lib/opkg/info/패키지명.control 경로 추적
			controlPath := path.Join(parentDir, "info", d.Package+".control")
			
			loc := resolver.RelativeFileByPath(dbLocation, controlPath)
			if loc != nil {
				if reader, err := resolver.FileContentsByLocation(*loc); err == nil {
					// 파일을 바이트 단위로 읽어서 CPE-ID 문자열 찾기
					bytes, _ := io.ReadAll(reader)
					for _, line := range strings.Split(string(bytes), "\n") {
						if strings.HasPrefix(line, "CPE-ID:") {
							cpeID = strings.TrimSpace(strings.TrimPrefix(line, "CPE-ID:"))
							break
						}
					}
					reader.Close()
				}
			}
		}
	}

	// 3. 찾아낸 CPE 주입하기
	if cpeID != "" {
		parsedCPE, err := cpe.New(cpeID, cpe.DeclaredSource)
		if err == nil {
			
			// 👇 ====== 수정된 버저닝 로직 (Attributes 추가) ====== 👇
			// 파싱된 CPE의 버전이 비어있거나 와일드카드(*)인 경우, 패키지 버전을 정제해서 채워넣음
			if parsedCPE.Attributes.Version == "" || parsedCPE.Attributes.Version == "*" || parsedCPE.Attributes.Version == "ANY" {
				cleanVersion := d.Version
				
				// 1. epoch 제거 (예: "1:2.90" -> "2.90")
				if parts := strings.SplitN(cleanVersion, ":", 2); len(parts) == 2 {
					cleanVersion = parts[1]
				}
				// 2. OpenWrt 리비전 제거 (예: "2.90-r4" -> "2.90")
				if parts := strings.SplitN(cleanVersion, "-", 2); len(parts) == 2 {
					cleanVersion = parts[0]
				}
				
				// CPE 객체 하위 Attributes에 깔끔해진 버전 강제 할당
				parsedCPE.Attributes.Version = cleanVersion
			}
			// 👆 ====== 여기까지 ====== 👆

			// 정제된 CPE를 맨 앞에 꽂아넣어 최우선 순위로 만듦
			p.CPEs = append([]cpe.CPE{parsedCPE}, p.CPEs...)
		} else {
			log.Tracef("failed to parse custom CPE-ID for package %s: %v", d.Package, err)
		}
		
		// SBOM 메타데이터 갱신
		if metadata, ok := p.Metadata.(pkg.DpkgDBEntry); ok {
			metadata.CPEID = cpeID
			p.Metadata = metadata
		}
	}
	p.SetID()

	return p
}

func newDebArchivePackage(ctx context.Context, location file.Location, metadata pkg.DpkgArchiveEntry, licenseStrings []string) pkg.Package {
	p := pkg.Package{
		Name:     metadata.Package,
		Version:  metadata.Version,
		Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromValuesWithContext(ctx, licenseStrings...)...),
		Type:     pkg.DebPkg,
		PURL: packageURL(
			pkg.DpkgDBEntry(metadata),
			// we don't know the distro information, but since this is a deb file then we can reasonably assume it is a debian-based distro
			&linux.Release{IDLike: []string{"debian"}},
		),
		Metadata:  metadata,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
	}

	p.SetID()
	return p
}

// PackageURL returns the PURL for the specific Debian package (see https://github.com/package-url/purl-spec)
func packageURL(m pkg.DpkgDBEntry, distro *linux.Release) string {
	if distro == nil {
		return ""
	}

	if distro.ID != "debian" && !internal.StringInSlice("debian", distro.IDLike) {
		return ""
	}

	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Architecture,
	}

	if m.Source != "" {
		if m.SourceVersion != "" {
			qualifiers[pkg.PURLQualifierUpstream] = fmt.Sprintf("%s@%s", m.Source, m.SourceVersion)
		} else {
			qualifiers[pkg.PURLQualifierUpstream] = m.Source
		}
	}

	return packageurl.NewPackageURL(
		packageurl.TypeDebian,
		distro.ID,
		m.Package,
		m.Version,
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}

func addLicenses(ctx context.Context, resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	metadata, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.WithFields("package", p).Trace("unable to extract DPKG metadata to add licenses")
		return
	}

	// get license information from the copyright file
	copyrightReader, copyrightLocation := fetchCopyrightContents(resolver, dbLocation, metadata)
	var licenseStrs []string
	if copyrightReader != nil && copyrightLocation != nil {
		defer internal.CloseAndLogError(copyrightReader, copyrightLocation.AccessPath)
		// attach the licenses
		licenseStrs = parseLicensesFromCopyright(copyrightReader)
		for _, licenseStr := range licenseStrs {
			p.Licenses.Add(pkg.NewLicenseFromLocationsWithContext(ctx, licenseStr, copyrightLocation.WithoutAnnotations()))
		}
		// keep a record of the file where this was discovered
		p.Locations.Add(*copyrightLocation)
	}
	// try to use the license classifier if parsing the copyright file failed
	if len(licenseStrs) == 0 {
		sr, sl := fetchCopyrightContents(resolver, dbLocation, metadata)
		if sr != nil && sl != nil {
			defer internal.CloseAndLogError(sr, sl.AccessPath)
			p.Licenses.Add(pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(*sl, sr))...)
		}
	}
}

func mergeFileListing(resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	metadata, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.WithFields("package", p).Trace("unable to extract DPKG metadata to file listing")
		return
	}

	// get file listing (package files + additional config files)
	files, infoLocations := getAdditionalFileListing(resolver, dbLocation, metadata)
loopNewFiles:
	for _, newFile := range files {
		for _, existingFile := range metadata.Files {
			if existingFile.Path == newFile.Path {
				// skip adding this file since it already exists
				continue loopNewFiles
			}
		}
		metadata.Files = append(metadata.Files, newFile)
	}

	// sort files by path
	sort.SliceStable(metadata.Files, func(i, j int) bool {
		return metadata.Files[i].Path < metadata.Files[j].Path
	})

	// persist alterations
	p.Metadata = metadata

	// persist location information from each new source of information
	p.Locations.Add(infoLocations...)
}

func getAdditionalFileListing(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) ([]pkg.DpkgFileRecord, []file.Location) {
	// ensure the default value for a collection is never nil since this may be shown as JSON
	var files = make([]pkg.DpkgFileRecord, 0)
	var locations []file.Location

	md5Reader, md5Location := fetchMd5Contents(resolver, dbLocation, m)

	if md5Reader != nil && md5Location != nil {
		defer internal.CloseAndLogError(md5Reader, md5Location.AccessPath)
		// attach the file list
		files = append(files, parseDpkgMD5Info(md5Reader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *md5Location)
	}

	conffilesReader, conffilesLocation := fetchConffileContents(resolver, dbLocation, m)

	if conffilesReader != nil && conffilesLocation != nil {
		defer internal.CloseAndLogError(conffilesReader, conffilesLocation.AccessPath)
		// attach the file list
		files = append(files, parseDpkgConffileInfo(conffilesReader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *conffilesLocation)
	}

	return files, locations
}

func fetchMd5Contents(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) (io.ReadCloser, *file.Location) {
	var md5Reader io.ReadCloser
	var err error

	if resolver == nil {
		return nil, nil
	}

	// for typical debian-base distributions, the installed package info is at /var/lib/dpkg/status
	// and the md5sum information is under /var/lib/dpkg/info/; however, for distroless the installed
	// package info is across multiple files under /var/lib/dpkg/status.d/ and the md5sums are contained in
	// the same directory
	searchPath := filepath.Dir(dbLocation.RealPath)

	if !strings.HasSuffix(searchPath, "status.d") {
		searchPath = path.Join(searchPath, "info")
	}

	// look for /var/lib/dpkg/info/NAME:ARCH.md5sums
	name := md5Key(m)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(searchPath, name+md5sumsExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.md5sums
		location = resolver.RelativeFileByPath(dbLocation, path.Join(searchPath, m.Package+md5sumsExt))
	}

	if location == nil {
		return nil, nil
	}

	// this is unexpected, but not a show-stopper
	md5Reader, err = resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Tracef("failed to fetch deb md5 contents (package=%s): %+v", m.Package, err)
	}

	l := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)

	return md5Reader, &l
}

func fetchConffileContents(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) (io.ReadCloser, *file.Location) {
	var reader io.ReadCloser
	var err error

	if resolver == nil {
		return nil, nil
	}

	parentPath := filepath.Dir(dbLocation.RealPath)

	// look for /var/lib/dpkg/info/NAME:ARCH.conffiles
	name := md5Key(m)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", name+conffilesExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.conffiles
		location = resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", m.Package+conffilesExt))
	}

	if location == nil {
		return nil, nil
	}

	// this is unexpected, but not a show-stopper
	reader, err = resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Tracef("failed to fetch deb conffiles contents (package=%s): %+v", m.Package, err)
	}

	l := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)

	return reader, &l
}

func fetchCopyrightContents(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) (io.ReadCloser, *file.Location) {
	if resolver == nil {
		return nil, nil
	}

	// look for /usr/share/docs/NAME/copyright files
	copyrightPath := path.Join(docsPath, m.Package, "copyright")
	location := resolver.RelativeFileByPath(dbLocation, copyrightPath)

	// we may not have a copyright file for each package, ignore missing files
	if location == nil {
		return nil, nil
	}

	reader, err := resolver.FileContentsByLocation(*location) //nolint:gocritic // since we're returning the reader, it's up to the caller to close it
	if err != nil {
		log.Tracef("failed to fetch deb copyright contents (package=%s): %s", m.Package, err)
	}

	l := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)

	return reader, &l
}

func md5Key(metadata pkg.DpkgDBEntry) string {
	contentKey := metadata.Package
	if metadata.Architecture != "" && metadata.Architecture != "all" {
		contentKey = contentKey + ":" + metadata.Architecture
	}
	return contentKey
}
