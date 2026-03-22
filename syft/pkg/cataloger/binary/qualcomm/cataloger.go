package qualcomm

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft/artifact"
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
		)
}

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
		Metadata: pkg.QualcommBinaryEntry{
			Supplier:   "Qualcomm Technologies Inc.",
			SHA256:     result.SHA256,
			SONAME:     result.SONAME,
			Confidence: result.Confidence,
			Evidence:   result.Evidence,
		},
	}
	p.SetID()

	return []pkg.Package{p}, nil, nil
}

func resolvePackageType(path string) pkg.Type {
	if len(path) > 3 && path[len(path)-3:] == ".ko" {
		return pkg.LinuxKernelModulePkg
	}
	return pkg.BinaryPkg
}

func buildPURL(name, version string) string {
	return fmt.Sprintf("pkg:generic/qualcomm/%s@%s", name, version)
}