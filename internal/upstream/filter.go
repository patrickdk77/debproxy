package upstream

import (
	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/model"
)

// filterIndex returns idx with every package the filter rejects removed.
// The cached per-arch slices are shared with other callers, so a filtered
// arch gets a new slice; with a nil filter idx is returned as is.
func filterIndex(idx *Index, filter *model.PackageFilter) *Index {
	if filter == nil || idx == nil || len(idx.ByArch) == 0 {
		return idx
	}
	out := *idx
	out.ByArch = make(map[string][]apt.RawPkg, len(idx.ByArch))
	for arch, pkgs := range idx.ByArch {
		kept := make([]apt.RawPkg, 0, len(pkgs))
		for _, p := range pkgs {
			if filter.Allows(p.Package) {
				kept = append(kept, p)
			}
		}
		out.ByArch[arch] = kept
	}
	return &out
}

// filterSources returns srcs with every source package the filter rejects
// removed, matched on the source package name. A nil filter returns srcs
// as is.
func filterSources(srcs []apt.RawSrc, filter *model.PackageFilter) []apt.RawSrc {
	if filter == nil || len(srcs) == 0 {
		return srcs
	}
	kept := make([]apt.RawSrc, 0, len(srcs))
	for _, s := range srcs {
		if filter.Allows(s.Package) {
			kept = append(kept, s)
		}
	}
	return kept
}
