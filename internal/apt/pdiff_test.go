package apt_test

import (
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
)

// ---- ParsePDiffIndex --------------------------------------------------------

func TestParsePDiffIndex_Valid(t *testing.T) {
	input := `SHA256-Current:
 aabbccdd 1234
SHA256-History:
 00112233 1000 2024-01-14-0000.00
 44556677 1100 2024-01-15-0000.00
SHA256-Patches:
 deadbeef 200 2024-01-14-0000.00
 cafebabe 210 2024-01-15-0000.00
`
	idx, err := apt.ParsePDiffIndex(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if idx.CurrentSHA256 != "aabbccdd" {
		t.Errorf("CurrentSHA256: got %q, want %q", idx.CurrentSHA256, "aabbccdd")
	}
	if len(idx.Patches) != 2 {
		t.Fatalf("len(Patches): got %d, want 2", len(idx.Patches))
	}
	if idx.Patches[0].PackagesSHA256 != "00112233" {
		t.Errorf("Patches[0].PackagesSHA256: got %q, want %q", idx.Patches[0].PackagesSHA256, "00112233")
	}
	if idx.Patches[0].Name != "2024-01-14-0000.00" {
		t.Errorf("Patches[0].Name: got %q, want %q", idx.Patches[0].Name, "2024-01-14-0000.00")
	}
}

func TestParsePDiffIndex_EmptyInput(t *testing.T) {
	_, err := apt.ParsePDiffIndex(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error on empty input, got nil")
	}
}

func TestParsePDiffIndex_MissingCurrentField(t *testing.T) {
	input := `SHA256-History:
 00112233 1000 2024-01-14-0000.00
`
	_, err := apt.ParsePDiffIndex(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error on missing SHA256-Current, got nil")
	}
}

// ---- PatchChain -------------------------------------------------------------

func TestPatchChain_FoundAtIndex0(t *testing.T) {
	idx := &apt.PDiffIndex{
		CurrentSHA256: "current",
		Patches: []apt.PDiffPatch{
			{PackagesSHA256: "aaa", Name: "patch-a"},
			{PackagesSHA256: "bbb", Name: "patch-b"},
			{PackagesSHA256: "ccc", Name: "patch-c"},
		},
	}
	chain := idx.PatchChain("aaa")
	if len(chain) != 3 {
		t.Fatalf("expected 3 patches, got %d", len(chain))
	}
	if chain[0] != "patch-a" || chain[1] != "patch-b" || chain[2] != "patch-c" {
		t.Errorf("unexpected chain: %v", chain)
	}
}

func TestPatchChain_FoundAtIndex1(t *testing.T) {
	idx := &apt.PDiffIndex{
		CurrentSHA256: "current",
		Patches: []apt.PDiffPatch{
			{PackagesSHA256: "aaa", Name: "patch-a"},
			{PackagesSHA256: "bbb", Name: "patch-b"},
			{PackagesSHA256: "ccc", Name: "patch-c"},
		},
	}
	chain := idx.PatchChain("bbb")
	if len(chain) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(chain))
	}
	if chain[0] != "patch-b" || chain[1] != "patch-c" {
		t.Errorf("unexpected chain: %v", chain)
	}
}

func TestPatchChain_NotFound(t *testing.T) {
	idx := &apt.PDiffIndex{
		CurrentSHA256: "current",
		Patches: []apt.PDiffPatch{
			{PackagesSHA256: "aaa", Name: "patch-a"},
		},
	}
	chain := idx.PatchChain("zzz")
	if chain != nil {
		t.Errorf("expected nil chain, got %v", chain)
	}
}

func TestPatchChain_EmptyHistoryNotFound(t *testing.T) {
	idx := &apt.PDiffIndex{
		CurrentSHA256: "current",
		Patches:       []apt.PDiffPatch{},
	}
	chain := idx.PatchChain("aaa")
	if chain != nil {
		t.Errorf("expected nil chain for empty history, got %v", chain)
	}
}

func TestPatchChain_LastEntryReturnsSingleElement(t *testing.T) {
	idx := &apt.PDiffIndex{
		CurrentSHA256: "current",
		Patches: []apt.PDiffPatch{
			{PackagesSHA256: "aaa", Name: "patch-a"},
			{PackagesSHA256: "bbb", Name: "patch-b"},
		},
	}
	// The last history entry's sha256 should yield a single-element chain.
	chain := idx.PatchChain("bbb")
	if len(chain) != 1 {
		t.Fatalf("expected 1 patch, got %d: %v", len(chain), chain)
	}
	if chain[0] != "patch-b" {
		t.Errorf("unexpected patch name: %q", chain[0])
	}
}

// ---- SerializeRawPkgs round-trip --------------------------------------------

const twoStanzaPkgs = "Package: apt\nVersion: 2.6.1\nArchitecture: amd64\n\nPackage: bash\nVersion: 5.2\nArchitecture: amd64\n\n"

func TestSerializeRawPkgs_RoundTrip(t *testing.T) {
	pkgs, err := apt.ParsePackageRaws(strings.NewReader(twoStanzaPkgs))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 stanzas, got %d", len(pkgs))
	}
	got := string(apt.SerializeRawPkgs(pkgs))
	if got != twoStanzaPkgs {
		t.Errorf("round-trip mismatch:\ngot:  %q\nwant: %q", got, twoStanzaPkgs)
	}
}

func TestSerializeRawPkgs_StanzaEndsWithDoubleNewline(t *testing.T) {
	pkgs, err := apt.ParsePackageRaws(strings.NewReader(twoStanzaPkgs))
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(apt.SerializeRawPkgs(pkgs))
	stanzas := strings.Split(strings.TrimRight(serialized, "\n"), "\n\n")
	for i, s := range stanzas {
		if s == "" {
			continue
		}
		// After splitting on \n\n, each piece should not be empty and the full
		// serialized form should contain a \n\n after each stanza.
		_ = i
	}
	// Simply verify each stanza boundary appears as \n\n in the output.
	if strings.Count(serialized, "\n\n") != 2 {
		t.Errorf("expected 2 blank-line separators, got %d in %q", strings.Count(serialized, "\n\n"), serialized)
	}
}

// ---- SerializeRawSrcs round-trip --------------------------------------------

const twoStanzaSrcs = "Package: apt\nVersion: 2.6.1\nDirectory: pool/main/a/apt\n\nPackage: bash\nVersion: 5.2\nDirectory: pool/main/b/bash\n\n"

func TestSerializeRawSrcs_RoundTrip(t *testing.T) {
	srcs, err := apt.ParseSourceRaws(strings.NewReader(twoStanzaSrcs))
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 2 {
		t.Fatalf("expected 2 stanzas, got %d", len(srcs))
	}
	got := string(apt.SerializeRawSrcs(srcs))
	if got != twoStanzaSrcs {
		t.Errorf("round-trip mismatch:\ngot:  %q\nwant: %q", got, twoStanzaSrcs)
	}
}

func TestSerializeRawSrcs_StanzaEndsWithDoubleNewline(t *testing.T) {
	srcs, err := apt.ParseSourceRaws(strings.NewReader(twoStanzaSrcs))
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(apt.SerializeRawSrcs(srcs))
	if strings.Count(serialized, "\n\n") != 2 {
		t.Errorf("expected 2 blank-line separators, got %d in %q", strings.Count(serialized, "\n\n"), serialized)
	}
}

// ---- ApplyEdPatch -----------------------------------------------------------

func makePkgs(t *testing.T, raw string) []apt.RawPkg {
	t.Helper()
	pkgs, err := apt.ParsePackageRaws(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func TestApplyEdPatch_Delete(t *testing.T) {
	// Two stanzas; patch deletes all lines of the first stanza (lines 1-3) plus
	// its trailing blank separator (line 4).
	input := "Package: apt\nVersion: 2.6.1\nArchitecture: amd64\n\nPackage: bash\nVersion: 5.2\nArchitecture: amd64\n\n"
	pkgs := makePkgs(t, input)

	// Lines: 1=Package:apt 2=Version:2.6.1 3=Architecture:amd64 4=(blank) 5=Package:bash ...
	patch := []byte("1,4d\n")
	result, err := apt.ApplyEdPatch(pkgs, patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 stanza, got %d", len(result))
	}
	if result[0].Package != "bash" {
		t.Errorf("expected Package=bash, got %q", result[0].Package)
	}
}

func TestApplyEdPatch_Append(t *testing.T) {
	input := "Package: apt\nVersion: 2.6.1\nArchitecture: amd64\n\n"
	pkgs := makePkgs(t, input)

	// Append a new stanza after line 4 (the trailing blank separator).
	patch := []byte("4a\nPackage: bash\nVersion: 5.2\nArchitecture: amd64\n.\n")
	result, err := apt.ApplyEdPatch(pkgs, patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 stanzas, got %d", len(result))
	}
	if result[1].Package != "bash" {
		t.Errorf("expected Package=bash, got %q", result[1].Package)
	}
}

func TestApplyEdPatch_FullStanzaChange(t *testing.T) {
	// Two stanzas; change all lines of the first stanza (lines 1-3).
	input := "Package: apt\nVersion: 2.6.1\nArchitecture: amd64\n\nPackage: bash\nVersion: 5.2\nArchitecture: amd64\n\n"
	pkgs := makePkgs(t, input)

	patch := []byte("1,3c\nPackage: apt\nVersion: 2.7.0\nArchitecture: amd64\n.\n")
	result, err := apt.ApplyEdPatch(pkgs, patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 stanzas, got %d", len(result))
	}
	if result[0].Version != "2.7.0" {
		t.Errorf("expected Version=2.7.0, got %q", result[0].Version)
	}
}

func TestApplyEdPatch_PartialStanzaChange_RebuildPath(t *testing.T) {
	// Three-line stanza; patch changes only line 2 (Version).
	// This exercises the rebuildStanza path (s1 == s2, partial overlap).
	input := "Package: apt\nVersion: 2.6.1\nFilename: pool/main/a/apt/apt_2.6.1_amd64.deb\n\n"
	pkgs := makePkgs(t, input)

	// Change only line 2 (Version).
	patch := []byte("2c\nVersion: 2.7.0\n.\n")
	result, err := apt.ApplyEdPatch(pkgs, patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 stanza, got %d", len(result))
	}
	if result[0].Package != "apt" {
		t.Errorf("Package line lost: got %q", result[0].Package)
	}
	if result[0].Version != "2.7.0" {
		t.Errorf("Version not updated: got %q", result[0].Version)
	}
	if result[0].Filename != "pool/main/a/apt/apt_2.6.1_amd64.deb" {
		t.Errorf("Filename lost: got %q", result[0].Filename)
	}
}

func TestApplyEdPatch_SequentialPatches(t *testing.T) {
	input := "Package: apt\nVersion: 2.6.1\nArchitecture: amd64\n\n"
	pkgs := makePkgs(t, input)

	// First patch: update version.
	patch1 := []byte("2c\nVersion: 2.7.0\n.\n")
	var err error
	pkgs, err = apt.ApplyEdPatch(pkgs, patch1)
	if err != nil {
		t.Fatal(err)
	}

	// Second patch: append a new stanza.
	patch2 := []byte("4a\nPackage: bash\nVersion: 5.2\nArchitecture: amd64\n.\n")
	pkgs, err = apt.ApplyEdPatch(pkgs, patch2)
	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 stanzas, got %d", len(pkgs))
	}
	if pkgs[0].Version != "2.7.0" {
		t.Errorf("first stanza Version: got %q, want 2.7.0", pkgs[0].Version)
	}
	if pkgs[1].Package != "bash" {
		t.Errorf("second stanza Package: got %q, want bash", pkgs[1].Package)
	}
}

func TestApplyEdPatch_UnknownCommand(t *testing.T) {
	pkgs := makePkgs(t, "Package: apt\nVersion: 2.6.1\nArchitecture: amd64\n\n")
	_, err := apt.ApplyEdPatch(pkgs, []byte("1z\n"))
	if err == nil {
		t.Fatal("expected error for unknown command, got nil")
	}
}

func TestApplyEdPatch_BadAddress(t *testing.T) {
	pkgs := makePkgs(t, "Package: apt\nVersion: 2.6.1\nArchitecture: amd64\n\n")
	_, err := apt.ApplyEdPatch(pkgs, []byte("xd\n"))
	if err == nil {
		t.Fatal("expected error for bad address, got nil")
	}
}

// TestApplyEdPatch_OutOfOrderOpsReturnsErrorNotPanic proves that a patch whose
// ops are NOT in the descending-address order real "diff -e" output always
// uses cannot panic. All ops in a patch are resolved against a single lineIdx
// built from the ORIGINAL (pre-patch) stanza list, while items shrinks as
// earlier ops in the same patch are applied; a later op's addresses can then
// point past the end of the now-shorter slice. Before the bounds check this
// paniced with "slice bounds out of range"; it must now return a clean error.
func TestApplyEdPatch_OutOfOrderOpsReturnsErrorNotPanic(t *testing.T) {
	// Three 2-line stanzas: lines 1-2, 4-5, 7-8 (3, 6, 9 are blank separators).
	input := "Package: a\nVersion: 1\n\nPackage: b\nVersion: 1\n\nPackage: c\nVersion: 1\n\n"
	pkgs := makePkgs(t, input)
	if len(pkgs) != 3 {
		t.Fatalf("test setup: expected 3 stanzas, got %d", len(pkgs))
	}

	// Ascending order (invalid for real diff -e, which always emits descending
	// addresses): delete stanza 0 first, then try to delete stanza 2 using its
	// address in the ORIGINAL numbering. After the first delete, items has only
	// 2 elements, but the stale lineIdx still resolves "7,8d" to original
	// stanza index 2 -- out of bounds for the shrunk slice.
	patch := []byte("1,2d\n7,8d\n")

	_, err := apt.ApplyEdPatch(pkgs, patch)
	if err == nil {
		t.Fatal("expected error for out-of-order/out-of-bounds ed ops, got nil (and no panic, which is the main thing being tested)")
	}
}

// TestApplyEdPatch_OutOfOrderAppendReturnsError proves the 'a' (append) op is
// bounds-checked the same way 'd'/'c' are: a stale insertion point past the
// end of an already-shrunk items slice must be rejected, not silently
// clamped into the wrong position by sliceInsert.
func TestApplyEdPatch_OutOfOrderAppendReturnsError(t *testing.T) {
	input := "Package: a\nVersion: 1\n\nPackage: b\nVersion: 1\n\nPackage: c\nVersion: 1\n\n"
	pkgs := makePkgs(t, input)
	if len(pkgs) != 3 {
		t.Fatalf("test setup: expected 3 stanzas, got %d", len(pkgs))
	}

	// Delete stanza 0 first (items shrinks to 2), then append after original
	// line 8 (stanza 2 in the stale lineIdx) -- insertion point 3 is out of
	// bounds for the now 2-element items slice.
	patch := []byte("1,2d\n8a\nPackage: d\nVersion: 1\n.\n")

	_, err := apt.ApplyEdPatch(pkgs, patch)
	if err == nil {
		t.Fatal("expected error for out-of-bounds append insertion point, got nil")
	}
}
