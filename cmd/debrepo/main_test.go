package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
)

// dscBody is a minimal source package description; debrepo appends the
// .dsc's own checksum line to its Files field.
const dscBody = "Source: hello\nVersion: 1.0\nMaintainer: T <t@example.com>\nFiles:\n d41d8cd98f00b204e9800998ecf8427e 0 hello_1.0.tar.gz\n"

func checkSources(t *testing.T, repo repoFS) {
	t.Helper()
	sources := string(readRepoFile(t, repo, "dists/trixie/main/source/Sources"))
	sum := md5.Sum([]byte(dscBody))
	own := fmt.Sprintf("%s %d hello_1.0.dsc\n", hex.EncodeToString(sum[:]), len(dscBody))
	if !strings.Contains(sources, "Package: hello\n") || !strings.Contains(sources, "Directory: dists/trixie/main/source\n") || !strings.Contains(sources, own) {
		t.Fatalf("Sources lacks the hello entry, its Directory or its own line %q:\n%s", own, sources)
	}
}

func testSigningKey(t *testing.T) (*signing.Key, openpgp.EntityList) {
	t.Helper()
	privPath := filepath.Join(t.TempDir(), "test.asc")
	entity, err := openpgp.NewEntity("test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(privPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	w, err := armor.Encode(f, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	_ = f.Close()
	key, err := signing.Load(privPath)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := key.PublicKeyring()
	if err != nil {
		t.Fatal(err)
	}
	return key, keyring
}

// buildTestDeb creates a minimal .deb AR archive readable by
// internal/deb.ControlParagraph; adapted from internal/deb/control_test.go.
func buildTestDeb(t *testing.T, pkg, version, arch string) []byte {
	t.Helper()
	control := []byte(fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: T <t@example.com>\nDescription: %s\n", pkg, version, arch, pkg))

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Size: int64(len(control)), Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(control); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeTestARMember(&ar, "debian-binary", []byte("2.0\n"))
	writeTestARMember(&ar, "control.tar", tarBuf.Bytes())
	writeTestARMember(&ar, "data.tar.gz", []byte{0x1f, 0x8b, 0x08, 0x00})
	return ar.Bytes()
}

func writeTestARMember(w *bytes.Buffer, name string, data []byte) {
	hdr := make([]byte, 60)
	copy(hdr[0:], name+"/")
	for i := len(name) + 1; i < 16; i++ {
		hdr[i] = ' '
	}
	copy(hdr[16:], "0           ")
	copy(hdr[28:], "0     ")
	copy(hdr[34:], "0     ")
	copy(hdr[40:], "100644  ")
	sz := len(data)
	copy(hdr[48:], fmt.Sprintf("%-10d", sz))
	hdr[58] = '`'
	hdr[59] = '\n'
	w.Write(hdr)
	w.Write(data)
	if sz%2 == 1 {
		w.WriteByte(0)
	}
}

func readRepoFile(t *testing.T, repo repoFS, rel string) []byte {
	t.Helper()
	rc, err := repo.open(context.Background(), rel)
	if err != nil {
		t.Fatalf("open %s: %v", rel, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// checkPublished verifies dists/trixie/InRelease against keyring and
// returns the amd64 Packages index of main.
func checkPublished(t *testing.T, repo repoFS, keyring openpgp.EntityList) string {
	t.Helper()
	body, _, err := signing.VerifyClearsigned(readRepoFile(t, repo, "dists/trixie/InRelease"), keyring)
	if err != nil {
		t.Fatalf("InRelease does not verify: %v", err)
	}
	rel, err := apt.ParseRelease(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rel.Files["main/binary-amd64/Packages"]; !ok {
		t.Fatalf("InRelease lists no main/binary-amd64/Packages: %v", rel.Files)
	}
	return string(readRepoFile(t, repo, "dists/trixie/main/binary-amd64/Packages"))
}

func stanza(packages, pkg, version string) bool {
	return strings.Contains(packages, "Package: "+pkg+"\n") && strings.Contains(packages, "Version: "+version+"\n")
}

func writeLocal(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunLocalRepository(t *testing.T) {
	ctx := context.Background()
	key, keyring := testSigningKey(t)
	root := t.TempDir()
	writeLocal(t, root, "dists/trixie/main/deb/hello_1.0_amd64.deb", buildTestDeb(t, "hello", "1.0", "amd64"))
	if err := os.MkdirAll(filepath.Join(root, "dists/trixie/main/binary-amd64"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLocal(t, root, "pool/main/w/world/world_2.0_amd64.deb", buildTestDeb(t, "world", "2.0", "amd64"))
	writeLocal(t, root, "dists/trixie/main/source/hello_1.0.dsc", []byte(dscBody))
	repo := localRepo{root: root}

	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	packages := checkPublished(t, repo, keyring)
	if !stanza(packages, "hello", "1.0") || !stanza(packages, "world", "2.0") {
		t.Fatalf("Packages lacks hello 1.0 or world 2.0:\n%s", packages)
	}
	if !strings.Contains(packages, "Filename: dists/trixie/main/deb/hello_1.0_amd64.deb\n") || !strings.Contains(packages, "Filename: pool/main/w/world/world_2.0_amd64.deb\n") {
		t.Fatalf("Packages has the wrong Filename fields:\n%s", packages)
	}
	checkSources(t, repo)

	// An unchanged tree leaves the state alone: nothing to rotate.
	state := filepath.Join(root, "dists/trixie/main/.debrepo.zst")
	before, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("state rewritten although nothing changed")
	}
	if _, err := os.Stat(state[:len(state)-len(".zst")] + ".old.zst"); err == nil {
		t.Fatal("previous state kept although nothing changed")
	}

	// A replaced .deb (same size, newer mtime) is reprocessed and the
	// previous state is kept as .old.
	hello := filepath.Join(root, "dists/trixie/main/deb/hello_1.0_amd64.deb")
	writeLocal(t, root, "dists/trixie/main/deb/hello_1.0_amd64.deb", buildTestDeb(t, "hello", "1.0.1", "amd64"))
	later := before.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(hello, later, later); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	packages = checkPublished(t, repo, keyring)
	if !stanza(packages, "hello", "1.0.1") || stanza(packages, "hello", "1.0") {
		t.Fatalf("Packages not updated to hello 1.0.1:\n%s", packages)
	}
	if _, err := os.Stat(filepath.Join(root, "dists/trixie/main/.debrepo.old.zst")); err != nil {
		t.Fatalf("previous state not kept: %v", err)
	}
}

// isolateAWSEnv keeps the host's AWS environment, shared config files and
// every other credential source out of the test.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing")
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID":                      "",
		"AWS_SECRET_ACCESS_KEY":                  "",
		"AWS_SESSION_TOKEN":                      "",
		"AWS_PROFILE":                            "",
		"AWS_REGION":                             "",
		"AWS_DEFAULT_REGION":                     "",
		"AWS_CONFIG_FILE":                        missing,
		"AWS_SHARED_CREDENTIALS_FILE":            missing,
		"AWS_EC2_METADATA_DISABLED":              "true",
		"AWS_WEB_IDENTITY_TOKEN_FILE":            "",
		"AWS_ROLE_ARN":                           "",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI":     "",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN":      "",
		"AWS_CA_BUNDLE":                          "",
		"AWS_USE_FIPS_ENDPOINT":                  "",
		"AWS_USE_DUALSTACK_ENDPOINT":             "",
		"AWS_ENDPOINT_URL":                       "",
		"AWS_ENDPOINT_URL_S3":                    "",
	} {
		t.Setenv(k, v)
	}
}

func TestRunS3Repository(t *testing.T) {
	// Downloads land in TMPDIR; it must be empty again when the run ends.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	isolateAWSEnv(t)
	ctx := context.Background()
	key, keyring := testSigningKey(t)
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMURL": "url/secret"})
	fake.region = "us-east-1"
	const helloKey = "debian/dists/trixie/main/deb/hello_1.0_amd64.deb"
	fake.put(helloKey, buildTestDeb(t, "hello", "1.0", "amd64"))
	fake.put("debian/dists/trixie/main/binary-amd64/", nil)
	fake.put("debian/pool/main/w/world/world_2.0_amd64.deb", buildTestDeb(t, "world", "2.0", "amd64"))
	fake.put("debian/dists/trixie/main/source/hello_1.0.dsc", []byte(dscBody))
	// A sibling prefix that shares the name is another repository.
	fake.put("debian-old/dists/bookworm/main/deb/old_1.0_amd64.deb", buildTestDeb(t, "old", "1.0", "amd64"))
	flags := s3Flags{region: "us-east-1", endpoint: fake.srv.URL, pathStyle: true}
	const dir = "s3://AKIAFROMURL:url%2Fsecret@repo/debian"

	repo, err := openRepo(ctx, dir, flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	packages := checkPublished(t, repo, keyring)
	if !stanza(packages, "hello", "1.0") || !stanza(packages, "world", "2.0") || stanza(packages, "old", "1.0") {
		t.Fatalf("Packages lacks hello 1.0 or world 2.0, or has the sibling prefix's package:\n%s", packages)
	}
	checkSources(t, repo)
	fake.signedOnlyBy(t, "AKIAFROMURL")
	for _, k := range []string{"debian/dists/trixie/InRelease", "debian/dists/trixie/Release.gpg", "debian/dists/trixie/main/binary-amd64/Packages.gz", "debian/dists/trixie/main/source/Sources.gz", "debian/dists/trixie/main/.debrepo.zst", "debian/dists/trixie/main/.debrepo-src.zst", "debian/pool/main/.debrepo.zst"} {
		if _, ok := fake.get(k); !ok {
			t.Fatalf("object %s not written", k)
		}
	}
	for _, k := range []string{"debian/dists/bookworm/InRelease", "debian-old/dists/bookworm/InRelease"} {
		if _, ok := fake.get(k); ok {
			t.Fatalf("object %s written for the sibling prefix", k)
		}
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}

	// A second run reads the state objects and downloads no .deb again.
	fake.resetGets()
	repo, err = openRepo(ctx, dir, flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	for _, k := range fake.getsSeen() {
		if strings.HasSuffix(k, ".deb") {
			t.Fatalf("unchanged package downloaded again: %s", k)
		}
	}
	if _, ok := fake.get("debian/dists/trixie/main/.debrepo.old.zst"); ok {
		t.Fatal("previous state kept although nothing changed")
	}

	// A replaced object (same size, newer LastModified) is downloaded once,
	// reprocessed, and the previous state is kept as .old.
	fake.put(helloKey, buildTestDeb(t, "hello", "1.0.1", "amd64"))
	fake.resetGets()
	repo, err = openRepo(ctx, dir, flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	packages = checkPublished(t, repo, keyring)
	if !stanza(packages, "hello", "1.0.1") || stanza(packages, "hello", "1.0") {
		t.Fatalf("Packages not updated to hello 1.0.1:\n%s", packages)
	}
	downloads := 0
	for _, k := range fake.getsSeen() {
		if k == helloKey {
			downloads++
		}
	}
	if downloads != 1 {
		t.Fatalf("replaced package downloaded %d times, want 1", downloads)
	}
	if _, ok := fake.get("debian/dists/trixie/main/.debrepo.old.zst"); !ok {
		t.Fatal("previous state not kept")
	}
}

// A URL without credentials uses the default chain, here the environment,
// and a bare bucket is a repository at the root of the bucket.
func TestRunS3RepositoryAtBucketRootWithDefaultCredentialChain(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	t.Setenv("AWS_REGION", "us-east-1")
	ctx := context.Background()
	key, keyring := testSigningKey(t)
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
	fake.region = "us-east-1"
	fake.put("dists/trixie/main/deb/hello_1.0_amd64.deb", buildTestDeb(t, "hello", "1.0", "amd64"))
	fake.put("dists/trixie/main/binary-amd64/", nil)

	repo, err := openRepo(ctx, "s3://repo", s3Flags{endpoint: fake.srv.URL, pathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	if packages := checkPublished(t, repo, keyring); !stanza(packages, "hello", "1.0") {
		t.Fatalf("Packages lacks hello 1.0:\n%s", packages)
	}
	if _, ok := fake.get("dists/trixie/InRelease"); !ok {
		t.Fatal("InRelease not written at the bucket root")
	}
	fake.signedOnlyBy(t, "AKIAFROMENV")
}

func TestOpenS3RepoWrongSecretIsRefused(t *testing.T) {
	isolateAWSEnv(t)
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMURL": "url/secret"})
	_, err := openRepo(context.Background(), "s3://AKIAFROMURL:wrong@repo", s3Flags{region: "us-east-1", endpoint: fake.srv.URL, pathStyle: true})
	if !errors.Is(err, storage.ErrAccessDenied) {
		t.Fatalf("err = %v, want access denied from the bucket", err)
	}
	fake.signedOnlyBy(t, "AKIAFROMURL")
}

// The region comes from -s3-region, then AWS_REGION, then
// AWS_DEFAULT_REGION; the fake refuses a signature scoped to any other.
func TestOpenS3RepoRegionPrecedence(t *testing.T) {
	cases := []struct {
		name, flag, env, defaultEnv, want string
	}{
		{"flag beats AWS_REGION", "eu-west-1", "us-east-1", "", "eu-west-1"},
		{"AWS_REGION beats AWS_DEFAULT_REGION", "", "us-east-1", "ap-south-1", "us-east-1"},
		{"AWS_DEFAULT_REGION alone", "", "", "ap-south-1", "ap-south-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
			t.Setenv("AWS_REGION", tc.env)
			t.Setenv("AWS_DEFAULT_REGION", tc.defaultEnv)
			fake := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
			fake.region = tc.want
			fake.put("dists/trixie/main/binary-amd64/", nil)
			flags := s3Flags{region: tc.flag, endpoint: fake.srv.URL, pathStyle: true}
			if _, err := openRepo(context.Background(), "s3://repo", flags); err != nil {
				t.Fatalf("region %q not used: %v", tc.want, err)
			}
			other := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
			other.region = "us-west-2"
			other.put("dists/trixie/main/binary-amd64/", nil)
			flags.endpoint = other.srv.URL
			if _, err := openRepo(context.Background(), "s3://repo", flags); err == nil {
				t.Fatal("a signature for the wrong region was accepted, so the region check proves nothing")
			}
		})
	}
}

// A bucket with public ACLs blocked answers AccessDenied to every PUT
// that carries one, which is every write unless -s3-no-acl is set.
func TestRunS3RepositoryOnBucketThatBlocksPublicACLs(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	ctx := context.Background()
	key, keyring := testSigningKey(t)
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
	fake.rejectACL = true
	fake.put("dists/trixie/main/deb/hello_1.0_amd64.deb", buildTestDeb(t, "hello", "1.0", "amd64"))
	fake.put("dists/trixie/main/binary-amd64/", nil)
	flags := s3Flags{region: "us-east-1", endpoint: fake.srv.URL, pathStyle: true}

	repo, err := openRepo(ctx, "s3://repo", flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err == nil {
		t.Fatal("run reported success although every write was refused")
	}
	if _, ok := fake.get("dists/trixie/InRelease"); ok {
		t.Fatal("InRelease written although the bucket refused the ACL, so the control proves nothing")
	}

	flags.noACL = true
	repo, err = openRepo(ctx, "s3://repo", flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	if packages := checkPublished(t, repo, keyring); !stanza(packages, "hello", "1.0") {
		t.Fatalf("Packages lacks hello 1.0:\n%s", packages)
	}
}

// A package the listing returned but the bucket will not deliver must
// abort the run with a failure, not be dropped from a signed index as if
// it had been deleted; the aborted run leaves the old index alone and no
// temporary file behind.
func TestRunS3RepositoryAbortsWhenAListedPackageCannotBeRead(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	ctx := context.Background()
	key, keyring := testSigningKey(t)
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
	const helloKey = "dists/trixie/main/deb/hello_1.0_amd64.deb"
	fake.put(helloKey, buildTestDeb(t, "hello", "1.0", "amd64"))
	fake.put("dists/trixie/main/binary-amd64/", nil)
	flags := s3Flags{region: "us-east-1", endpoint: fake.srv.URL, pathStyle: true}

	repo, err := openRepo(ctx, "s3://repo", flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	published, _ := fake.get("dists/trixie/InRelease")

	fake.put("dists/trixie/main/deb/world_2.0_amd64.deb", buildTestDeb(t, "world", "2.0", "amd64"))
	fake.denyGet = map[string]bool{"dists/trixie/main/deb/world_2.0_amd64.deb": true}
	repo, err = openRepo(ctx, "s3://repo", flags)
	if err != nil {
		t.Fatal(err)
	}
	err = run(ctx, repo, "myorg", "MyOrg", "myorg", false, key)
	if err == nil || !strings.Contains(err.Error(), "codenames failed") {
		t.Fatalf("err = %v, want the run to fail", err)
	}
	if now, _ := fake.get("dists/trixie/InRelease"); !bytes.Equal(now, published) {
		t.Fatal("InRelease rewritten by a run that could not read every package")
	}
	if packages := checkPublished(t, repo, keyring); !stanza(packages, "hello", "1.0") {
		t.Fatalf("the earlier index was lost:\n%s", packages)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

// A corrupt state object falls back to the .old copy, so an unchanged
// package is still not downloaded again.
func TestRunS3RepositoryFallsBackToPreviousState(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	ctx := context.Background()
	key, _ := testSigningKey(t)
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
	fake.put("dists/trixie/main/deb/hello_1.0_amd64.deb", buildTestDeb(t, "hello", "1.0", "amd64"))
	fake.put("dists/trixie/main/binary-amd64/", nil)
	flags := s3Flags{region: "us-east-1", endpoint: fake.srv.URL, pathStyle: true}

	repo, err := openRepo(ctx, "s3://repo", flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	state, ok := fake.get("dists/trixie/main/.debrepo.zst")
	if !ok {
		t.Fatal("state not written")
	}
	fake.put("dists/trixie/main/.debrepo.old.zst", state)
	fake.put("dists/trixie/main/.debrepo.zst", []byte("not zstd"))
	fake.resetGets()

	repo, err = openRepo(ctx, "s3://repo", flags)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, repo, "myorg", "MyOrg", "myorg", false, key); err != nil {
		t.Fatal(err)
	}
	for _, k := range fake.getsSeen() {
		if strings.HasSuffix(k, ".deb") {
			t.Fatalf("package downloaded again although the previous state described it: %s", k)
		}
	}
}

// With no flag and no environment variable, the region comes from the
// shared config, as it does for every other AWS tool.
func TestOpenS3RepoRegionFromSharedConfig(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	cfgPath := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(cfgPath, []byte("[default]\nregion = ap-south-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgPath)
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
	fake.region = "ap-south-1"
	fake.put("dists/trixie/main/binary-amd64/", nil)

	if _, err := openRepo(context.Background(), "s3://repo", s3Flags{endpoint: fake.srv.URL, pathStyle: true}); err != nil {
		t.Fatalf("region from the shared config not used: %v", err)
	}
}

// A key that does not clean to itself would be read back from the cleaned
// path, so the listing leaves it out instead of publishing a file this
// run cannot fetch or a ".." codename.
func TestS3RepoIgnoresKeysThatDoNotCleanToThemselves(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	ctx := context.Background()
	fake := newMemS3(t, "repo", map[string]string{"AKIAFROMENV": "envsecret"})
	deb := buildTestDeb(t, "hello", "1.0", "amd64")
	fake.put("dists/trixie/main/deb/hello_1.0_amd64.deb", deb)
	fake.put("dists/trixie/main/deb//twice_1.0_amd64.deb", deb)
	fake.put("dists/../escape/main/deb/x_1.0_amd64.deb", deb)
	fake.put("dists/./dot/main/deb/x_1.0_amd64.deb", deb)

	repo, err := openRepo(ctx, "s3://repo", s3Flags{region: "us-east-1", endpoint: fake.srv.URL, pathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	names, err := repo.subdirs(ctx, "dists")
	if err != nil || fmt.Sprint(names) != "[trixie]" {
		t.Fatalf("subdirs = %v, %v, want [trixie]", names, err)
	}
	var walked []string
	_ = repo.walk(ctx, "dists/trixie/main/deb", ".deb", func(rel string, _ int64, _ time.Time) {
		walked = append(walked, rel)
	})
	if fmt.Sprint(walked) != "[hello_1.0_amd64.deb]" {
		t.Fatalf("walk = %v, want only hello_1.0_amd64.deb", walked)
	}
}

func TestOpenS3RepoNeedsRegion(t *testing.T) {
	isolateAWSEnv(t)
	_, err := openRepo(context.Background(), "s3://repo/debian", s3Flags{})
	if err == nil || !strings.Contains(err.Error(), "-s3-region") {
		t.Fatalf("err = %v, want a region error", err)
	}
}

func TestParseS3Dir(t *testing.T) {
	good := []struct {
		dir                               string
		bucket, prefix, accessKey, secret string
	}{
		{"s3://bucket", "bucket", "", "", ""},
		{"s3://bucket/", "bucket", "", "", ""},
		{"s3://bucket/debian/repo/", "bucket", "debian/repo", "", ""},
		{"s3://AKIA:sec%2Fret@bucket/debian", "bucket", "debian", "AKIA", "sec/ret"},
	}
	for _, tc := range good {
		bucket, prefix, accessKey, secret, err := parseS3Dir(tc.dir)
		if err != nil {
			t.Fatalf("%s: %v", tc.dir, err)
		}
		if bucket != tc.bucket || prefix != tc.prefix || accessKey != tc.accessKey || secret != tc.secret {
			t.Fatalf("%s: got %q %q %q %q", tc.dir, bucket, prefix, accessKey, secret)
		}
	}
	bad := []string{
		"s3://",
		"s3://bucket:9000/x",
		"s3://k:/topsecret@bucket/x",
		"s3://k:12/topsecret@bucket/x",
		"s3://bucket/x@topsecret",
		"s3://k@bucket/x",
		"s3://bucket/x?topsecret",
		"s3://bucket/x#topsecret",
		"http://bucket/x",
	}
	for _, dir := range bad {
		_, _, _, _, err := parseS3Dir(dir)
		if err == nil {
			t.Fatalf("%s: accepted", dir)
		}
		if strings.Contains(err.Error(), "topsecret") {
			t.Fatalf("%s: error leaks the secret: %v", dir, err)
		}
	}
}
