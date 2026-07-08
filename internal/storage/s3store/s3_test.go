package s3store

import "testing"

func TestS3KeyRejectsTraversal(t *testing.T) {
	cases := []struct {
		prefix  string
		key     string
		wantErr bool
		want    string
	}{
		{prefix: "", key: "pool/debian/trixie/main/h/hello/hello_1.0.deb", want: "pool/debian/trixie/main/h/hello/hello_1.0.deb"},
		{prefix: "myprefix", key: "pool/debian/trixie/main/h/hello/hello_1.0.deb", want: "myprefix/pool/debian/trixie/main/h/hello/hello_1.0.deb"},
		{prefix: "", key: "../../etc/passwd", wantErr: true},
		{prefix: "myprefix", key: "../../etc/passwd", wantErr: true},
		{prefix: "myprefix", key: "pool/../../../metadata/index/debian.packages.zst", wantErr: true},
		{prefix: "", key: "..", wantErr: true},
		{prefix: "", key: "/pool/debian/foo.deb", want: "pool/debian/foo.deb"},
	}
	for _, c := range cases {
		s := &Store{prefix: c.prefix}
		got, err := s.s3Key(c.key)
		if c.wantErr {
			if err == nil {
				t.Errorf("s3Key(prefix=%q, %q) = %q, want error", c.prefix, c.key, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("s3Key(prefix=%q, %q) unexpected error: %v", c.prefix, c.key, err)
			continue
		}
		if got != c.want {
			t.Errorf("s3Key(prefix=%q, %q) = %q, want %q", c.prefix, c.key, got, c.want)
		}
	}
}
