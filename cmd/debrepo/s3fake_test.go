package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// memS3 is an in-memory S3 endpoint for one bucket: PutObject, GetObject,
// HeadObject, DeleteObject and ListObjectsV2 over path-style URLs. Every
// request must carry a SigV4 signature made with one of the secrets the
// fake was given; it recomputes the signature the way S3 does and answers
// an unknown key id or a wrong signature with 403. It records the key id
// of every request and every key fetched with GET, so a test can tell
// which credentials signed and what a run downloaded.
type memS3 struct {
	srv     *httptest.Server
	bucket  string
	secrets map[string]string
	// region, when set, must match the region in every signature's scope.
	region string
	// rejectACL refuses any PUT that carries an ACL, like a bucket with
	// public ACLs blocked.
	rejectACL bool
	// denyGet lists keys whose GET is answered 403, like a policy that
	// grants ListBucket but not GetObject on them.
	denyGet map[string]bool

	mu      sync.Mutex
	objects map[string]memObject
	gets    []string
	keyIDs  []string
}

type memObject struct {
	data    []byte
	modTime time.Time
}

func newMemS3(t *testing.T, bucket string, secrets map[string]string) *memS3 {
	t.Helper()
	m := &memS3{bucket: bucket, secrets: secrets, objects: map[string]memObject{}}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

// put stores an object directly, the way a publisher would upload it. A
// replaced object gets a later LastModified than the one it replaces, as
// it would on S3 where uploads are seconds apart.
func (m *memS3) put(key string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = memObject{data: data, modTime: m.nextModTime(key)}
}

// nextModTime returns now, or one second past the stored object's time
// when that is not earlier; the caller holds m.mu.
func (m *memS3) nextModTime(key string) time.Time {
	now := time.Now().UTC().Truncate(time.Second)
	if old, ok := m.objects[key]; ok && !old.modTime.Before(now) {
		return old.modTime.Add(time.Second)
	}
	return now
}

func (m *memS3) get(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	obj, ok := m.objects[key]
	return obj.data, ok
}

func (m *memS3) getsSeen() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.gets...)
}

func (m *memS3) resetGets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets = nil
}

// signedOnlyBy fails the test unless every request the fake saw was
// signed with keyID.
func (m *memS3) signedOnlyBy(t *testing.T, keyID string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.keyIDs) == 0 {
		t.Fatal("no request reached the bucket")
	}
	for i, got := range m.keyIDs {
		if got != keyID {
			t.Fatalf("request %d signed with credential %q, want %q", i+1, got, keyID)
		}
	}
}

func (m *memS3) handle(w http.ResponseWriter, r *http.Request) {
	if code := m.authenticate(r); code != "" {
		s3Error(w, http.StatusForbidden, code)
		return
	}
	bucketPath := "/" + m.bucket
	if r.URL.Path != bucketPath && !strings.HasPrefix(r.URL.Path, bucketPath+"/") {
		s3Error(w, http.StatusNotFound, "NoSuchBucket")
		return
	}
	key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, bucketPath), "/")

	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case key == "" && r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		m.list(w, r.URL.Query().Get("prefix"))
	case r.Method == http.MethodPut:
		if m.rejectACL && r.Header.Get("X-Amz-Acl") != "" {
			s3Error(w, http.StatusForbidden, "AccessDenied")
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			s3Error(w, http.StatusBadRequest, "IncompleteBody")
			return
		}
		m.objects[key] = memObject{data: data, modTime: m.nextModTime(key)}
		w.Header().Set("ETag", etagOf(data))
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		if m.denyGet[key] {
			s3Error(w, http.StatusForbidden, "AccessDenied")
			return
		}
		obj, ok := m.objects[key]
		if !ok {
			s3Error(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		if r.Method == http.MethodGet {
			m.gets = append(m.gets, key)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(obj.data)))
		w.Header().Set("Last-Modified", obj.modTime.Format(http.TimeFormat))
		w.Header().Set("ETag", etagOf(obj.data))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(obj.data)
		}
	case r.Method == http.MethodDelete:
		delete(m.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		s3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

type listBucketResult struct {
	XMLName     xml.Name     `xml:"ListBucketResult"`
	Xmlns       string       `xml:"xmlns,attr"`
	Name        string       `xml:"Name"`
	Prefix      string       `xml:"Prefix"`
	KeyCount    int          `xml:"KeyCount"`
	MaxKeys     int          `xml:"MaxKeys"`
	IsTruncated bool         `xml:"IsTruncated"`
	Contents    []listObject `xml:"Contents"`
}

type listObject struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int    `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

// list answers ListObjectsV2 for prefix in one page; the caller holds m.mu.
func (m *memS3) list(w http.ResponseWriter, prefix string) {
	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	res := listBucketResult{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: m.bucket, Prefix: prefix, KeyCount: len(keys), MaxKeys: 1000}
	for _, k := range keys {
		obj := m.objects[k]
		res.Contents = append(res.Contents, listObject{
			Key:          k,
			LastModified: obj.modTime.Format("2006-01-02T15:04:05.000Z"),
			ETag:         etagOf(obj.data),
			Size:         len(obj.data),
			StorageClass: "STANDARD",
		})
	}
	body, err := xml.Marshal(res)
	if err != nil {
		s3Error(w, http.StatusInternalServerError, "InternalError")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}

func etagOf(data []byte) string {
	sum := md5.Sum(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func s3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

// authenticate records the request's key id and checks its signature,
// returning the S3 error code for a failure or "" when it verifies.
func (m *memS3) authenticate(r *http.Request) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	auth := r.Header.Get("Authorization")
	var keyID, scope, signedHeaders, signature string
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "Credential="):
			keyID, scope, _ = strings.Cut(strings.TrimPrefix(part, "Credential="), "/")
		case strings.HasPrefix(part, "SignedHeaders="):
			signedHeaders = strings.TrimPrefix(part, "SignedHeaders=")
		case strings.HasPrefix(part, "Signature="):
			signature = strings.TrimPrefix(part, "Signature=")
		}
	}
	m.keyIDs = append(m.keyIDs, keyID)
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || keyID == "" {
		return "AccessDenied"
	}
	secret, ok := m.secrets[keyID]
	if !ok {
		return "InvalidAccessKeyId"
	}
	if parts := strings.Split(scope, "/"); m.region != "" && (len(parts) < 2 || parts[1] != m.region) {
		return "AuthorizationHeaderMalformed"
	}
	if !hmac.Equal([]byte(sigV4(r, secret, scope, signedHeaders)), []byte(signature)) {
		return "SignatureDoesNotMatch"
	}
	return ""
}

// sigV4 recomputes the AWS Signature Version 4 of r the way S3 does to
// check it: a canonical request over the signed headers, a string to sign
// over the credential scope, and an HMAC chain from the secret.
func sigV4(r *http.Request, secret, scope, signedHeaders string) string {
	var canonHeaders strings.Builder
	for _, name := range strings.Split(signedHeaders, ";") {
		var value string
		switch name {
		case "host":
			value = r.Host
		case "content-length":
			value = strconv.FormatInt(r.ContentLength, 10)
		default:
			value = strings.Join(r.Header.Values(name), ",")
		}
		canonHeaders.WriteString(name + ":" + strings.TrimSpace(value) + "\n")
	}
	canonical := strings.Join([]string{
		r.Method,
		r.URL.EscapedPath(),
		canonicalQuery(r.URL.Query()),
		canonHeaders.String(),
		signedHeaders,
		r.Header.Get("X-Amz-Content-Sha256"),
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope, hex.EncodeToString(sum[:])}, "\n")
	key := []byte("AWS4" + secret)
	for _, part := range strings.Split(scope, "/") {
		key = hmacSHA256(key, part)
	}
	return hex.EncodeToString(hmacSHA256(key, toSign))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
