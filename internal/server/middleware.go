package server

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

var (
	zstdPool  = sync.Pool{New: func() any { enc, _ := zstd.NewWriter(io.Discard); return enc }}
	gzipPool  = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}
	flatePool = sync.Pool{New: func() any { w, _ := flate.NewWriter(io.Discard, flate.DefaultCompression); return w }}
)

type compressWriter struct {
	http.ResponseWriter
	compressor  io.WriteCloser
	wroteHeader bool
	encoding    string
}

// isCompressible reports whether a content type benefits from compression.
// Already-compressed payloads (.deb, .gz, .zst) are skipped.
func isCompressible(contentType string) bool {
	contentType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	switch contentType {
	case "text/plain", "text/html", "text/css", "text/xml",
		"application/json", "application/xml":
		return true
	}
	return false
}

func (w *compressWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	if code == http.StatusNoContent || code == http.StatusNotModified ||
		w.Header().Get("Content-Encoding") != "" || !isCompressible(w.Header().Get("Content-Type")) {
		w.encoding = ""
		w.ResponseWriter.WriteHeader(code)
		return
	}

	w.Header().Set("Content-Encoding", w.encoding)
	w.Header().Add("Vary", "Accept-Encoding")
	w.Header().Del("Content-Length")
	// Byte ranges no longer map to the encoded stream.
	w.Header().Del("Accept-Ranges")

	switch w.encoding {
	case "zstd":
		enc := zstdPool.Get().(*zstd.Encoder)
		enc.Reset(w.ResponseWriter)
		w.compressor = enc
	case "gzip":
		enc := gzipPool.Get().(*gzip.Writer)
		enc.Reset(w.ResponseWriter)
		w.compressor = enc
	case "deflate":
		enc := flatePool.Get().(*flate.Writer)
		enc.Reset(w.ResponseWriter)
		w.compressor = enc
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *compressWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.encoding != "" && w.compressor != nil {
		return w.compressor.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *compressWriter) release() {
	if w.compressor == nil {
		return
	}
	if err := w.compressor.Close(); err != nil {
		slog.Warn("compressor close", "encoding", w.encoding, "err", err)
	}
	switch w.encoding {
	case "zstd":
		zstdPool.Put(w.compressor)
	case "gzip":
		gzipPool.Put(w.compressor)
	case "deflate":
		flatePool.Put(w.compressor)
	}
}

// compress negotiates zstd/gzip/deflate response compression. Range requests
// are passed through uncompressed so http.ServeContent can serve byte ranges.
func compress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			next.ServeHTTP(w, r)
			return
		}
		accept := r.Header.Get("Accept-Encoding")
		encoding := ""
		switch {
		case strings.Contains(accept, "zstd"):
			encoding = "zstd"
		case strings.Contains(accept, "gzip"):
			encoding = "gzip"
		case strings.Contains(accept, "deflate"):
			encoding = "deflate"
		}
		if encoding == "" {
			next.ServeHTTP(w, r)
			return
		}
		cw := &compressWriter{ResponseWriter: w, encoding: encoding}
		defer cw.release()
		next.ServeHTTP(cw, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += n
	return n, err
}

// logging writes one Apache Combined Log Format line per request to stdout.
// Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		referer := r.Referer()
		if referer == "" {
			referer = "-"
		}
		userAgent := r.UserAgent()
		if userAgent == "" {
			userAgent = "-"
		}

		fmt.Printf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
			clientIP(r),
			t.Format("02/Jan/2006:15:04:05 -0700"),
			r.Method,
			r.RequestURI,
			r.Proto,
			sw.status,
			sw.bytes,
			referer,
			userAgent,
		)
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if realIP := r.Header.Get("X-Real-Ip"); realIP != "" {
		return realIP
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
