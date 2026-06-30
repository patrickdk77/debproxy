package deb

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

const arGlobalHeader = "!<arch>\n"

type arHeader struct {
	Name string
	Size int64
}

func readAR(r io.Reader) ([]arHeader, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if string(hdr[:]) != arGlobalHeader {
		return nil, fmt.Errorf("invalid ar archive")
	}

	var members []arHeader
	for {
		var bh [60]byte
		if _, err := io.ReadFull(r, bh[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		name := strings.TrimSpace(string(bh[0:16]))
		name = strings.TrimSuffix(name, "/")
		sizeStr := strings.TrimSpace(string(bh[48:58]))
		var size int64
		if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
			return nil, fmt.Errorf("parse ar size: %w", err)
		}
		members = append(members, arHeader{Name: name, Size: size})
		if size%2 == 1 {
			size++
		}
		if _, err := io.CopyN(io.Discard, r, size); err != nil {
			return nil, err
		}
	}
	return members, nil
}

func openARMember(r io.ReadSeeker, memberName string) (io.Reader, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if string(magic[:]) != arGlobalHeader {
		return nil, fmt.Errorf("invalid ar archive")
	}

	for {
		var bh [60]byte
		if _, err := io.ReadFull(r, bh[:]); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(string(bh[0:16]))
		name = strings.TrimSuffix(name, "/")
		sizeStr := strings.TrimSpace(string(bh[48:58]))
		var size int64
		if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
			return nil, fmt.Errorf("parse ar size: %w", err)
		}
		if name == memberName {
			data := make([]byte, size)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("read ar member %q: %w", memberName, err)
			}
			return bytes.NewReader(data), nil
		}
		if size%2 == 1 {
			size++
		}
		if _, err := r.Seek(size, io.SeekCurrent); err != nil {
			return nil, err
		}
	}
}

func readARMemberNames(r io.Reader) ([]string, error) {
	members, err := readAR(r)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.Name)
	}
	return names, nil
}
