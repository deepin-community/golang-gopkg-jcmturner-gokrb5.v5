// Package mstypes implements representations of Microsoft types for PAC processing.
package mstypes

import (
	"encoding/binary"
	"time"

	"gopkg.in/jcmturner/rpc.v0/ndr"
)

const unixEpochDiff = 116444736000000000

// FileTime implements the Microsoft FILETIME type https://msdn.microsoft.com/en-us/library/cc230324.aspx
type FileTime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// Time return a golang Time type from the FileTime
func (ft FileTime) Time() time.Time {
	ns := (ft.MSEpoch() - unixEpochDiff) * 100
	return time.Unix(0, int64(ns)).UTC()
}

// MSEpoch returns the FileTime as a Microsoft epoch, the number of 100 nano second periods elapsed from January 1, 1601 UTC.
func (ft FileTime) MSEpoch() int64 {
	return (int64(ft.HighDateTime) << 32) + int64(ft.LowDateTime)
}

// Unix returns the FileTime as a Unix time, the number of seconds elapsed since January 1, 1970 UTC.
func (ft FileTime) Unix() int64 {
	return (ft.MSEpoch() - unixEpochDiff) / 10000000
}

// GetFileTime returns a FileTime type from the provided Golang Time type.
func GetFileTime(t time.Time) FileTime {
	ns := t.UnixNano()
	fp := (ns / 100) + unixEpochDiff
	hd := fp >> 32
	ld := fp - (hd << 32)
	return FileTime{
		LowDateTime:  uint32(ld),
		HighDateTime: uint32(hd),
	}
}

// ReadFileTime reads a FileTime from the bytes slice.
func ReadFileTime(b *[]byte, p *int, e *binary.ByteOrder) FileTime {
	l := ndr.ReadUint32(b, p, e)
	h := ndr.ReadUint32(b, p, e)
	return FileTime{
		LowDateTime:  l,
		HighDateTime: h,
	}
}
