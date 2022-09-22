package mstypes

import (
	"encoding/binary"

	"gopkg.in/jcmturner/rpc.v0/ndr"
)

// RPCUnicodeString implements https://msdn.microsoft.com/en-us/library/cc230365.aspx
type RPCUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	BufferPrt     uint32
	Value         string
}

// ReadRPCUnicodeString reads a RPCUnicodeString from the bytes slice.
func ReadRPCUnicodeString(b *[]byte, p *int, e *binary.ByteOrder) (RPCUnicodeString, error) {
	l := ndr.ReadUint16(b, p, e)
	ml := ndr.ReadUint16(b, p, e)
	if ml < l || l%2 != 0 || ml%2 != 0 {
		return RPCUnicodeString{}, ndr.Malformed{EText: "Invalid data for RPC_UNICODE_STRING"}
	}
	ptr := ndr.ReadUint32(b, p, e)
	return RPCUnicodeString{
		Length:        l,
		MaximumLength: ml,
		BufferPrt:     ptr,
	}, nil
}

// UnmarshalString populates a golang string into the RPCUnicodeString struct.
func (s *RPCUnicodeString) UnmarshalString(b *[]byte, p *int, e *binary.ByteOrder) (err error) {
	s.Value, err = ndr.ReadConformantVaryingString(b, p, e)
	return
}
