package pac

import (
	"encoding/binary"

	"gopkg.in/jcmturner/rpc.v0/ndr"
)

const (
	ulTypeKerbValidationInfo     = 1
	ulTypeCredentials            = 2
	ulTypePACServerSignatureData = 6
	ulTypePACKDCSignatureData    = 7
	ulTypePACClientInfo          = 10
	ulTypeS4UDelegationInfo      = 11
	ulTypeUPNDNSInfo             = 12
	ulTypePACClientClaimsInfo    = 13
	ulTypePACDeviceInfo          = 14
	ulTypePACDeviceClaimsInfo    = 15
)

// InfoBuffer implements the PAC Info Buffer: https://msdn.microsoft.com/en-us/library/cc237954.aspx
type InfoBuffer struct {
	ULType       uint32
	CBBufferSize uint32
	Offset       uint64
}

// ReadPACInfoBuffer reads a InfoBuffer from the byte slice.
func ReadPACInfoBuffer(b *[]byte, p *int, e *binary.ByteOrder) InfoBuffer {
	u := ndr.ReadUint32(b, p, e)
	s := ndr.ReadUint32(b, p, e)
	o := ndr.ReadUint64(b, p, e)
	return InfoBuffer{
		ULType:       u,
		CBBufferSize: s,
		Offset:       o,
	}
}
