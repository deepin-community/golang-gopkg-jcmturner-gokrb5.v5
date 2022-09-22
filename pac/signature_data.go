package pac

import (
	"encoding/binary"

	"gopkg.in/jcmturner/gokrb5.v5/iana/chksumtype"
	"gopkg.in/jcmturner/rpc.v0/ndr"
)

/*
https://msdn.microsoft.com/en-us/library/cc237955.aspx
*/

// SignatureData implements https://msdn.microsoft.com/en-us/library/cc237955.aspx
type SignatureData struct {
	SignatureType  uint32
	Signature      []byte
	RODCIdentifier uint16
}

// Unmarshal bytes into the SignatureData struct
func (k *SignatureData) Unmarshal(b []byte) ([]byte, error) {
	var p int
	var e binary.ByteOrder = binary.LittleEndian

	k.SignatureType = ndr.ReadUint32(&b, &p, &e)
	var c int
	switch k.SignatureType {
	case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
		c = 16
	case uint32(chksumtype.HMAC_SHA1_96_AES128):
		c = 12
	case uint32(chksumtype.HMAC_SHA1_96_AES256):
		c = 12
	}
	sp := p
	k.Signature = ndr.ReadBytes(&b, &p, c, &e)
	k.RODCIdentifier = ndr.ReadUint16(&b, &p, &e)

	//Check that there is only zero padding left
	for _, v := range b[p:] {
		if v != 0 {
			return []byte{}, ndr.Malformed{EText: "non-zero padding left over at end of data stream"}
		}
	}

	// Create bytes with zeroed signature needed for checksum verification
	rb := make([]byte, len(b), len(b))
	copy(rb, b)
	z := make([]byte, len(b), len(b))
	copy(rb[sp:sp+c], z)

	return rb, nil
}
