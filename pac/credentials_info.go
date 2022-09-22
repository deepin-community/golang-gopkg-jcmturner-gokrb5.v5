package pac

import (
	"encoding/binary"
	"errors"
	"fmt"

	"gopkg.in/jcmturner/gokrb5.v5/crypto"
	"gopkg.in/jcmturner/gokrb5.v5/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v5/mstypes"
	"gopkg.in/jcmturner/gokrb5.v5/types"
	"gopkg.in/jcmturner/rpc.v0/ndr"
)

// https://msdn.microsoft.com/en-us/library/cc237931.aspx

// CredentialsInfo implements https://msdn.microsoft.com/en-us/library/cc237953.aspx
type CredentialsInfo struct {
	Version                    uint32
	EType                      uint32
	PACCredentialDataEncrypted []byte
	PACCredentialData          CredentialData
}

// Unmarshal bytes into the CredentialsInfo struct
func (c *CredentialsInfo) Unmarshal(b []byte, k types.EncryptionKey) error {
	//The CredentialsInfo structure is a simple structure that is not NDR-encoded.
	var p int
	var e binary.ByteOrder = binary.LittleEndian

	c.Version = ndr.ReadUint32(&b, &p, &e)
	if c.Version != 0 {
		return errors.New("credentials info version is not zero")
	}
	c.EType = ndr.ReadUint32(&b, &p, &e)
	c.PACCredentialDataEncrypted = ndr.ReadBytes(&b, &p, len(b)-p, &e)

	err := c.DecryptEncPart(k, &e)
	if err != nil {
		return fmt.Errorf("error decrypting PAC Credentials Data: %v", err)
	}
	return nil
}

// DecryptEncPart decrypts the encrypted part of the CredentialsInfo.
func (c *CredentialsInfo) DecryptEncPart(k types.EncryptionKey, e *binary.ByteOrder) error {
	if k.KeyType != int32(c.EType) {
		return fmt.Errorf("key provided is not the correct type. Type needed: %d, type provided: %d", c.EType, k.KeyType)
	}
	pt, err := crypto.DecryptMessage(c.PACCredentialDataEncrypted, k, keyusage.KERB_NON_KERB_SALT)
	if err != nil {
		return err
	}
	var p int
	c.PACCredentialData = ReadPACCredentialData(&pt, &p, e)
	return nil
}

// CredentialData implements https://msdn.microsoft.com/en-us/library/cc237952.aspx
type CredentialData struct {
	CredentialCount uint32
	Credentials     []SECPKGSupplementalCred // Size is the value of CredentialCount
}

// ReadPACCredentialData reads a CredentialData from the byte slice.
func ReadPACCredentialData(b *[]byte, p *int, e *binary.ByteOrder) CredentialData {
	c := ndr.ReadUint32(b, p, e)
	cr := make([]SECPKGSupplementalCred, c, c)
	for i := range cr {
		cr[i] = ReadSECPKGSupplementalCred(b, p, e)
	}
	return CredentialData{
		CredentialCount: c,
		Credentials:     cr,
	}
}

// SECPKGSupplementalCred implements https://msdn.microsoft.com/en-us/library/cc237956.aspx
type SECPKGSupplementalCred struct {
	PackageName    mstypes.RPCUnicodeString
	CredentialSize uint32
	Credentials    []uint8 // Is a ptr. Size is the value of CredentialSize
}

// ReadSECPKGSupplementalCred reads a SECPKGSupplementalCred from the byte slice.
func ReadSECPKGSupplementalCred(b *[]byte, p *int, e *binary.ByteOrder) SECPKGSupplementalCred {
	n, _ := mstypes.ReadRPCUnicodeString(b, p, e)
	cs := ndr.ReadUint32(b, p, e)
	c := make([]uint8, cs, cs)
	for i := range c {
		c[i] = ndr.ReadUint8(b, p)
	}
	return SECPKGSupplementalCred{
		PackageName:    n,
		CredentialSize: cs,
		Credentials:    c,
	}
}

// NTLMSupplementalCred implements https://msdn.microsoft.com/en-us/library/cc237949.aspx
type NTLMSupplementalCred struct {
	Version    uint32
	Flags      uint32
	LMPassword []byte
	NTPassword []byte
}

// ReadNTLMSupplementalCred reads a NTLMSupplementalCred from the byte slice.
func ReadNTLMSupplementalCred(b *[]byte, p *int, e *binary.ByteOrder) NTLMSupplementalCred {
	v := ndr.ReadUint32(b, p, e)
	f := ndr.ReadUint32(b, p, e)
	l := ndr.ReadBytes(b, p, 16, e)
	n := ndr.ReadBytes(b, p, 16, e)
	return NTLMSupplementalCred{
		Version:    v,
		Flags:      f,
		LMPassword: l,
		NTPassword: n,
	}
}

const (
	// NTLMSupCredLMOWF indicates that the LM OWF member is present and valid.
	NTLMSupCredLMOWF = 31
	// NTLMSupCredNTOWF indicates that the NT OWF member is present and valid.
	NTLMSupCredNTOWF = 30
)
