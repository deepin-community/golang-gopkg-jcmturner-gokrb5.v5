package pac

import (
	"fmt"

	"gopkg.in/jcmturner/gokrb5.v5/mstypes"
	"gopkg.in/jcmturner/rpc.v0/ndr"
)

// DeviceInfo implements https://msdn.microsoft.com/en-us/library/hh536402.aspx
type DeviceInfo struct {
	UserID            uint32
	PrimaryGroupID    uint32
	AccountDomainID   mstypes.RPCSID
	AccountGroupCount uint32
	AccountGroupIDs   []mstypes.GroupMembership
	SIDCount          uint32
	ExtraSIDs         []mstypes.KerbSidAndAttributes
	DomainGroupCount  uint32
	DomainGroup       []mstypes.DomainGroupMembership
}

// Unmarshal bytes into the DeviceInfo struct
func (k *DeviceInfo) Unmarshal(b []byte) error {
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.UserID = ndr.ReadUint32(&b, &p, e)
	k.PrimaryGroupID = ndr.ReadUint32(&b, &p, e)
	k.AccountDomainID, err = mstypes.ReadRPCSID(&b, &p, e)
	if err != nil {
		return err
	}
	k.AccountGroupCount = ndr.ReadUint32(&b, &p, e)
	if k.AccountGroupCount > 0 {
		ag := make([]mstypes.GroupMembership, k.AccountGroupCount, k.AccountGroupCount)
		for i := range ag {
			ag[i] = mstypes.ReadGroupMembership(&b, &p, e)
		}
		k.AccountGroupIDs = ag
	}

	k.SIDCount = ndr.ReadUint32(&b, &p, e)
	var ah ndr.ConformantArrayHeader
	if k.SIDCount > 0 {
		ah, err = ndr.ReadUniDimensionalConformantArrayHeader(&b, &p, e)
		if ah.MaxCount != int(k.SIDCount) {
			return fmt.Errorf("error with size of ExtraSIDs list. expected: %d, Actual: %d", k.SIDCount, ah.MaxCount)
		}
		es := make([]mstypes.KerbSidAndAttributes, k.SIDCount, k.SIDCount)
		attr := make([]uint32, k.SIDCount, k.SIDCount)
		ptr := make([]uint32, k.SIDCount, k.SIDCount)
		for i := range attr {
			ptr[i] = ndr.ReadUint32(&b, &p, e)
			attr[i] = ndr.ReadUint32(&b, &p, e)
		}
		for i := range es {
			if ptr[i] != 0 {
				s, err := mstypes.ReadRPCSID(&b, &p, e)
				es[i] = mstypes.KerbSidAndAttributes{SID: s, Attributes: attr[i]}
				if err != nil {
					return ndr.Malformed{EText: fmt.Sprintf("could not read ExtraSIDs: %v", err)}
				}
			}
		}
		k.ExtraSIDs = es
	}

	k.DomainGroupCount = ndr.ReadUint32(&b, &p, e)
	if k.DomainGroupCount > 0 {
		dg := make([]mstypes.DomainGroupMembership, k.DomainGroupCount, k.DomainGroupCount)
		for i := range dg {
			dg[i], _ = mstypes.ReadDomainGroupMembership(&b, &p, e)
		}
		k.DomainGroup = dg
	}

	//Check that there is only zero padding left
	if len(b) >= p {
		for _, v := range b[p:] {
			if v != 0 {
				return ndr.Malformed{EText: "non-zero padding left over at end of data stream"}
			}
		}
	}

	return nil
}
