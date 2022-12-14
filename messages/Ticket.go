package messages

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"gopkg.in/jcmturner/gokrb5.v5/asn1tools"
	"gopkg.in/jcmturner/gokrb5.v5/crypto"
	"gopkg.in/jcmturner/gokrb5.v5/iana"
	"gopkg.in/jcmturner/gokrb5.v5/iana/adtype"
	"gopkg.in/jcmturner/gokrb5.v5/iana/asnAppTag"
	"gopkg.in/jcmturner/gokrb5.v5/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v5/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v5/keytab"
	"gopkg.in/jcmturner/gokrb5.v5/krberror"
	"gopkg.in/jcmturner/gokrb5.v5/pac"
	"gopkg.in/jcmturner/gokrb5.v5/types"
)

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.3

// Ticket implements the Kerberos ticket.
type Ticket struct {
	TktVNO           int                 `asn1:"explicit,tag:0"`
	Realm            string              `asn1:"generalstring,explicit,tag:1"`
	SName            types.PrincipalName `asn1:"explicit,tag:2"`
	EncPart          types.EncryptedData `asn1:"explicit,tag:3"`
	DecryptedEncPart EncTicketPart       `asn1:"optional"` // Not part of ASN1 bytes so marked as optional so unmarshalling works
}

// EncTicketPart is the encrypted part of the Ticket.
type EncTicketPart struct {
	Flags             asn1.BitString          `asn1:"explicit,tag:0"`
	Key               types.EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string                  `asn1:"generalstring,explicit,tag:2"`
	CName             types.PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding       `asn1:"explicit,tag:4"`
	AuthTime          time.Time               `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time               `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time               `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time               `asn1:"generalized,explicit,optional,tag:8"`
	CAddr             types.HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData types.AuthorizationData `asn1:"explicit,optional,tag:10"`
}

// TransitedEncoding part of the ticket's encrypted part.
type TransitedEncoding struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// NewTicket creates a new Ticket instance.
func NewTicket(cname types.PrincipalName, crealm string, sname types.PrincipalName, srealm string, flags asn1.BitString, sktab keytab.Keytab, eTypeID int32, kvno int, authTime, startTime, endTime, renewTill time.Time) (Ticket, types.EncryptionKey, error) {
	etype, err := crypto.GetEtype(eTypeID)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "error getting etype for new ticket")
	}
	ks := etype.GetKeyByteSize()
	kv := make([]byte, ks, ks)
	rand.Read(kv)
	sessionKey := types.EncryptionKey{
		KeyType:  eTypeID,
		KeyValue: kv,
	}
	etp := EncTicketPart{
		Flags:     flags,
		Key:       sessionKey,
		CRealm:    crealm,
		CName:     cname,
		Transited: TransitedEncoding{},
		AuthTime:  authTime,
		StartTime: startTime,
		EndTime:   endTime,
		RenewTill: renewTill,
	}
	b, err := asn1.Marshal(etp)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncodingError, "error marshalling ticket encpart")
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart)
	skey, err := sktab.GetEncryptionKey(sname.NameString, srealm, kvno, eTypeID)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "error getting encryption key for new ticket")
	}
	ed, err := crypto.GetEncryptedData(b, skey, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "error encrypting ticket encpart")
	}
	tkt := Ticket{
		TktVNO:  iana.PVNO,
		Realm:   srealm,
		SName:   sname,
		EncPart: ed,
	}
	return tkt, sessionKey, nil
}

// Unmarshal bytes b into a Ticket struct.
func (t *Ticket) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, t, fmt.Sprintf("application,explicit,tag:%d", asnAppTag.Ticket))
	return err
}

// Marshal the Ticket.
func (t *Ticket) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*t)
	if err != nil {
		return nil, err
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.Ticket)
	return b, nil
}

// Unmarshal bytes b into the EncTicketPart struct.
func (t *EncTicketPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, t, fmt.Sprintf("application,explicit,tag:%d", asnAppTag.EncTicketPart))
	return err
}

// UnmarshalTicket returns a ticket from the bytes provided.
func UnmarshalTicket(b []byte) (t Ticket, err error) {
	_, err = asn1.UnmarshalWithParams(b, &t, fmt.Sprintf("application,explicit,tag:%d", asnAppTag.Ticket))
	return
}

// UnmarshalTicketsSequence returns a slice of Tickets from a raw ASN1 value.
func UnmarshalTicketsSequence(in asn1.RawValue) ([]Ticket, error) {
	//This is a workaround to a asn1 decoding issue in golang - https://github.com/golang/go/issues/17321. It's not pretty I'm afraid
	//We pull out raw values from the larger raw value (that is actually the data of the sequence of raw values) and track our position moving along the data.
	b := in.Bytes
	// Ignore the head of the asn1 stream (1 byte for tag and those for the length) as this is what tells us its a sequence but we're handling it ourselves
	p := 1 + asn1tools.GetNumberBytesInLengthHeader(in.Bytes)
	var tkts []Ticket
	var raw asn1.RawValue
	for p < (len(b)) {
		_, err := asn1.UnmarshalWithParams(b[p:], &raw, fmt.Sprintf("application,tag:%d", asnAppTag.Ticket))
		if err != nil {
			return nil, fmt.Errorf("unmarshaling sequence of tickets failed geting length of ticket: %v", err)
		}
		t, err := UnmarshalTicket(b[p:])
		if err != nil {
			return nil, fmt.Errorf("unmarshaling sequence of tickets failed: %v", err)
		}
		p += len(raw.FullBytes)
		tkts = append(tkts, t)
	}
	MarshalTicketSequence(tkts)
	return tkts, nil
}

// MarshalTicketSequence marshals a slice of Tickets returning an ASN1 raw value containing the ticket sequence.
func MarshalTicketSequence(tkts []Ticket) (asn1.RawValue, error) {
	raw := asn1.RawValue{
		Class:      2,
		IsCompound: true,
	}
	if len(tkts) < 1 {
		// There are no tickets to marshal
		return raw, nil
	}
	var btkts []byte
	for i, t := range tkts {
		b, err := t.Marshal()
		if err != nil {
			return raw, fmt.Errorf("error marshaling ticket number %d in seqence of tickets", i+1)
		}
		btkts = append(btkts, b...)
	}
	btkts = append(asn1tools.MarshalLengthBytes(len(btkts)), btkts...)
	btkts = append([]byte{byte(32 + asn1.TagSequence)}, btkts...)
	raw.Bytes = btkts
	// If we need to create the full bytes then identifier octet is "context-specific" = 128 + "constructed" + 32 + the wrapping explicit tag (11)
	//fmt.Fprintf(os.Stderr, "mRaw fb: %v\n", raw.FullBytes)
	return raw, nil
}

// DecryptEncPart decrypts the encrypted part of the ticket.
func (t *Ticket) DecryptEncPart(keytab keytab.Keytab, ktprinc string) error {
	var upn types.PrincipalName
	realm := t.Realm
	if ktprinc != "" {
		var r string
		upn, r = types.ParseSPNString(ktprinc)
		if r != "" {
			realm = r
		}
	} else {
		upn = t.SName
	}
	key, err := keytab.GetEncryptionKey(upn.NameString, realm, t.EncPart.KVNO, t.EncPart.EType)
	if err != nil {
		return NewKRBError(t.SName, t.Realm, errorcode.KRB_AP_ERR_NOKEY, fmt.Sprintf("Could not get key from keytab: %v", err))
	}
	b, err := crypto.DecryptEncPart(t.EncPart, key, keyusage.KDC_REP_TICKET)
	if err != nil {
		return fmt.Errorf("error decrypting Ticket EncPart: %v", err)
	}
	var denc EncTicketPart
	err = denc.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("error unmarshaling encrypted part: %v", err)
	}
	t.DecryptedEncPart = denc
	return nil
}

// GetPACType returns a Microsoft PAC that has been extracted from the ticket and processed.
func (t *Ticket) GetPACType(keytab keytab.Keytab, ktprinc string) (bool, pac.PACType, error) {
	var isPAC bool
	for _, ad := range t.DecryptedEncPart.AuthorizationData {
		if ad.ADType == adtype.ADIfRelevant {
			var ad2 types.AuthorizationData
			err := ad2.Unmarshal(ad.ADData)
			if err != nil {
				continue
			}
			if ad2[0].ADType == adtype.ADWin2KPAC {
				isPAC = true
				var p pac.PACType
				err = p.Unmarshal(ad2[0].ADData)
				if err != nil {
					return isPAC, p, fmt.Errorf("error unmarshaling PAC: %v", err)
				}
				var upn []string
				if ktprinc != "" {
					upn = strings.Split(ktprinc, "/")
				} else {
					upn = t.SName.NameString
				}
				key, err := keytab.GetEncryptionKey(upn, t.Realm, t.EncPart.KVNO, t.EncPart.EType)
				if err != nil {
					return isPAC, p, NewKRBError(t.SName, t.Realm, errorcode.KRB_AP_ERR_NOKEY, fmt.Sprintf("Could not get key from keytab: %v", err))
				}
				err = p.ProcessPACInfoBuffers(key)
				return isPAC, p, err
			}
		}
	}
	return isPAC, pac.PACType{}, nil
}
