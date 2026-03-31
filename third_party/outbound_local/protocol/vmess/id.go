package vmess

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"github.com/google/uuid"
	"hash"
)

const (
	IDBytesLen = 16
)

type IDHash func(key []byte) hash.Hash

func DefaultIDHash(key []byte) hash.Hash {
	return hmac.New(md5.New, key)
}

// The ID of en entity, in the form of a UUID.
type ID struct {
	uuid   uuid.UUID
	cmdKey [IDBytesLen]byte
}

// Equals returns true if this ID equals to the other one.
func (id *ID) Equals(another *ID) bool {
	if id == another {
		return true
	}
	a, _ := another.uuid.MarshalBinary()
	b, _ := id.uuid.MarshalBinary()
	return bytes.Equal(a, b)
}

func (id *ID) Bytes() []byte {
	b, _ := id.uuid.MarshalBinary()
	return b
}

func (id *ID) String() string {
	return id.uuid.String()
}

func (id *ID) UUID() uuid.UUID {
	return id.uuid
}

func (id *ID) CmdKey() []byte {
	return id.cmdKey[:]
}

// NewID returns an ID with given UUID.
func NewID(uuid uuid.UUID) *ID {
	id := &ID{uuid: uuid}
	md5hash := md5.New()
	b, _ := uuid.MarshalBinary()
	md5hash.Write(b)
	md5hash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	md5hash.Sum(id.cmdKey[:0])
	return id
}

func nextID(u *uuid.UUID) uuid.UUID {
	md5hash := md5.New()
	b, _ := u.MarshalBinary()
	md5hash.Write(b)
	md5hash.Write([]byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
	var newid uuid.UUID
	for {
		md5hash.Sum(newid[:0])
		a, _ := newid.MarshalBinary()
		if !bytes.Equal(a, b) {
			return newid
		}
		md5hash.Write([]byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"))
	}
}

func NewAlterIDs(primary *ID, alterIDCount uint16) []*ID {
	alterIDs := make([]*ID, alterIDCount)
	prevID := primary.UUID()
	for idx := range alterIDs {
		newid := nextID(&prevID)
		alterIDs[idx] = NewID(newid)
		prevID = newid
	}
	return alterIDs
}
