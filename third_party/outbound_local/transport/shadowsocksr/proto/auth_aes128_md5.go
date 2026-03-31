package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/common"
	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	swBytes "github.com/daeuniverse/outbound/pool/bytes"
)

func init() {
	register("auth_aes128_md5", NewAuthAES128MD5)
}

func NewAuthAES128MD5() IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_md5",
		hmac:       common.HmacMD5,
		hashDigest: common.MD5Sum,
		packID:     1,
		recvInfo: recvInfo{
			recvID: 1,
			buffer: new(swBytes.Buffer),
		},
	}
	return a
}

type recvInfo struct {
	recvID uint32
	buffer *swBytes.Buffer
}

type authAES128 struct {
	*ServerInfo
	recvInfo
	data          *AuthData
	hasSentHeader bool
	packID        uint32
	userKey       []byte
	uid           [4]byte
	salt          string
	hmac          hmacMethod
	hashDigest    hashDigestMethod
}

func (a *authAES128) InitWithServerInfo(s *ServerInfo) {
	a.ServerInfo = s
	a.initUser()
}

func (a *authAES128) SetData(data interface{}) {
	if auth, ok := data.(*AuthData); ok {
		a.data = auth
	}
}

func (a *authAES128) GetData() interface{} {
	if a.data == nil {
		a.data = &AuthData{}
	}
	return a.data
}

func (a *authAES128) packData(data []byte) (outData []byte) {
	dataLength := len(data)
	randLength := 1

	if dataLength <= 1200 {
		if a.packID > 4 {
			randLength += rand.Intn(32)
		} else {
			if dataLength > 900 {
				randLength += rand.Intn(128)
			} else {
				randLength += rand.Intn(512)
			}
		}
	}

	outLength := randLength + dataLength + 8
	outData = make([]byte, outLength)
	// 0~1, out length
	binary.LittleEndian.PutUint16(outData[0:], uint16(outLength&0xFFFF))
	// 2~3, hmac
	key := make([]byte, len(a.userKey)+4)
	copy(key, a.userKey)
	binary.LittleEndian.PutUint32(key[len(key)-4:], a.packID)
	h := a.hmac(key, outData[0:2])
	copy(outData[2:4], h[:2])
	// 4~rand length+4, rand number
	_, _ = rand.Read(outData[4 : 4+randLength])
	// 4, rand length
	if randLength < 128 {
		outData[4] = byte(randLength & 0xFF)
	} else {
		// 4, magic number 0xFF
		outData[4] = 0xFF
		// 5~6, rand length
		binary.LittleEndian.PutUint16(outData[5:], uint16(randLength&0xFFFF))
	}
	// rand length+4~out length-4, data
	if dataLength > 0 {
		copy(outData[randLength+4:], data)
	}
	a.packID++
	h = a.hmac(key, outData[:outLength-4])
	copy(outData[outLength-4:], h[:4])
	return
}

func (a *authAES128) initUser() {
	params := strings.Split(a.Param, ":")
	if len(params) >= 2 {
		if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
			binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
			a.userKey = a.hashDigest([]byte(params[1]))
		}
	}

	if a.userKey == nil {
		_, _ = rand.Read(a.uid[:])
		a.userKey = make([]byte, len(a.Key))
		copy(a.userKey, a.Key)
	}
}
func (a *authAES128) packAuthData(data []byte) (outData []byte) {
	dataLength := len(data)
	var randLength int

	if dataLength > 400 {
		randLength = rand.Intn(512)
	} else {
		randLength = rand.Intn(1024)
	}

	dataOffset := randLength + 16 + 4 + 4 + 7
	outLength := dataOffset + dataLength + 4
	outData = make([]byte, outLength)
	encrypt := make([]byte, 24)
	key := make([]byte, len(a.IV)+len(a.Key))
	copy(key, a.IV)
	copy(key[len(a.IV):], a.Key)

	_, _ = rand.Read(outData[dataOffset-randLength:])
	a.data.connectionID++
	if a.data.connectionID > 0xFF000000 {
		a.data.clientID = nil
	}
	if len(a.data.clientID) == 0 {
		a.data.clientID = make([]byte, 8)
		_, _ = rand.Read(a.data.clientID)
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		a.data.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	copy(encrypt[4:], a.data.clientID)
	binary.LittleEndian.PutUint32(encrypt[8:], a.data.connectionID)

	now := time.Now().Unix()
	binary.LittleEndian.PutUint32(encrypt[0:4], uint32(now))

	binary.LittleEndian.PutUint16(encrypt[12:], uint16(outLength&0xFFFF))
	binary.LittleEndian.PutUint16(encrypt[14:], uint16(randLength&0xFFFF))

	aesCipherKey := common.EVPBytesToKey(base64.StdEncoding.EncodeToString(a.userKey)+a.salt, 16)
	block, err := aes.NewCipher(aesCipherKey)
	if err != nil {
		return nil
	}
	encryptData := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encryptData, encrypt[:16])
	copy(encrypt[:4], a.uid[:])
	copy(encrypt[4:4+16], encryptData)

	h := a.hmac(key, encrypt[0:20])
	copy(encrypt[20:], h[:4])

	_, _ = rand.Read(outData[0:1])
	h = a.hmac(key, outData[0:1])
	copy(outData[1:], h[0:7-1])

	copy(outData[7:], encrypt)
	copy(outData[dataOffset:], data)

	h = a.hmac(a.userKey, outData[0:outLength-4])
	copy(outData[outLength-4:], h[:4])

	return
}

func (a *authAES128) EncodePkt(buf *swBytes.Buffer) (err error) {
	_, _ = buf.Write(a.uid[:])
	_, _ = buf.Write(a.hmac(a.userKey, buf.Bytes())[:4])
	return nil
}

func (a *authAES128) DecodePkt(in []byte) (out pool.Bytes, err error) {
	if len(in) < 4 {
		return nil, ErrAuthAES128DataLengthError
	}
	if !bytes.Equal(a.hmac(a.Key, in[:len(in)-4])[:4], in[len(in)-4:]) {
		return nil, ErrAuthAES128IncorrectChecksum
	}
	return pool.B(in[:len(in)-4]), nil
}

func (a *authAES128) Encode(plainData []byte) (outData []byte, err error) {
	a.buffer.Reset()
	dataLength := len(plainData)
	offset := 0
	if dataLength > 0 && !a.hasSentHeader {
		authLength := dataLength
		if authLength > 1200 {
			authLength = 1200
		}
		a.hasSentHeader = true
		_, _ = a.buffer.Write(a.packAuthData(plainData[:authLength]))
		dataLength -= authLength
		offset += authLength
	}
	const blockSize = 4096
	for dataLength > blockSize {
		_, _ = a.buffer.Write(a.packData(plainData[offset : offset+blockSize]))
		dataLength -= blockSize
		offset += blockSize
	}
	if dataLength > 0 {
		_, _ = a.buffer.Write(a.packData(plainData[offset:]))
	}
	return a.buffer.Bytes(), nil
}

func (a *authAES128) Decode(plainData []byte) ([]byte, int, error) {
	a.buffer.Reset()
	plainLength := len(plainData)
	readlenth := 0
	key := make([]byte, len(a.userKey)+4)
	copy(key, a.userKey)
	for plainLength > 4 {
		binary.LittleEndian.PutUint32(key[len(key)-4:], a.recvID)

		h := a.hmac(key, plainData[0:2])
		if h[0] != plainData[2] || h[1] != plainData[3] {
			return nil, 0, ErrAuthAES128IncorrectHMAC
		}
		length := int(binary.LittleEndian.Uint16(plainData[0:2]))
		if length >= 8192 || length < 7 {
			return nil, 0, ErrAuthAES128DataLengthError
		}
		if length > plainLength {
			break
		}
		h = a.hmac(key, plainData[:length-4])
		if !bytes.Equal(h[:4], plainData[length-4:length]) {
			return nil, 0, ErrAuthAES128IncorrectChecksum
		}
		a.recvID++
		pos := int(plainData[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.LittleEndian.Uint16(plainData[5:7])) + 4
		}
		if pos > length-4 {
			return nil, 0, ErrAuthAES128PosOutOfRange
		}
		_, _ = a.buffer.Write(plainData[pos : length-4])
		plainData = plainData[length:]
		plainLength -= length
		readlenth += length
	}
	return a.buffer.Bytes(), readlenth, nil
}

func (a *authAES128) GetOverhead() int {
	return 9
}
