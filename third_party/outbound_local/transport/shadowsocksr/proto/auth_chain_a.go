// https://github.com/shadowsocksr-backup/shadowsocks-rss/blob/master/doc/auth_chain_a.md

package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	swBytes "github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/internal/crypto"
)

func init() {
	register("auth_chain_a", NewAuthChainA)
}

type authChainA struct {
	*ServerInfo
	randomClient crypto.Shift128plusContext
	randomServer crypto.Shift128plusContext
	recvInfo
	cipher         *ciphers.StreamCipher
	hasSentHeader  bool
	lastClientHash []byte
	lastServerHash []byte
	userKey        []byte
	userKeyLen     int
	uid            [4]byte
	salt           string
	data           *AuthData
	hmac           hmacMethod
	hashDigest     hashDigestMethod
	rnd            rndMethod
	rndPkt         pktRndMethod
	dataSizeList   []int
	dataSizeList2  []int
	chunkID        uint32
}

func NewAuthChainA() IProtocol {
	a := &authChainA{
		salt:       "auth_chain_a",
		hmac:       common.HmacMD5,
		hashDigest: common.SHA1Sum,
		rnd:        authChainAGetRandLen,
		rndPkt:     authChainAPktGetRandLen,
		recvInfo: recvInfo{
			recvID: 1,
			buffer: new(swBytes.Buffer),
		},
	}
	return a
}

func (a *authChainA) initUser() {
	params := strings.Split(a.Param, ":")
	if len(params) >= 2 {
		if userID, err := strconv.Atoi(params[0]); err == nil {
			binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
			a.userKeyLen = len(params[1])
			a.userKey = []byte(params[1])
		}
	}
	if a.userKey == nil {
		_, _ = rand.Read(a.uid[:])

		a.userKeyLen = len(a.Key)
		a.userKey = make([]byte, len(a.Key))
		copy(a.userKey, a.Key)
	}
}

func (a *authChainA) InitWithServerInfo(s *ServerInfo) {
	a.ServerInfo = s
	if a.salt == "auth_chain_b" {
		a.authChainBInitDataSize()
	}
	a.initUser()
}

func (a *authChainA) SetData(data interface{}) {
	if auth, ok := data.(*AuthData); ok {
		a.data = auth
	}
}

func (a *authChainA) GetData() interface{} {
	if a.data == nil {
		a.data = &AuthData{}
	}
	return a.data
}

func authChainAGetRandLen(dataLength int, random *crypto.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func getRandStartPos(random *crypto.Shift128plusContext, randLength int) int {
	if randLength > 0 {
		return int(random.Next() % 8589934609 % uint64(randLength))
	}
	return 0
}

func (a *authChainA) getClientRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomClient, a.lastClientHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChainA) getServerRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomServer, a.lastServerHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChainA) packedDataLen(data []byte) (chunkLength, randLength int) {
	dataLength := len(data)
	randLength = a.getClientRandLen(dataLength, a.Overhead)
	chunkLength = randLength + dataLength + 2 + 2
	return
}

func (a *authChainA) packData(outData []byte, data []byte, randLength int) {
	dataLength := len(data)
	outLength := randLength + dataLength + 2
	outData[0] = byte(dataLength) ^ a.lastClientHash[14]
	outData[1] = byte(dataLength>>8) ^ a.lastClientHash[15]

	{
		if dataLength > 0 {
			randPart1Length := getRandStartPos(&a.randomClient, randLength)
			_, _ = rand.Read(outData[2 : 2+randPart1Length])
			a.cipher.Encrypt(outData[2+randPart1Length:], data)
			_, _ = rand.Read(outData[2+randPart1Length+dataLength : outLength])
		} else {
			_, _ = rand.Read(outData[2 : 2+randLength])
		}
	}

	keyLen := a.userKeyLen + 4
	key := make([]byte, keyLen)
	copy(key, a.userKey)
	a.chunkID++
	binary.LittleEndian.PutUint32(key[a.userKeyLen:], a.chunkID)
	a.lastClientHash = a.hmac(key, outData[:outLength])
	copy(outData[outLength:], a.lastClientHash[:2])
}

const authheadLength = 4 + 8 + 4 + 16 + 4

func (a *authChainA) packAuthData(data []byte) (outData []byte) {
	outData = make([]byte, authheadLength, authheadLength+1500)
	a.data.connectionID++
	if a.data.connectionID > 0xFF000000 || a.data.clientID == nil {
		_, _ = rand.Read(a.data.clientID)
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		a.data.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	var key = make([]byte, len(a.IV)+len(a.Key))
	copy(key, a.IV)
	copy(key[len(a.IV):], a.Key)

	encrypt := make([]byte, 20)
	t := time.Now().Unix()
	binary.LittleEndian.PutUint32(encrypt[:4], uint32(t))
	copy(encrypt[4:8], a.data.clientID)
	binary.LittleEndian.PutUint32(encrypt[8:], a.data.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:], uint16(a.Overhead))
	binary.LittleEndian.PutUint16(encrypt[14:16], 0)

	// first 12 bytes
	{
		_, _ = rand.Read(outData[:4])
		a.lastClientHash = a.hmac(key, outData[:4])
		copy(outData[4:], a.lastClientHash[:8])
	}
	var base64UserKey string
	// uid & 16 bytes auth data
	{
		uid := make([]byte, 4)
		for i := 0; i < 4; i++ {
			uid[i] = a.uid[i] ^ a.lastClientHash[8+i]
		}
		base64UserKey = base64.StdEncoding.EncodeToString(a.userKey)
		aesCipherKey := common.EVPBytesToKey(base64UserKey+a.salt, 16)
		block, err := aes.NewCipher(aesCipherKey)
		if err != nil {
			return
		}
		encryptData := make([]byte, 16)
		iv := make([]byte, aes.BlockSize)
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(encryptData, encrypt[:16])
		copy(encrypt[:4], uid[:])
		copy(encrypt[4:4+16], encryptData)
	}
	// final HMAC
	{
		a.lastServerHash = a.hmac(a.userKey, encrypt[0:20])

		copy(outData[12:], encrypt)
		copy(outData[12+20:], a.lastServerHash[:4])
	}

	// init cipher
	password := make([]byte, len(base64UserKey)+base64.StdEncoding.EncodedLen(16))
	copy(password, base64UserKey)
	base64.StdEncoding.Encode(password[len(base64UserKey):], a.lastClientHash[:16])
	a.cipher, _ = ciphers.NewStreamCipher("rc4", string(password))
	_, _ = a.cipher.InitEncrypt()
	_ = a.cipher.InitDecrypt(nil)

	// data
	chunkLength, randLength := a.packedDataLen(data)
	if authheadLength+chunkLength <= cap(outData) {
		outData = outData[:authheadLength+chunkLength]
	} else {
		newOutData := make([]byte, authheadLength+chunkLength)
		copy(newOutData, outData[:authheadLength])
		outData = newOutData
	}
	a.packData(outData[authheadLength:], data, randLength)
	return outData
}

func authChainAPktGetRandLen(ctx *crypto.Shift128plusContext, lastHash []byte) int {
	ctx.InitFromBin(lastHash)
	return int(ctx.Next() % 127)
}

func (a *authChainA) EncodePkt(buf *swBytes.Buffer) (err error) {
	authData := pool.Get(3)
	defer pool.Put(authData)
	_, _ = rand.Read(authData)

	md5Data := a.hmac(a.Key, authData)

	randDataLength := a.rndPkt(&a.randomClient, md5Data)

	key := common.EVPBytesToKey(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return err
	}
	rc4Cipher.XORKeyStream(buf.Bytes(), buf.Bytes())

	buf.Extend(randDataLength)
	_, _ = rand.Read(buf.Bytes()[buf.Len()-randDataLength:])
	_, _ = buf.Write(a.uid[:])
	_ = binary.Write(buf, binary.LittleEndian, binary.LittleEndian.Uint32(a.uid[:])^binary.LittleEndian.Uint32(md5Data[:4]))
	_, _ = buf.Write(a.hmac(a.userKey, buf.Bytes())[:1])
	return nil
}

func (a *authChainA) DecodePkt(in []byte) (out pool.Bytes, err error) {
	if len(in) < 9 {
		return nil, ErrAuthChainDataLengthError
	}
	if !bytes.Equal(a.hmac(a.userKey, in[:len(in)-1])[:1], in[len(in)-1:]) {
		return nil, ErrAuthChainIncorrectHMAC
	}
	md5Data := a.hmac(a.Key, in[len(in)-8:len(in)-1])

	randDataLength := a.rndPkt(&a.randomServer, md5Data)

	key := common.EVPBytesToKey(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data := in[:len(in)-8-randDataLength]
	rc4Cipher.XORKeyStream(data, data)
	return pool.B(data), nil
}

func (a *authChainA) Encode(plainData []byte) (outData []byte, err error) {
	a.buffer.Reset()
	dataLength := len(plainData)
	offset := 0
	if dataLength > 0 && !a.hasSentHeader {
		headSize := 1200
		if headSize > dataLength {
			headSize = dataLength
		}
		_, _ = a.buffer.Write(a.packAuthData(plainData[:headSize]))
		offset += headSize
		dataLength -= headSize
		a.hasSentHeader = true
	}
	var unitSize = a.TcpMss - a.Overhead
	for dataLength > unitSize {
		dataLen, randLength := a.packedDataLen(plainData[offset : offset+unitSize])
		b := make([]byte, dataLen)
		a.packData(b, plainData[offset:offset+unitSize], randLength)
		_, _ = a.buffer.Write(b)
		dataLength -= unitSize
		offset += unitSize
	}
	if dataLength > 0 {
		dataLen, randLength := a.packedDataLen(plainData[offset:])
		b := make([]byte, dataLen)
		a.packData(b, plainData[offset:], randLength)
		_, _ = a.buffer.Write(b)
	}
	return a.buffer.Bytes(), nil
}

func (a *authChainA) Decode(plainData []byte) (outData []byte, n int, err error) {
	a.buffer.Reset()
	key := make([]byte, len(a.userKey)+4)
	readlenth := 0
	copy(key, a.userKey)
	for len(plainData) > 4 {
		binary.LittleEndian.PutUint32(key[len(a.userKey):], a.recvID)
		dataLen := (int)((uint(plainData[1]^a.lastServerHash[15]) << 8) + uint(plainData[0]^a.lastServerHash[14]))
		randLen := a.getServerRandLen(dataLen, a.Overhead)
		length := randLen + dataLen
		if length >= 4096 {
			return nil, 0, ErrAuthChainDataLengthError
		}
		length += 4
		if length > len(plainData) {
			break
		}

		hash := a.hmac(key, plainData[:length-2])
		if !bytes.Equal(hash[:2], plainData[length-2:length]) {
			return nil, 0, ErrAuthChainIncorrectHMAC
		}
		var dataPos int
		if dataLen > 0 && randLen > 0 {
			dataPos = 2 + getRandStartPos(&a.randomServer, randLen)
		} else {
			dataPos = 2
		}
		b := make([]byte, dataLen)
		a.cipher.Decrypt(b, plainData[dataPos:dataPos+dataLen])
		_, _ = a.buffer.Write(b)
		if a.recvID == 1 {
			a.TcpMss = int(binary.LittleEndian.Uint16(a.buffer.Next(2)))
		}
		a.lastServerHash = hash
		a.recvID++
		plainData = plainData[length:]
		readlenth += length

	}
	return a.buffer.Bytes(), readlenth, nil
}

func (a *authChainA) GetOverhead() int {
	return 4
}
