package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"

	"github.com/daeuniverse/outbound/common"
	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/dgryski/go-camellia"
	"github.com/dgryski/go-idea"
	"github.com/dgryski/go-rc2"
	"gitlab.com/yawning/chacha20.git"
	"golang.org/x/crypto/blowfish" // nolint:staticcheck
	"golang.org/x/crypto/cast5"    // nolint:staticcheck
	"golang.org/x/crypto/salsa20/salsa"
)

var errEmptyPassword = errors.New("empty key")

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newCTRStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCTRStream(block, err, key, iv, doe)
}

func newOFBStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewOFB(block, iv), nil // nolint:staticcheck
}

func newAESOFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newOFBStream(block, err, key, iv, doe)
}

func newCFBStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil // nolint:staticcheck
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil // nolint:staticcheck
	}
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.New(key, iv)
}

func newChacha20IETFStream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.New(key, iv)
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else {
		buf = pool.Get(dataSize)
		defer pool.Put(buf)
	}

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}

func newSalsa20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c, nil
}

func newCamelliaStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := camellia.New(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newIdeaStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := idea.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newRC2Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := rc2.New(key, 16)
	return newCFBStream(block, err, key, iv, doe)
}

func newRC4Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return rc4.NewCipher(key)
}

func newSeedStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	// TODO: SEED block cipher implementation is required
	block, err := rc2.New(key, 16)
	return newCFBStream(block, err, key, iv, doe)
}

type NoneStream struct {
	cipher.Stream
}

func (*NoneStream) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

func newNoneStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return new(NoneStream), nil
}

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var streamCipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":      {16, 16, newAESCFBStream},
	"aes-192-cfb":      {24, 16, newAESCFBStream},
	"aes-256-cfb":      {32, 16, newAESCFBStream},
	"aes-128-ctr":      {16, 16, newAESCTRStream},
	"aes-192-ctr":      {24, 16, newAESCTRStream},
	"aes-256-ctr":      {32, 16, newAESCTRStream},
	"aes-128-ofb":      {16, 16, newAESOFBStream},
	"aes-192-ofb":      {24, 16, newAESOFBStream},
	"aes-256-ofb":      {32, 16, newAESOFBStream},
	"des-cfb":          {8, 8, newDESStream},
	"bf-cfb":           {16, 8, newBlowFishStream},
	"cast5-cfb":        {16, 8, newCast5Stream},
	"rc4-md5":          {16, 16, newRC4MD5Stream},
	"rc4-md5-6":        {16, 6, newRC4MD5Stream},
	"chacha20":         {32, 8, newChaCha20Stream},
	"chacha20-ietf":    {32, 12, newChacha20IETFStream},
	"salsa20":          {32, 8, newSalsa20Stream},
	"camellia-128-cfb": {16, 16, newCamelliaStream},
	"camellia-192-cfb": {24, 16, newCamelliaStream},
	"camellia-256-cfb": {32, 16, newCamelliaStream},
	"idea-cfb":         {16, 8, newIdeaStream},
	"rc2-cfb":          {16, 8, newRC2Stream},
	"seed-cfb":         {16, 8, newSeedStream},
	"rc4":              {16, 0, newRC4Stream},
	"none":             {16, 0, newNoneStream},
	"plain":            {16, 0, newNoneStream},
}

type StreamCipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
	iv   []byte
}

// NewStreamCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Clone() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewStreamCipher(method, password string) (c *StreamCipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	if method == "" {
		method = "rc4-md5"
	}
	mi, ok := streamCipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := common.EVPBytesToKey(password, mi.keyLen)

	c = &StreamCipher{key: key, info: mi}

	return c, nil
}

func (c *StreamCipher) EncryptInited() bool {
	return c.enc != nil
}

func (c *StreamCipher) DecryptInited() bool {
	return c.dec != nil
}

// InitEncrypt initializes the block cipher with CFB mode, returns IV.
func (c *StreamCipher) InitEncrypt() (iv []byte, err error) {
	if c.EncryptInited() {
		return c.iv, nil
	}
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		_, _ = rand.Read(iv)
		c.iv = iv
	} else {
		iv = c.iv
	}
	if c.enc, err = c.info.newStream(c.key, iv, Encrypt); err != nil {
		return nil, err
	}
	return iv, nil
}

func (c *StreamCipher) NewEncryptor(iv []byte) (enc cipher.Stream, err error) {
	if iv == nil {
		iv = pool.Get(c.info.ivLen)
		defer pool.Put(iv)
	}
	iv = iv[:c.info.ivLen]
	_, _ = rand.Read(iv)
	return c.info.newStream(c.key, iv, Encrypt)
}

func (c *StreamCipher) InitDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return err
}

func (c *StreamCipher) NewDecryptor(iv []byte) (dec cipher.Stream, err error) {
	return c.info.newStream(c.key, iv, Decrypt)
}

func (c *StreamCipher) Encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *StreamCipher) Decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

// Clone creates a new cipher at it's initial state.
func (c *StreamCipher) Clone() *StreamCipher {
	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.

	// AES and DES ciphers does not return specific types, so it's difficult
	// to create copy. But their initialization time is less than 4000ns on my
	// 2.26 GHz Intel Core 2 Duo processor. So no need to worry.

	// Currently, blow-fish and cast5 initialization cost is an order of
	// magnitude slower than other ciphers. (I'm not sure whether this is
	// because the current implementation is not highly optimized, or this is
	// the nature of the algorithm.)

	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}

func (c *StreamCipher) Key() []byte {
	return c.key
}

func (c *StreamCipher) IV() []byte {
	return c.iv
}

func (c *StreamCipher) SetIV(iv []byte) {
	c.iv = iv
}

func (c *StreamCipher) SetKey(key []byte) {
	c.key = key
}

func (c *StreamCipher) InfoIVLen() int {
	return c.info.ivLen
}

func (c *StreamCipher) InfoKeyLen() int {
	return c.info.keyLen
}
