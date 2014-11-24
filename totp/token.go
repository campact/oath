package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"time"
)

const (
	VERSION = "1.0.0"
)

type Token struct {
	key      []byte
	epoch    time.Time
	interval time.Duration
	hash     func() hash.Hash
}

func New(key []byte) Token {
	token := Token{
		key:      key,
		epoch:    time.Unix(0, 0).UTC(),
		interval: 30 * time.Second,
		hash:     sha256.New,
	}
	return token
}

func NewHashToken(key []byte, h func() hash.Hash) Token {
	token := New(key)
	token.hash = h
	return token
}

func (token Token) Generate(t time.Time, length int) string {
	c := (t.Unix() - token.epoch.Unix()) / int64(token.interval.Seconds())
	h := hmac.New(token.hash, token.key)

	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, c)
	h.Write(b.Bytes())

	v := h.Sum(nil)
	o := v[len(v)-1] & 0xf
	val := (int32(v[o]&0x7f)<<24 |
		int32(v[o+1])<<16 |
		int32(v[o+2])<<8 |
		int32(v[o+3])) % 1000000000

	return fmt.Sprintf("%010d", val)[10-length : 10]
}

func (t Token) String() string {
	return t.Generate(time.Now().UTC(), 6)
}
