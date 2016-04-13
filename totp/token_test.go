package totp_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"time"

	"github.com/campact/oath/totp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Token", func() {
	var key []byte
	var secret1 []byte
	var secret256 []byte
	var secret512 []byte
	type vector struct {
		Key   []byte
		Time  string
		Hash  func() hash.Hash
		Token string
	}
	var vectors []vector

	BeforeEach(func() {
		secret1 = make([]byte, hex.EncodedLen(20))
		secret256 = make([]byte, hex.EncodedLen(32))
		secret512 = make([]byte, hex.EncodedLen(64))

		key = bytes.Repeat([]byte("1234567890"), 7)
		secret1 = key[:20]
		secret256 = key[:32]
		secret512 = key[:64]
		vectors = []vector{
			{secret1, "1970-01-01T00:00:59Z", sha1.New, "94287082"},
			{secret256, "1970-01-01T00:00:59Z", sha256.New, "46119246"},
			{secret512, "1970-01-01T00:00:59Z", sha512.New, "90693936"},
			{secret1, "2005-03-18T01:58:29Z", sha1.New, "07081804"},
			{secret256, "2005-03-18T01:58:29Z", sha256.New, "68084774"},
			{secret512, "2005-03-18T01:58:29Z", sha512.New, "25091201"},
			{secret1, "2005-03-18T01:58:31Z", sha1.New, "14050471"},
			{secret256, "2005-03-18T01:58:31Z", sha256.New, "67062674"},
			{secret512, "2005-03-18T01:58:31Z", sha512.New, "99943326"},
			{secret1, "2009-02-13T23:31:30Z", sha1.New, "89005924"},
			{secret256, "2009-02-13T23:31:30Z", sha256.New, "91819424"},
			{secret512, "2009-02-13T23:31:30Z", sha512.New, "93441116"},
			{secret1, "2033-05-18T03:33:20Z", sha1.New, "69279037"},
			{secret256, "2033-05-18T03:33:20Z", sha256.New, "90698825"},
			{secret512, "2033-05-18T03:33:20Z", sha512.New, "38618901"},
			{secret1, "2603-10-11T11:33:20Z", sha1.New, "65353130"},
			{secret256, "2603-10-11T11:33:20Z", sha256.New, "77737706"},
			{secret512, "2603-10-11T11:33:20Z", sha512.New, "47863826"},
		}
	})

	It("should pass RFC 6238 test vectors", func() {
		for i, v := range vectors {
			token := totp.NewHashToken(v.Key, v.Hash)
			t, err := time.Parse(time.RFC3339, v.Time)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(token.Generate(t.UTC(), len(v.Token))).Should(Equal(v.Token), "vector #%d failed", i+1)
		}
	})
})
