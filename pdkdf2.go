package jo

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
)

const (
	defaultHashFunc       = Kdf_SHA3_256
	defaultSaltLen  int   = 64
	defaultKeyLen   int64 = 256
	defaultIter     int64 = 4096
)

type Option func(*Kdf)

var (
	ErrNilData    = errors.New("jo: Pass or Hash cannot be nil")
	ErrMismatched = errors.New("jo: No match found")
)

var hashMap = map[Kdf_HashAlg]func() hash.Hash{
	Kdf_SHA256:   sha256.New,
	Kdf_SHA512:   sha512.New,
	Kdf_SHA3_224: sha3.New224,
	Kdf_SHA3_256: sha3.New256,
	Kdf_SHA3_384: sha3.New384,
	Kdf_SHA3_512: sha3.New512,
}

func New(pass []byte, opts ...Option) ([]byte, error) {
	if len(pass) == 0 {
		return nil, ErrNilData
	}
	k := &Kdf{KeyLen: defaultKeyLen, Iter: defaultIter, Alg: defaultHashFunc}
	for _, opt := range opts {
		opt(k)
	}
	if len(k.Salt) == 0 {
		WithSaltLen(defaultSaltLen)(k)
	}
	k.Key = pbkdf2.Key(pass, k.Salt, int(k.Iter), int(k.KeyLen), hashMap[k.Alg])
	return proto.Marshal(k)
}

func CompareHashAndPassword(hash, pass []byte) error {
	if len(hash) == 0 || len(pass) == 0 {
		return ErrNilData
	}
	kdf := new(Kdf)
	if err := proto.Unmarshal(hash, kdf); err != nil {
		return err
	}
	key := pbkdf2.Key(pass, kdf.Salt, int(kdf.Iter), int(kdf.KeyLen), hashMap[kdf.Alg])
	if !bytes.Equal(kdf.Key, key) {
		return ErrMismatched
	}
	return nil
}

//WithKeyLen sets the length of the pbkdf2 key
func WithKeyLen(len int64) Option { return func(obj *Kdf) { obj.KeyLen = len } }

//WithSalt sets the key salt
//IMPORTANT! Do not use with WithSaltLen
func WithSalt(salt []byte) Option { return func(obj *Kdf) { obj.Salt = salt } }

//WithSaltLen sets the length to generate key salt
//IMPORTANT! Do not use with WithSalt
func WithSaltLen(len int) Option { return func(obj *Kdf) { WithSalt(randomKey(len)) } }

func randomKey(len int) []byte {
	key := make([]byte, len)
	_, _ = io.ReadAtLeast(rand.Reader, key, len)
	return key
}
