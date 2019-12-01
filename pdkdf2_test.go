package jo

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
	"hash"
	"testing"
)

func TestNewAndCompare(t *testing.T) {
	tests := []struct {
		name           string
		pass           []byte
		opts           []Option
		wantErrNew     bool
		wantErrCompare bool
	}{
		{
			name:           "empty pass",
			pass:           nil,
			wantErrNew:     true,
			wantErrCompare: true,
		},
		{
			name:           "successful",
			pass:           []byte("test"),
			wantErrNew:     false,
			wantErrCompare: false,
		},
		{
			name: "successful with custom params",
			pass: []byte("test"),
			opts: []Option{
				WithSalt([]byte("salt")),
				WithHmacKey([]byte("hmac-key")),
				WithKeyLen(10),
			},
			wantErrNew:     false,
			wantErrCompare: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.pass, tt.opts...)
			if tt.wantErrNew {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			err = CompareHashAndPassword(got, tt.pass)
			if tt.wantErrCompare {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
func TestCompareHashAndPassword(t *testing.T) {
	type args struct {
		hash []byte
		pass []byte
	}
	testHash := []byte("test-hash")
	testPass := []byte("test-pass")
	checkPass := []byte("best-pass")
	bytes, _ := New(checkPass)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty pass and hash",
			args: args{
				hash: nil,
				pass: nil,
			},
			wantErr: true,
		},
		{
			name: "empty pass but filled hash",
			args: args{
				hash: testHash,
				pass: nil,
			},
			wantErr: true,
		},
		{
			name: "empty hash but filled pass",
			args: args{
				hash: nil,
				pass: testPass,
			},
			wantErr: true,
		},
		{
			name: "not protobuf data",
			args: args{
				hash: testHash,
				pass: testPass,
			},
			wantErr: true,
		},
		{
			name: "data mismatch",
			args: args{
				hash: bytes,
				pass: testPass,
			},
			wantErr: true,
		},
		{
			name: "successful",
			args: args{
				hash: bytes,
				pass: checkPass,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CompareHashAndPassword(tt.args.hash, tt.args.pass)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type structTestHfArgs struct {
	f Kdf_HashAlg
	k []byte
}

type structTestHf struct {
	name string
	args struct {
		f Kdf_HashAlg
		k []byte
	}
	want hash.Hash
}

func wrapHmacNew(h func() hash.Hash, k []byte) hash.Hash { return hmac.New(h, k) }

func newStructTestHf(k Kdf_HashAlg, h func() hash.Hash) structTestHf {
	key := []byte(k.String())
	return structTestHf{
		name: k.String(),
		args: structTestHfArgs{f: k, k: key},
		want: wrapHmacNew(h, key),
	}
}

func Test_hf(t *testing.T) {
	tests := []structTestHf{
		newStructTestHf(Kdf_SHA256, sha256.New),
		newStructTestHf(Kdf_SHA512, sha512.New),
		newStructTestHf(Kdf_SHA3_224, sha3.New224),
		newStructTestHf(Kdf_SHA3_256, sha3.New256),
		newStructTestHf(Kdf_SHA3_384, sha3.New384),
		newStructTestHf(Kdf_SHA3_512, sha3.New512),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hf(tt.args.f, tt.args.k)()
			assert.Equal(t, got, tt.want)
		})
	}
}
