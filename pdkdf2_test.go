package jo

import (
	"github.com/stretchr/testify/assert"
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
