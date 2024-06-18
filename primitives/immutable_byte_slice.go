package primitives

import (
	"bytes"
)

type ImmutableByteSlice struct {
	data []byte
}

func (u *ImmutableByteSlice) Equal(other []byte) bool {
	return bytes.Equal(u.data, other)
}

func NewImmutableByteSlice(data []byte) *ImmutableByteSlice {
	return &ImmutableByteSlice{data: data}
}
