package primitives

import (
	"bytes"
)

type UnmodifiableByteSlice struct {
    data []byte
}

func (u *UnmodifiableByteSlice) Equal(other []byte) bool {
	return bytes.Equal(u.data, other)
}

func NewUnmodifiableByteSlice(data []byte) *UnmodifiableByteSlice {
	return &UnmodifiableByteSlice{data: data}
}