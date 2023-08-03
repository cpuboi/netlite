package tools

import (
	"encoding/binary"
	"hash/fnv"
)

// Converts a string to a uint64
func StringToFnvUint64(s string) uint64 {
	f := fnv.New64()   // Create new fnv hash
	f.Write([]byte(s)) // Insert string, convert to bytes
	bs := f.Sum(nil)
	return binary.BigEndian.Uint64(bs) // Return a Uint64
}
