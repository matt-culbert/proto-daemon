//go:build withComp

package shared

import (
	"bytes"
	"compress/zlib"
)

func DoComp(data string) (bytes.Buffer, bool) {
	// Create a buffer to hold the compressed data
	var compressedData bytes.Buffer

	// Create a new zlib writer with the buffer as the output
	writer := zlib.NewWriter(&compressedData)

	// Compress the data
	_, err := writer.Write([]byte(data))
	if err != nil {
		// Return uncompressed data in case of an error
		return *bytes.NewBufferString(data), false
	}

	// Close the writer to finalize compression
	writer.Close()

	// Return the compressed data
	return compressedData, true
}
