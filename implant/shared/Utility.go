package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// DecodeIPv6ToString takes a string formatted like an IPv6 address (e.g., "7465:7374::")
// and decodes it back into its original string representation.
func DecodeIPv6ToString(encoded string) (string, error) {

	// Remove all non-hexadecimal characters from the encoded string
	hexParts := strings.ReplaceAll(encoded, `"`, "")
	hexParts = strings.ReplaceAll(hexParts, `[`, "")
	hexParts = strings.ReplaceAll(hexParts, `]`, "")
	hexParts = strings.ReplaceAll(hexParts, `:`, "")
	result, _ := hex.DecodeString(hexParts)

	// Return the decoded string
	return string(result), nil
}

func VerifyMessageWithHMAC(message, receivedHMAC string, secretKey []byte) bool {
	// Create a new HMAC object using SHA-256
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(message))
	computedHMAC := h.Sum(nil)

	// Decode the received HMAC from hexadecimal
	receivedHMACBytes, err := hex.DecodeString(receivedHMAC)
	if err != nil {
		fmt.Println("Error decoding HMAC:", err)
		return false
	}

	// Use hmac.Equal to securely compare the computed HMAC with the received HMAC
	return hmac.Equal(computedHMAC, receivedHMACBytes)
}
