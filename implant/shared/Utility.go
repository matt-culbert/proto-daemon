package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// DecodeIPv6ToString takes a string formatted like an IPv6 address (e.g., "7465:7374::")
// and decodes it back into its original string representation.
func DecodeIPv6ToString(encoded string) (string, error) {
	// Remove "::" placeholder, which represents a series of zeroes.
	// We assume "::" is only at the end or between sections of the address.
	encoded = strings.Replace(encoded, "::", ":", 1)

	// Split by the colon to get the hex pairs
	hexParts := strings.Split(encoded, ":")

	// Decode each hex part into a character and build the original string
	var result strings.Builder
	for _, part := range hexParts {
		if len(part) > 0 {
			// Convert the hex part into an integer
			decoded, err := strconv.ParseInt(part, 16, 64)
			if err != nil {
				return "", err
			}

			// Convert the integer to a byte and append it to the result
			result.WriteByte(byte(decoded))
		}
	}

	// Return the decoded string
	return result.String(), nil
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
