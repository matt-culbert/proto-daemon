package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
	"unicode"
)

// DecodeIPv6ToString takes a string formatted like an IPv6 address (e.g., ["7465:7374::"])
// and decodes it back into its original string representation.
func DecodeIPv6ToString(encoded string) (string, error) {
	// Remove all non-hexadecimal characters from the encoded string
	hexParts := strings.ReplaceAll(encoded, `"`, "")
	hexParts = strings.ReplaceAll(hexParts, `[`, "")
	hexParts = strings.ReplaceAll(hexParts, `]`, "")
	hexParts = strings.ReplaceAll(hexParts, `:`, "")
	hexParts = strings.ReplaceAll(hexParts, `,`, "")

	// Remove spaces and any non-hex characters explicitly
	hexParts = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || !unicode.Is(unicode.Hex_Digit, r) {
			return -1 // Skip non-hex characters
		}
		return r
	}, hexParts)

	// Pad the hex string if its length is odd
	if len(hexParts)%2 != 0 {
		hexParts = "0" + hexParts
	}

	// Decode the hex string into bytes
	result, err := hex.DecodeString(hexParts)
	if err != nil {
		return "", err
	}

	// Return the decoded string
	return string(result), nil
}

// VerifyMessageWithHMAC takes in a message, a received HMAC, and a secret key
// and returns true if the HMAC is valid for the message and secret key.
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

// GenerateAuthToken takes in a URI and PSK
// and returns an auth token to use when requesting commands
func GenerateAuthToken(uri, psk string) (string, string) {
	// Generate a timestamp (current Unix time as a string)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Create the message by combining URI and timestamp
	message := uri + ":" + timestamp

	// Generate HMAC using SHA-256 and the secret key
	h := hmac.New(sha256.New, []byte(psk))
	h.Write([]byte(message))
	token := hex.EncodeToString(h.Sum(nil))

	return token, timestamp
}

// GetSelfHash gets the hash of itself during run time
func GetSelfHash() []byte {
	// Get the path of the currently running executable
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}

	// Open the executable file
	exeFile, err := os.Open(exePath)
	if err != nil {
		log.Fatalf("Failed to open executable file: %v", err)
	}
	defer exeFile.Close()

	// Create a SHA-256 hasher and copy the file's contents into it
	hasher := sha256.New()
	if _, err := io.Copy(hasher, exeFile); err != nil {
		log.Fatalf("Failed to hash executable file: %v", err)
	}
	return hasher.Sum(nil)
}
