//go:build http

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/matt-culbert/dns-daemon/implant/shared"
)

// Function to load configuration from embedded JSON
func loadConfig() (Config, error) {
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

//go:embed config.json
var configData []byte // Embedded config data

// Config struct to hold configuration
type Config struct {
	listener string `json:"listener"`
	id       string `json:"id"`
	sleep    string `json:"sleep"`
}

func main() {
	// Load configuration from embedded data
	_, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

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

	// Compute the SHA-256 hash
	localHash := hasher.Sum(nil)

	url := "http://localhost:5000/1234"

	// Make the GET request
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error making GET request: %v", err)
	}
	fmt.Println("request made")
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Non-OK HTTP status: %s", resp.Status)
	}
	fmt.Println("response received")

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}
	fmt.Println("body read")

	// Print the response status and body
	fmt.Println("Response Status:", resp.Status)
	fmt.Println("Response Body:", string(body))

	decoded, _ := shared.DecodeIPv6ToString(string(body))
	fmt.Println("Decoded string:", decoded)
	fmt.Println(localHash)
	/*
		// Example message and HMAC to verify
		message := "Hello, World!"
		receivedHMAC := "ab4bc3d4e2f29c6f" // Replace with actual HMAC in hex or base64 format

		if shared.VerifyMessageWithHMAC(message, receivedHMAC, localHash) {
			fmt.Println("HMAC is valid!")
		} else {
			fmt.Println("HMAC is invalid or message was tampered with.")
		}
	*/
}
