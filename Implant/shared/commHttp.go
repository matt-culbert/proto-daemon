//go:build withHttp

package shared

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// GetDataRequest makes a GET request to the given URL
// It takes in 3 parameters
// 1) The base URL to make the request to
// 2) The maximum number of retries before giving up
// 3) The query parameters to include in the request
// It returns the response and any error that occurred
func GetDataRequest(baseUrl string, maxRetries int, cookies ...*http.Cookie) (*http.Response, error) {
	var resp *http.Response
	var err error

	// Parse the base URL
	reqURL, err := url.Parse(baseUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Create an HTTP client
	client := &http.Client{}

	for attempts := 0; attempts < maxRetries; attempts++ {
		// Create a new request for each attempt
		req, err := http.NewRequest("GET", reqURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Add cookies to the request
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		// Send the request
		resp, err = client.Do(req)
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

// SendDataRequest makes a POST request to the given URL
// It takes in 3 parameters
// 1) The base URL to make the request to
// 2) The params of the message
// It returns the response and any error that occurred
func SendDataRequest(baseUrl string, params string) (*http.Response, error) {
	reqURL, _ := url.Parse(baseUrl)
	// Create the data payload
	data := map[string]string{
		"msg": params,
	}

	// Marshal the data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Send the HTTP POST request
	resp, err := http.Post(reqURL.String(), "application/json", bytes.NewBuffer(jsonData))

	if err != nil {
		return nil, fmt.Errorf("error sending POST request: %v", err)
	}

	return resp, nil
}
