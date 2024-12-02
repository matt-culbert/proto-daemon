//go:build !withHttp || !withDns

package shared

import (
	"net/http"
	"net/url"
)

type noCommTag struct{}

func (m *noCommTag) Error() string {
	return "No comm method tags used at build"
}

// GetDataRequest empty default function to let you know you goofed
func GetDataRequest(baseUrl string, maxRetries int, params url.Values) (*http.Response, error) {
	return nil, &noCommTag{}
}

// SendDataRequest empty default function to let you know you goofed
func SendDataRequest(baseUrl string, params string) (*http.Response, error) {
	return nil, &noCommTag{}
}
