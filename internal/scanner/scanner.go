package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type threatEntry struct {
	URL string `json:"url"`
}

type threatInfo struct {
	ThreatTypes      []string      `json:"threatTypes"`
	PlatformTypes    []string      `json:"platformTypes"`
	ThreatEntryTypes []string      `json:"threatEntryTypes"`
	ThreatEntries    []threatEntry `json:"threatEntries"`
}

type requestBody struct {
	Client struct {
		ClientID      string `json:"clientId"`
		ClientVersion string `json:"clientVersion"`
	} `json:"client"`
	ThreatInfo threatInfo `json:"threatInfo"`
}

// ValidateURL ensures the URL is correctly formatted
func ValidateURL(rawurl string) error {
	_, err := url.ParseRequestURI(rawurl)
	return err
}

// CheckURL uses the Google Safe Browsing API to check a URL
func CheckURL(apiKey, urlToCheck string) (bool, error) {
	err := ValidateURL(urlToCheck)
	if err != nil {
		return false, fmt.Errorf("Invalid URL: %v", err)
	}

	reqBody := requestBody{}
	reqBody.Client.ClientID = "url-safety-scanner"
	reqBody.Client.ClientVersion = "1.0"
	reqBody.ThreatInfo = threatInfo{
		ThreatTypes:      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
		PlatformTypes:    []string{"ANY_PLATFORM"},
		ThreatEntryTypes: []string{"URL"},
		ThreatEntries:    []threatEntry{{URL: urlToCheck}},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return false, err
	}

	apiURL := fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", apiKey)
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if len(body) <= 2 {
		return false, nil
	}

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return false, err
	}

	if _, exists := response["matches"]; exists {
		return true, nil
	}

	return false, nil
}

// DetectDownload checks if a URL triggers a forced download
func DetectDownload(urlToCheck string) (bool, error) {
	err := ValidateURL(urlToCheck)
	if err != nil {
		return false, err
	}

	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(urlToCheck)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	disposition := resp.Header.Get("Content-Disposition")
	return strings.Contains(disposition, "attachment"), nil
}

// DetectTrackersAndCookies checks for tracking and cookies
func DetectTrackersAndCookies(urlToCheck string) (bool, bool, error) {
	err := ValidateURL(urlToCheck)
	if err != nil {
		return false, false, err
	}

	jar, _ := cookiejar.New(nil)
	client := http.Client{Timeout: 10 * time.Second, Jar: jar}
	resp, err := client.Get(urlToCheck)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()

	cookies := jar.Cookies(resp.Request.URL)
	trackers := false
	for _, cookie := range cookies {
		if strings.Contains(cookie.Domain, "track") || strings.Contains(cookie.Domain, "analytics") {
			trackers = true
		}
	}

	return trackers, len(cookies) > 0, nil
}
