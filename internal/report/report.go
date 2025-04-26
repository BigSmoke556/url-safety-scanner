package report

import (
	"encoding/csv"
	"encoding/json"
	"os"
)

type URLResult struct {
	URL                string `json:"url"`
	SafeBrowsingStatus string `json:"safebrowsing_status"`
	DownloadStatus     string `json:"download_status"`
	CookieStatus       string `json:"cookie_status"`
	TrackerStatus      string `json:"tracker_status"`
}

// SaveCSV saves scan results into a CSV file
func SaveCSV(filename string, results [][]string) error {
	file, err := os.Create(filename + ".csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"URL", "SafeBrowsing Status", "Download", "Cookies", "Trackers"}
	writer.Write(headers)

	for _, record := range results {
		writer.Write(record)
	}
	return nil
}

// SaveJSON saves scan results into a JSON file
func SaveJSON(filename string, results []URLResult) error {
	file, err := os.Create(filename + ".json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}
