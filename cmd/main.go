package main

import (
	"bufio"
	"fmt"
	"os"

	"url-safety-scanner/internal/config"
	"url-safety-scanner/internal/report"
	"url-safety-scanner/internal/scanner"
	"url-safety-scanner/internal/utils"
)

func main() {
	utils.PrintBanner()

	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load API key: %v\n", err)
		return
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  url-safety-scanner <URL> [-download] [-cookies] [-trackers]")
		fmt.Println("  url-safety-scanner -f <file_with_urls.txt> [-download] [-cookies] [-trackers]")
		return
	}

	downloadCheck := false
	cookieCheck := false
	trackerCheck := false
	args := os.Args[1:]
	var urls []string

	if args[0] == "-f" && len(args) >= 2 {
		inputFile := args[1]
		for _, flag := range args[2:] {
			switch flag {
			case "-download":
				downloadCheck = true
			case "-cookies":
				cookieCheck = true
			case "-trackers":
				trackerCheck = true
			}
		}

		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Printf("❌ Failed to open file: %v\n", err)
			return
		}
		defer file.Close()

		scannerInput := bufio.NewScanner(file)
		for scannerInput.Scan() {
			urls = append(urls, scannerInput.Text())
		}
	} else {
		urlToCheck := args[0]
		for _, flag := range args[1:] {
			switch flag {
			case "-download":
				downloadCheck = true
			case "-cookies":
				cookieCheck = true
			case "-trackers":
				trackerCheck = true
			}
		}
		urls = []string{urlToCheck}
	}

	var results [][]string
	var jsonResults []report.URLResult

	for _, u := range urls {
		result := []string{u}
		jsonRes := report.URLResult{URL: u}

		malicious, err := scanner.CheckURL(cfg.ApiKey, u)
		if err != nil {
			result = append(result, "Error")
			jsonRes.SafeBrowsingStatus = "Error"
		} else if malicious {
			result = append(result, "Malicious")
			jsonRes.SafeBrowsingStatus = "Malicious"
		} else {
			result = append(result, "Safe")
			jsonRes.SafeBrowsingStatus = "Safe"
		}

		if downloadCheck {
			downloaded, err := scanner.DetectDownload(u)
			if err != nil {
				result = append(result, "Error")
				jsonRes.DownloadStatus = "Error"
			} else if downloaded {
				result = append(result, "Download Detected")
				jsonRes.DownloadStatus = "Download Detected"
			} else {
				result = append(result, "No Download")
				jsonRes.DownloadStatus = "No Download"
			}
		} else {
			result = append(result, "N/A")
			jsonRes.DownloadStatus = "N/A"
		}

		if cookieCheck || trackerCheck {
			trackers, cookies, err := scanner.DetectTrackersAndCookies(u)
			if err != nil {
				result = append(result, "Error", "Error")
				jsonRes.CookieStatus = "Error"
				jsonRes.TrackerStatus = "Error"
			} else {
				if cookieCheck {
					if cookies {
						result = append(result, "Cookies Detected")
						jsonRes.CookieStatus = "Cookies Detected"
					} else {
						result = append(result, "No Cookies")
						jsonRes.CookieStatus = "No Cookies"
					}
				} else {
					result = append(result, "N/A")
					jsonRes.CookieStatus = "N/A"
				}

				if trackerCheck {
					if trackers {
						result = append(result, "Trackers Detected")
						jsonRes.TrackerStatus = "Trackers Detected"
					} else {
						result = append(result, "No Trackers")
						jsonRes.TrackerStatus = "No Trackers"
					}
				} else {
					result = append(result, "N/A")
					jsonRes.TrackerStatus = "N/A"
				}
			}
		} else {
			result = append(result, "N/A", "N/A")
			jsonRes.CookieStatus = "N/A"
			jsonRes.TrackerStatus = "N/A"
		}

		results = append(results, result)
		jsonResults = append(jsonResults, jsonRes)

		fmt.Printf("✅ %s scanned\n", u)
	}

	err = report.SaveCSV("report", results)
	if err != nil {
		fmt.Printf("❌ Failed to save CSV: %v\n", err)
	}

	err = report.SaveJSON("report", jsonResults)
	if err != nil {
		fmt.Printf("❌ Failed to save JSON: %v\n", err)
	}

	fmt.Println("📄 Reports saved as report.csv and report.json")
}
