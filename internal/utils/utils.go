package utils

import (
	"fmt"
)

// PrintBanner shows the ASCII logo at startup
func PrintBanner() {
	banner := `
'##::::'##:::::::'######::::::::'######::
 ##:::: ##::::::'##... ##::::::'##... ##:
 ##:::: ##:::::: ##:::..::::::: ##:::..::
 ##:::: ##::::::. ######:::::::. ######::
 ##:::: ##:::::::..... ##:::::::..... ##:
 ##:::: ##:'###:'##::: ##:'###:'##::: ##:
. #######:: ###:. ######:: ###:. ######::
:.......:::...:::......:::...:::......:::
        Made in Brazil 🇧🇷
`
	fmt.Println(banner)
}

// CalculateRiskScore evaluates the risk score based on scan results
func CalculateRiskScore(safeBrowsing, download, cookies, trackers string) int {
	score := 0

	if safeBrowsing == "Malicious" {
		score += 50
	}
	if download == "Download Detected" {
		score += 20
	}
	if cookies == "Cookies Detected" {
		score += 10
	}
	if trackers == "Trackers Detected" {
		score += 20
	}

	return score
}
