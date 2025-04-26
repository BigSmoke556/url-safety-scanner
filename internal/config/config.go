package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	ApiKey string `json:"api_key"`
}

const configFile = ".safeurlchecker_config.json"

// LoadConfig loads the API key from the config file or asks the user to enter one
func LoadConfig() (*Config, error) {
	var cfg Config

	file, err := os.Open(configFile)
	if err != nil {
		fmt.Println("API Key not found. Please enter your Google Safe Browsing API Key:")
		var apiKey string
		fmt.Scanln(&apiKey)
		cfg.ApiKey = apiKey
		err = saveConfig(&cfg)
		if err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	file, err := os.Create(configFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(cfg)
}
