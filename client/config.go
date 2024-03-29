package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	ServerURL        string `json:"server_url"`
	MonitorPath      string `json:"monitor_path"`
	ThreatBookAPIKey string `json:"threatbook_api_key"`
}

func LoadConfig(filePath string) (*Config, error) {
	var cfg Config
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
