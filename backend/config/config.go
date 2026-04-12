package config

import (
	"encoding/json"
	"os"
)

// All runtime configuration for the backend
type Config struct {
	ListenAddr        string `json:"listen_addr"`
	EventsJSONL       string `json:"events_jsonl"`
	PolicyJSON        string `json:"policy_json"`
	PolicyLocalJSON   string `json:"policy_local_json"`
	PIDFile           string `json:"pid_file"`
	JWTSecret         string `json:"jwt_secret"`
	AdminUsername     string `json:"admin_username"`
	AdminPasswordHash string `json:"admin_password_hash"` // bcrypt hash
	AllowedOrigin     string `json:"allowed_origin"`      // CORS origin
}

var defaults = Config{
	ListenAddr:      ":8080",
	EventsJSONL:     "../daemon/policy/events.jsonl",
	PolicyJSON:      "../daemon/policy/policy.json",
	PolicyLocalJSON: "../daemon/policy/policy.local.json",
	PIDFile:         "/run/qks_daemon.pid",
	AdminUsername:   "admin",
	AllowedOrigin:   "http://localhost:4200",
}

func Load(path string) (*Config, error) {
	cfg := defaults

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, err
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
