package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"qks/backend/config"
	"qks/backend/internal/policyreload"
)

// GetPolicyHandler handles GET /api/policy — returns policy.json verbatim.
func GetPolicyHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serveJSONFile(w, cfg.PolicyJSON)
	}
}

// PutPolicyHandler handles PUT /api/policy — validates JSON, writes to disk, signals daemon.
func PutPolicyHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writePolicy(w, r, cfg.PolicyJSON, cfg.PIDFile)
	}
}

// GetPolicyLocalHandler handles GET /api/policy/local.
func GetPolicyLocalHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serveJSONFile(w, cfg.PolicyLocalJSON)
	}
}

// PutPolicyLocalHandler handles PUT /api/policy/local.
func PutPolicyLocalHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writePolicy(w, r, cfg.PolicyLocalJSON, cfg.PIDFile)
	}
}

// serveJSONFile reads a file and writes it as application/json.
func serveJSONFile(w http.ResponseWriter, path string) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, f)
}

// writePolicy validates the JSON body, writes it atomically, then signals the daemon.
func writePolicy(w http.ResponseWriter, r *http.Request, path, pidFile string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
	if err != nil {
		http.Error(w, `{"error":"read error"}`, http.StatusBadRequest)
		return
	}

	// Validate JSON before writing anything.
	if !json.Valid(body) {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Write atomically: write to a temp file then rename.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0644); err != nil {
		http.Error(w, `{"error":"write failed"}`, http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		http.Error(w, `{"error":"write failed"}`, http.StatusInternalServerError)
		return
	}

	// Signal the daemon; log but don't fail the request if it's not running.
	if err := policyreload.Signal(pidFile); err != nil {
		// Non-fatal: policy is written, daemon will pick it up on next start.
		w.Header().Set("X-Reload-Warning", err.Error())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
