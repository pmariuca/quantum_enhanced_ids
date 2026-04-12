package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"qks/backend/config"
)

type statusResponse struct {
	DaemonAlive        bool   `json:"daemon_alive"`
	KernelModuleLoaded bool   `json:"kernel_module_loaded"`
	ModuleName         string `json:"module_name"`
}

const kernelModuleName = "qks_ids"

// StatusHandler handles GET /api/status.
func StatusHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := statusResponse{
			ModuleName:         kernelModuleName,
			DaemonAlive:        daemonAlive(cfg.PIDFile),
			KernelModuleLoaded: moduleLoaded(kernelModuleName),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func daemonAlive(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	pid := strings.TrimSpace(string(data))
	if pid == "" {
		return false
	}
	// A process is alive if /proc/<pid>/status is readable.
	_, err = os.Stat("/proc/" + pid + "/status")
	return err == nil
}

func moduleLoaded(name string) bool {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[0] == name {
			return true
		}
	}
	return false
}
