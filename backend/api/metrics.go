package api

import (
	"encoding/json"
	"net/http"

	"qks/backend/config"
	"qks/backend/internal/eventstore"
	"qks/backend/internal/procstat"
)

type metricsResponse struct {
	CPUPercent  float64 `json:"cpu_pct"`
	MemPercent  float64 `json:"mem_pct"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	MemUsedMB   uint64  `json:"mem_used_mb"`
	TotalEvents int     `json:"total_events"`
	TotalAllow  int     `json:"total_allow"`
	TotalDeny   int     `json:"total_deny"`
	TotalML     int     `json:"total_ml"`
}

// MetricsHandler handles GET /api/metrics.
func MetricsHandler(store *eventstore.Store, _ *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cpu, err := procstat.CPUPercent()
		if err != nil {
			cpu = -1
		}

		mem, err := procstat.MemInfo()
		if err != nil {
			mem = procstat.MemStats{}
		}

		totals := store.Totals()

		resp := metricsResponse{
			CPUPercent:  cpu,
			MemPercent:  mem.UsedPct,
			MemTotalMB:  mem.Total / 1024 / 1024,
			MemUsedMB:   (mem.Total - mem.Available) / 1024 / 1024,
			TotalEvents: totals.Total,
			TotalAllow:  totals.TotalAllow,
			TotalDeny:   totals.TotalDeny,
			TotalML:     totals.TotalML,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
