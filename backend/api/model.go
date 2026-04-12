package api

import (
	"encoding/json"
	"net/http"

	"qks/backend/internal/eventstore"
)

type modelMetricsResponse struct {
	TotalEvents    int     `json:"total_events"`
	DenyRate       float64 `json:"deny_rate"`
	MLCoverage     float64 `json:"ml_coverage"`
	AvgMLProb      float64 `json:"avg_ml_prob"`
}

// ModelMetricsHandler handles GET /api/model/metrics.
func ModelMetricsHandler(store *eventstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Pull more events for a broader sample.
		events := store.Events(eventstore.QueryOptions{Limit: 1000})

		var mlSum float64
		var mlCount int
		for _, ev := range events {
			if ev.MlProb != nil {
				mlSum += *ev.MlProb
				mlCount++
			}
		}

		totals := store.Totals()

		var denyRate, mlCoverage, avgMLProb float64
		if totals.Total > 0 {
			denyRate = float64(totals.TotalDeny) / float64(totals.Total) * 100
			mlCoverage = float64(totals.TotalML) / float64(totals.Total) * 100
		}
		if mlCount > 0 {
			avgMLProb = mlSum / float64(mlCount)
		}

		resp := modelMetricsResponse{
			TotalEvents: totals.Total,
			DenyRate:    denyRate,
			MLCoverage:  mlCoverage,
			AvgMLProb:   avgMLProb,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

type modelActivityResponse struct {
	RecentSyscalls []*eventstore.Event `json:"recent_syscalls"`
	RecentPackets  []*eventstore.Event `json:"recent_packets"`
}

// ModelActivityHandler handles GET /api/model/activity.
func ModelActivityHandler(store *eventstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		syscalls := store.Events(eventstore.QueryOptions{Limit: 20, EventType: "SYSCALL"})
		packets := store.Events(eventstore.QueryOptions{Limit: 20, EventType: "PACKET"})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(modelActivityResponse{
			RecentSyscalls: syscalls,
			RecentPackets:  packets,
		})
	}
}
