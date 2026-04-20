package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"qks/backend/config"
	"qks/backend/internal/eventstore"
	"qks/backend/internal/tailer"
)

// EventsHandler handles GET /api/events
// Query params: limit, type, policy, since_id
func EventsHandler(store *eventstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		opts := eventstore.QueryOptions{
			EventType: q.Get("type"),
			Policy:    q.Get("policy"),
		}

		if l := q.Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				opts.Limit = n
			}
		}
		if s := q.Get("since_id"); s != "" {
			if n, err := strconv.ParseUint(s, 10, 64); err == nil {
				opts.SinceID = n
			}
		}

		events := store.Events(opts)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}

// EventsStreamHandler handles GET /api/events/stream (Server-Sent Events).
// Each new line from events.jsonl is pushed as: data: <json>\n\n
func EventsStreamHandler(t *tailer.Tailer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if behind a proxy

		sub := t.Subscribe()
		defer t.Unsubscribe(sub)

		// Send a comment as an initial keepalive so the browser doesn't timeout.
		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()

		for {
			select {
			case <-r.Context().Done():
				return
			case line, ok := <-sub.Chan():
				if !ok {
					return
				}
				fmt.Fprintf(w, "data: %s\n\n", line)
				flusher.Flush()
			}
		}
	}
}

// GET /api/events/download.
// It serves the full daemon events JSONL file.
// Query params: source=daemon|static
func EventsDownloadHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source := r.URL.Query().Get("source")
		if source == "" {
			source = "daemon"
		}

		if source == "static" {
			http.Error(w, "static source file export is not available", http.StatusBadRequest)
			return
		}

		data, err := os.ReadFile(cfg.EventsJSONL)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read events file: %v", err), http.StatusInternalServerError)
			return
		}

		filename := filepath.Base(cfg.EventsJSONL)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}
