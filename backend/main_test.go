package main

import (
	"net/http"
	"net/http/httptest"
	"qks/backend/api"
	"qks/backend/config"
	"qks/backend/internal/eventstore"
	"testing"
)

func TestEventStorePushAndQuery(t *testing.T) {
	store := eventstore.New(10)
	ev := &eventstore.Event{EventID: 1, Type: "EXEC", Policy: "ALLOW"}
	store.Push(ev)
	events := store.Events(eventstore.QueryOptions{})
	if len(events) == 0 || events[0].EventID != 1 {
		t.Errorf("Expected event with ID 1, got %+v", events)
	}
}

func TestConfigLoadDefaultsOnMissingFile(t *testing.T) {
	cfg, err := config.Load("nonexistent_config.json")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cfg.ListenAddr == "" {
		t.Error("Expected default ListenAddr to be set")
	}
}

func TestEventsHandlerReturnsJSON(t *testing.T) {
	store := eventstore.New(5)
	ev := &eventstore.Event{EventID: 42, Type: "EXEC", Policy: "ALLOW"}
	store.Push(ev)
	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()
	handler := api.EventsHandler(store)
	handler(w, req)
	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", res.StatusCode)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected application/json, got %s", ct)
	}
}
