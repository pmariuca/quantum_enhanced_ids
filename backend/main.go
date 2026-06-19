package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"qks/backend/api"
	"qks/backend/config"
	"qks/backend/internal/eventstore"
	"qks/backend/internal/tailer"
	qksmw "qks/backend/middleware"
)

func main() {
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Fatalf("[BACKEND] config: %v", err)
	}

	if cfg.JWTSecret == "" {
		log.Fatal("[BACKEND] config: jwt_secret must be set in config.json")
	}
	if cfg.AdminPasswordHash == "" {
		log.Fatal("[BACKEND] config: admin_password_hash must be set in config.json (run tools/genpw to generate)")
	}

	// --- Event store + tailer ---
	store := eventstore.New(0)
	t := tailer.New(cfg.EventsJSONL, store)
	stop := make(chan struct{})
	go t.Run(stop)

	r := chi.NewRouter()
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{cfg.AllowedOrigin},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Public routes
	r.Post("/api/auth/login", api.LoginHandler(cfg))
	r.Post("/api/auth/refresh", api.RefreshTokenHandler(cfg))

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(qksmw.JWTAuth(cfg.JWTSecret))

		r.Get("/api/events", api.EventsHandler(store))
		r.Get("/api/events/stream", api.EventsStreamHandler(t))
		r.Get("/api/events/download", api.EventsDownloadHandler(cfg))

		r.Get("/api/metrics", api.MetricsHandler(store, cfg))

		r.Get("/api/model/metrics", api.ModelMetricsHandler(store))
		r.Get("/api/model/activity", api.ModelActivityHandler(store))
		r.Get("/api/model/timeseries", api.ModelTimeseriesHandler(store))

		r.Get("/api/status", api.StatusHandler(cfg))

		r.Get("/api/policy", api.GetPolicyHandler(cfg))
		r.Put("/api/policy", api.PutPolicyHandler(cfg))
		r.Get("/api/policy/local", api.GetPolicyLocalHandler(cfg))
		r.Put("/api/policy/local", api.PutPolicyLocalHandler(cfg))
	})

	fmt.Printf("[BACKEND] Listening on %s\n", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, r); err != nil {
		log.Fatalf("[BACKEND] server: %v", err)
	}

	close(stop)
}
