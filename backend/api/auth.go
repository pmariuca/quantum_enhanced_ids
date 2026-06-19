package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"qks/backend/config"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type refreshRequest struct {
	Token string `json:"token"`
}

type refreshResponse struct {
	Token string `json:"token"`
}

// POST /api/auth/login
// Validate credentials against the bcrypt hash in config and return a signed JWT
func LoginHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}

		if req.Username != cfg.AdminUsername {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		if err := bcrypt.CompareHashAndPassword(
			[]byte(cfg.AdminPasswordHash),
			[]byte(req.Password),
		); err != nil {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		claims := jwt.MapClaims{
			"sub": req.Username,
			"exp": time.Now().Add(8 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString([]byte(cfg.JWTSecret))
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loginResponse{Token: signed})
	}
}

// POST /api/auth/refresh
// Validate and refresh a JWT token. Returns a new token if the current one is still valid.
func RefreshTokenHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}

		if req.Token == "" {
			http.Error(w, `{"error":"missing token"}`, http.StatusBadRequest)
			return
		}

		// Parse the token without validating expiration
		token, err := jwt.Parse(req.Token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(cfg.JWTSecret), nil
		}, jwt.WithValidMethods([]string{"HMAC"}))

		if err != nil || !token.Valid {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["sub"] == nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// Create a new token with updated expiration
		newClaims := jwt.MapClaims{
			"sub": claims["sub"],
			"exp": time.Now().Add(8 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}

		newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
		signed, err := newToken.SignedString([]byte(cfg.JWTSecret))
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(refreshResponse{Token: signed})
	}
}
