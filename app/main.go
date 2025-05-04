package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// Define constants for custom headers
const (
	XUserID       = "X-User-Id"
	XUserName     = "X-User-Name"
	XUserRoles    = "X-User-Roles"
	XClientID     = "X-Client-Id"
	XClientScopes = "X-Client-Scopes"
)

// Store the Hydra base URL in a global variable
var hydraBaseURL string

type IntrospectResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
	Ext      Ext    `json:"ext"`
}

type Ext struct {
	PreferredUsername string   `json:"preferred_username"`
	Roles             []string `json:"roles"`
	Username          string   `json:"username"`
}

func init() {
	// Fetch the HYDRA_BASE_URL environment variable once during initialization
	hydraBaseURL = os.Getenv("HYDRA_BASE_URL")
	if hydraBaseURL == "" {
		log.Fatal("HYDRA_BASE_URL environment variable not set. Exiting.")
	}
}

func main() {
	http.HandleFunc("/enforce-auth", enforceAuth)
	http.HandleFunc("/enrich-auth", enrichAuth)

	port := "8080"
	log.Printf("Server started on :%s\n", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func enforceAuth(w http.ResponseWriter, r *http.Request) {
	// Strip existing headers to prevent header injection attacks
	clearHeaders(w)

	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}

	introspectResp, err := introspectToken(token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error introspecting token: %v", err), http.StatusUnauthorized)
		return
	}

	if !introspectResp.Active {
		http.Error(w, "Token is inactive", http.StatusUnauthorized)
		return
	}

	w.Header().Set(XUserID, introspectResp.Sub)
	w.Header().Set(XUserName, introspectResp.Ext.Username)
	w.Header().Set(XUserRoles, strings.Join(introspectResp.Ext.Roles, " "))
	w.Header().Set(XClientID, introspectResp.ClientID)
	w.Header().Set(XClientScopes, introspectResp.Scope)

	// Allow Traefik to forward the request with the new headers
	w.WriteHeader(http.StatusOK)
}

func enrichAuth(w http.ResponseWriter, r *http.Request) {
	// Strip existing headers to prevent header injection attacks
	clearHeaders(w)

	token := extractBearerToken(r)
	if token == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	introspectResp, err := introspectToken(token)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	if !introspectResp.Active {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set(XUserID, introspectResp.Sub)
	w.Header().Set(XUserName, introspectResp.Ext.Username)
	w.Header().Set(XUserRoles, strings.Join(introspectResp.Ext.Roles, " "))
	w.Header().Set(XClientID, introspectResp.ClientID)
	w.Header().Set(XClientScopes, introspectResp.Scope)

	w.WriteHeader(http.StatusOK)
}

// extracts the Bearer token from the Authorization header
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(authHeader, "Bearer ")
}

// +introspects the token by calling Hydra's introspect endpoint
func introspectToken(token string) (*IntrospectResponse, error) {
	introspectURL := fmt.Sprintf("%s/oauth2/introspect", hydraBaseURL)

	req, err := http.NewRequest("POST", introspectURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read and decode the JSON response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspect failed with status %d: %s", resp.StatusCode, body)
	}

	var introspectResp IntrospectResponse
	err = json.Unmarshal(body, &introspectResp)
	if err != nil {
		return nil, err
	}

	return &introspectResp, nil
}

// clears sensitive headers to prevent malicious injection
func clearHeaders(w http.ResponseWriter) {
	w.Header().Del("X-USER-ID")
	w.Header().Del("X-USER-NAME")
	w.Header().Del("X-USER-GROUPS")
	w.Header().Del("X-CLIENT-ID")
	w.Header().Del("X-CLIENT-SCOPES")
}
