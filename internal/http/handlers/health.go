package handlers

import "net/http"

func HealthEndpoint(w http.ResponseWriter, r *http.Request) {
	sendText(w, http.StatusOK, "healthy")
}
