package handlers

import "net/http"

func HealthEndpoint(w http.ResponseWriter, _ *http.Request) {
	sendText(w, http.StatusOK, "healthy")
}
