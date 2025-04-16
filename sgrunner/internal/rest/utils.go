package rest

import (
	"encoding/json"
	"net/http"
)

func WriteSuccessResponse(w http.ResponseWriter, data interface{}) {
	body, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = w.Write(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func WriteErrorResponse(w http.ResponseWriter, statusCode int, data interface{}) {

	w.WriteHeader(statusCode)

	WriteSuccessResponse(w, data)
}
