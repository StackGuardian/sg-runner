package handlers

import (
	"encoding/json"
	"net/http"

	models "github.com/StackGuardian/sgrunner/internal/api"
	runnerstatus "github.com/StackGuardian/sgrunner/internal/service/status"
)

type httpHandler struct {
	statusService runnerstatus.StatusService
}

func NewHttpHandler(statusService runnerstatus.StatusService) httpHandler {
	return httpHandler{
		statusService: statusService,
	}
}

func (h *httpHandler) GetStatusHandler(w http.ResponseWriter, r *http.Request) {
	status, err := h.statusService.GetStatus()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	respModel := models.GetStatusHandlerResp{
		Msg: status,
	}

	if *status != runnerstatus.SUCCESSSTATUS {
		respBody, err := json.Marshal(respModel)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write(respBody)
	}
}
