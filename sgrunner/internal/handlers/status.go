package handlers

import (
	"net/http"

	"github.com/StackGuardian/sgrunner/internal/rest"
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
	health, msg, err := h.statusService.GetStatus()
	if err != nil {
		respModel := rest.ErrRespModel{
			Err: err.Error(),
		}
		rest.WriteErrorResponse(w, http.StatusInternalServerError, respModel)
		return
	}
	if !health {
		respModel := rest.ErrRespModel{
			Err: msg,
		}
		rest.WriteErrorResponse(w, http.StatusInternalServerError, respModel)
		return
	}

	respModel := rest.SuccessRespModel{
		Msg: "healthy",
	}
	rest.WriteSuccessResponse(w, respModel)
}
