package rest

type SuccessRespModel struct {
	Msg string `json:"msg,omitempty"`
}

type ErrRespModel struct {
	Err string `json:"error,omitempty"`
}
