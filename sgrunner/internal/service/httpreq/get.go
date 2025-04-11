package httpreq

import "net/http"

//go:generate mockgen --source=get.go --destination=../../../mocks/service/httpreq/httpreq.go
type HttpReqService interface {
	ECSMetadata() (bool, error)
	FluentBitHealth() (bool, error)
}

type httpReqServiceImpl struct {
}

func NewHttpReqService() *httpReqServiceImpl {
	return &httpReqServiceImpl{}
}

func (s *httpReqServiceImpl) ECSMetadata() (bool, error) {

	// GET call to ECS endpoint
	url := "http://localhost:51678/v1/metadata"

	resp, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, nil
	}

	return true, nil
}

func (s *httpReqServiceImpl) FluentBitHealth() (bool, error) {
	url := "http://127.0.0.1:2020/api/v1/health"
	resp, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, err
	}
	return true, err
}
