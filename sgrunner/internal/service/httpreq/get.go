package httpreq

import (
	"fmt"
	"net/http"
)

//go:generate mockgen --source=get.go --destination=../../../mocks/service/httpreq/httpreq.go
type HttpReqService interface {
	ECSMetadata() (ok bool, msg string, err error)
	FluentBitHealth() (ok bool, msg string, err error)
	SgAPI() (ok bool, msg string, err error)
}

type SgConfig struct {
	SgApiKey     string
	SgApiBaseUri string
}

type httpReqServiceImpl struct {
	sgConfig *SgConfig
}

func NewHttpReqService(sgConfig *SgConfig) *httpReqServiceImpl {
	return &httpReqServiceImpl{
		sgConfig: sgConfig,
	}
}

func (s *httpReqServiceImpl) ECSMetadata() (ok bool, msg string, err error) {

	// GET call to ECS endpoint
	url := "http://localhost:51678/v1/metadata"

	resp, err := http.Get(url)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "ECS returned a non 200 status", nil
	}

	return true, "", nil
}

func (s *httpReqServiceImpl) FluentBitHealth() (ok bool, msg string, err error) {
	url := "http://127.0.0.1:2020/api/v1/health"
	resp, err := http.Get(url)
	if err != nil {
		return false, msg, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "fluent bit returned a non 200 status", nil
	}
	return true, "", err
}

func (s *httpReqServiceImpl) SgAPI() (ok bool, msg string, err error) {
	url := fmt.Sprintf("%s/apidocs/redoc/swagger.json", s.sgConfig.SgApiBaseUri)

	client := &http.Client{}
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "SG API return a non 200 status", nil
	}

	return true, "", nil
}

func (s *httpReqServiceImpl) AzureSasTokenDelegationKey() {
	url := fmt.Sprintf("%s/")
}
