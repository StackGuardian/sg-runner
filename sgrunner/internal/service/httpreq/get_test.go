package httpreq

import "testing"

func TestSgAPI(t *testing.T) {
	httpReqServiceImpl := httpReqServiceImpl{}

	ok, msg, err := httpReqServiceImpl.SgAPI()
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Log(msg)
		t.Fail()
	}
}
