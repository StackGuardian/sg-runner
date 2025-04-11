package system

import "testing"

func TestSystemdServiceStatus(t *testing.T) {
	systemService := systemServiceImpl{}

	res, err := systemService.SystemdServiceStatus("docker")
	if err != nil {
		t.Error(err)
	}

	if res != true {
		t.Errorf("got %t want %t", res, true)
	}
}
