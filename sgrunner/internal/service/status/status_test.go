package status

import (
	"testing"

	mock_httpreq "github.com/StackGuardian/sgrunner/mocks/service/httpreq"
	mock_system "github.com/StackGuardian/sgrunner/mocks/service/system"
	"go.uber.org/mock/gomock"
)

func TestDockerStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSystemService := mock_system.NewMockSystemService(ctrl)
	mockHttpReqService := mock_httpreq.NewMockHttpReqService(ctrl)

	mockSystemService.EXPECT().SystemdServicesStatusAND([]string{"docker", "containerd"}).Return(true, nil)

	statusService := statusService{
		systemService:  mockSystemService,
		httpReqService: mockHttpReqService,
	}

	testCases := []struct {
		input []string
		Want  bool
	}{
		{
			input: []string{"docker", "containerd"},
			Want:  true,
		},
	}
	for _, testCase := range testCases {
		res, err := statusService.dockerStatus()
		if err != nil {
			t.Error(err)
		}
		if res != testCase.Want {
			t.Errorf("got %t want %t", res, testCase.Want)
		}
	}
}
