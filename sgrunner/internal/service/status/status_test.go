package status

import (
	"strings"
	"testing"

	mock_httpreq "github.com/StackGuardian/sgrunner/mocks/service/httpreq"
	mock_system "github.com/StackGuardian/sgrunner/mocks/service/system"
	"go.uber.org/mock/gomock"
)

func TestDockerStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSystemService := mock_system.NewMockSystemService(ctrl)
	mockHttpReqService := mock_httpreq.NewMockHttpReqService(ctrl)

	mockSystemService.EXPECT().SystemdServiceStatus("docker").Return(true, "", nil)
	mockSystemService.EXPECT().SystemdServiceStatus("containerd").Return(true, "", nil)

	statusService := statusService{
		systemService:  mockSystemService,
		httpReqService: mockHttpReqService,
	}

	type want struct {
		Ok  bool
		Msg string
		Err string
	}

	testCases := []struct {
		input []string
		Want  want
	}{
		{
			input: []string{"docker", "containerd"},
			Want: want{
				Ok: true,
			},
		},
	}
	for _, testCase := range testCases {
		res, msg, err := statusService.dockerStatus()
		if err != nil {
			t.Error(err)
		}
		if res != testCase.Want.Ok {
			t.Errorf("got %t want %t", res, testCase.Want.Ok)
		}
		if msg != testCase.Want.Msg {
			t.Errorf("msg got %s want %s", msg, testCase.Want.Msg)
		}
	}
}

func TestSsmStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSystemService := mock_system.NewMockSystemService(ctrl)
	mockHttpReqService := mock_httpreq.NewMockHttpReqService(ctrl)
	statusService := statusService{
		systemService:  mockSystemService,
		httpReqService: mockHttpReqService,
	}

	mockSystemService.EXPECT().Command(strings.Split(`awk -F= '/^NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release`, " ")).Return("ubuntu", nil)
	mockSystemService.EXPECT().SystemdServiceStatus("snap.amazon-ssm-agent.amazon-ssm-agent.service")

	statusService.ssmStatus()
	ok := ctrl.Satisfied()
	if !ok {
		t.Error("failed to check for snap package")
	}

	mockSystemService.EXPECT().Command(strings.Split(`awk -F= '/^NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release`, " ")).Return("Amazon Linux 2023", nil)
	mockSystemService.EXPECT().SystemdServiceStatus("amazon-ssm-agent.service")
	statusService.ssmStatus()
	ok = ctrl.Satisfied()
	if !ok {
		t.Error("failed to check for snap package")
	}
}

func TestSgApi(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSystemService := mock_system.NewMockSystemService(ctrl)
	mockHttpReqService := mock_httpreq.NewMockHttpReqService(ctrl)

	statusService := statusService{
		systemService:  mockSystemService,
		httpReqService: mockHttpReqService,
	}

	statusService.httpReqService.SgAPI()
}
