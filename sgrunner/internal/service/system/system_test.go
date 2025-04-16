package system

import (
	"errors"
	"testing"
)

func TestCommand(t *testing.T) {
	systemService := systemServiceImpl{}

	res, err := systemService.Command([]string{"echo", "hi"})
	if err != nil {
		t.Error(err)
	}

	if string(res) != "hi" {
		t.Errorf("got %s want %s", string(res), "hi")
	}
}

//func TestSystemdServiceStatus(t *testing.T) {
//	systemService := systemServiceImpl{}
//
//	res, msg, err := systemService.SystemdServiceStatus("systemd-journald")
//	if err != nil {
//		t.Error(err)
//	}
//
//	if res != true {
//		t.Errorf("got %t want %t with msg %s", res, true, msg)
//	}
//
//	_, _, err = systemService.SystemdServiceStatus("example")
//	if err == nil {
//		t.Errorf("Should have errored out")
//	}
//}

func TestSystemdServicesStatus(t *testing.T) {
	systemService := systemServiceImpl{}

	type want struct {
		Ok  bool
		Msg string
		Err error
	}

	testCases := []struct {
		input string
		want  want
	}{
		{
			input: "systemd-journald",
			want: want{
				Ok:  true,
				Err: nil,
			},
		},
		{
			input: "example",
			want: want{
				Ok:  false,
				Msg: "probably example does not exist",
				Err: errors.New("exit status 4"),
			},
		},
	}

	for _, testcase := range testCases {
		res, msg, err := systemService.SystemdServiceStatus(testcase.input)
		if err != nil {
			if err.Error() != testcase.want.Err.Error() {
				t.Error(err)
			}
			if msg != testcase.want.Msg {
				t.Errorf("msg got %s want %s", msg, testcase.want.Msg)
			}
		}
		if res != testcase.want.Ok {
			t.Errorf("got %t want %t", res, testcase.want.Ok)
		}
	}
}
