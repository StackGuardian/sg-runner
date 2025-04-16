package system

import (
	"fmt"
	"os/exec"
	"strings"
)

//go:generate mockgen -source=system.go -destination=../../../mocks/service/system/mock_system.go
type SystemService interface {
	Command(cmd []string) (output string, err error)
	SystemdServiceStatus(service string) (ok bool, msg string, err error)
}

type systemServiceImpl struct{}

func NewSystemService() *systemServiceImpl {
	return &systemServiceImpl{}
}

func (s *systemServiceImpl) Command(cmd []string) (output string, err error) {
	goCmd := exec.Command(cmd[0], cmd[1:]...)
	cmdOutput, err := goCmd.Output()
	if err != nil {
		return "", err
	}

	output = strings.TrimSuffix(string(cmdOutput), "\n")

	return output, nil
}

func (s *systemServiceImpl) SystemdServiceStatus(service string) (ok bool, msg string, err error) {
	output, err := s.Command([]string{"systemctl", "is-active", service})
	if err != nil {
		return false, fmt.Sprintf("probably %s does not exist", service), err
	}
	if output != "active" {
		return false, fmt.Sprintf("%s is not active", service), err
	}
	return true, "", nil
}

//// Evaluates the status of multiple systemd services using logical AND
//func (s *systemServiceImpl) SystemdServicesStatusAND(systemdServices []string) (ok bool, msg string, err error) {
//	var outputs []bool
//	for _, service := range systemdServices {
//		output, msg, err := s.SystemdServiceStatus(service)
//		if err != nil {
//			return false, msg, err
//		}
//		outputs = append(outputs, output)
//	}
//
//	ok = true
//	for _, output := range outputs {
//		ok = ok && output
//	}
//
//	return ok, "", nil
//}
//
