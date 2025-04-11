package system

import (
	"os/exec"
)

//go:generate mockgen -source=system.go -destination=../../../mocks/service/system/mock_system.go
type SystemService interface {
	Command(cmd []string) (output []byte, err error)
	SystemdServicesStatusAND(systemdServices []string) (bool, error)
}

type systemServiceImpl struct{}

func NewSystemService() *systemServiceImpl {
	return &systemServiceImpl{}
}

func (s *systemServiceImpl) Command(cmd []string) (output []byte, err error) {
	goCmd := exec.Command(cmd[0], cmd[1:]...)
	output, err = goCmd.Output()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (s *systemServiceImpl) SystemdServiceStatus(service string) (bool, error) {
	output, err := s.Command([]string{"systemctl", "is-active", service})
	if err != nil {
		return false, err
	}
	if string(output) != "active" {
		return false, nil
	}
	return true, nil
}

// Evaluates the status of multiple systemd services using logical AND
func (s *systemServiceImpl) SystemdServicesStatusAND(systemdServices []string) (bool, error) {
	var outputs []bool
	for _, service := range systemdServices {
		output, err := s.SystemdServiceStatus(service)
		if err != nil {
			return false, err
		}
		outputs = append(outputs, output)
	}

	finalStatus := true
	for _, output := range outputs {
		finalStatus = finalStatus && output
	}

	return finalStatus, nil
}
