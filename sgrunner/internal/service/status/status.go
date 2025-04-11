package status

import (
	"github.com/StackGuardian/sgrunner/internal/service/httpreq"
	"github.com/StackGuardian/sgrunner/internal/service/system"
)

const (
	SUCCESSSTATUS = "success"
)

type StatusService interface {
	GetStatus() (msg *string, err error)
}

type statusService struct {
	httpReqService httpreq.HttpReqService
	systemService  system.SystemService
}

func NewStatusService(httpreqService httpreq.HttpReqService, systemService system.SystemService) *statusService {
	return &statusService{}
}

// Checks the ECS status using metadata endpoint and systemctl
func (s *statusService) ecsStatus() (bool, error) {
	ecsAgentHealthy, err := s.httpReqService.ECSMetadata()
	if err != nil {
		return false, err
	}

	// systemctl status
	var ecsSystemdServiceActive bool
	cmd := []string{"systemctl", "is-active", "ecs"}
	output, err := s.systemService.Command(cmd)
	if err != nil {
		return false, err
	}
	if string(output) != "active" {
		ecsSystemdServiceActive = false
	}

	return ecsAgentHealthy && ecsSystemdServiceActive, nil
}

func (s *statusService) fluentbitStatus() (bool, error) {
	fluentbitHealth, err := s.httpReqService.FluentBitHealth()
	if err != nil {
		return false, err
	}

	return fluentbitHealth, nil
}

func (s *statusService) dockerStatus() (bool, error) {
	output, err := s.systemService.SystemdServicesStatusAND([]string{"docker", "containerd"})
	if err != nil {
		return false, err
	}

	return output, nil
}

// It returns "success" if the checks were successful
// or returns which check failed
func (s *statusService) GetStatus() (*string, error) {
	var msg string

	ecsStatus, err := s.ecsStatus()
	if err != nil {
		return nil, err
	}
	if !ecsStatus {
		msg = "ecs is unhealthy"
		return &msg, nil
	}

	fluentbitHealth, err := s.fluentbitStatus()
	if err != nil {
		return nil, err
	}
	if !fluentbitHealth {
		msg = "fluentbit is unhealthy"
		return &msg, nil
	}

	dockerStatus, err := s.dockerStatus()
	if err != nil {
		return nil, err
	}
	if !dockerStatus {
		msg = "docker is unhealthy"
	}

	return &msg, nil
}
