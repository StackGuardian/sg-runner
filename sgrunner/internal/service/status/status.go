package status

import (
	"github.com/StackGuardian/sgrunner/internal/service/httpreq"
	"github.com/StackGuardian/sgrunner/internal/service/system"
)

const (
	SUCCESSSTATUS = "success"
)

type StatusService interface {
	GetStatus() (health bool, msg string, err error)
}

type statusService struct {
	httpReqService httpreq.HttpReqService
	systemService  system.SystemService
}

func NewStatusService(httpreqService httpreq.HttpReqService, systemService system.SystemService) *statusService {
	return &statusService{
		httpReqService: httpreqService,
		systemService:  systemService,
	}
}

// Checks the ECS status using metadata endpoint and systemctl
func (s *statusService) ecsStatus() (ok bool, msg string, err error) {
	ecsAgentHealthy, msg, err := s.httpReqService.ECSMetadata()
	if err != nil {
		return false, msg, err
	}
	if !ecsAgentHealthy {
		return false, "ECS agent is not healthy", nil
	}

	// systemctl status
	ok, msg, err = s.systemService.SystemdServiceStatus("ecs")
	if err != nil {
		return false, msg, err
	}

	return ecsAgentHealthy && ok, msg, nil
}

func (s *statusService) fluentbitStatus() (ok bool, msg string, err error) {
	fluentbitHealth, msg, err := s.httpReqService.FluentBitHealth()

	return fluentbitHealth, msg, err
}

func (s *statusService) dockerStatus() (ok bool, msg string, err error) {
	for _, service := range []string{"docker", "containerd"} {
		status, msg, err := s.systemService.SystemdServiceStatus(service)
		if err != nil || !status {
			return false, msg, err
		}
	}

	return true, "", err
}

func (s *statusService) ssmStatus() (ok bool, msg string, err error) {
	operatingSystem, err := s.systemService.Command([]string{"awk", `-F=`, `/^NAME=/{gsub(/"/, "", $2); print $2}`, "/etc/os-release"})
	if err != nil {
		return false, "", err
	}

	service := "amazon-ssm-agent.service"
	if operatingSystem == "Ubuntu" {
		service = "snap.amazon-ssm-agent.amazon-ssm-agent.service"
	}

	ssmStatus, msg, err := s.systemService.SystemdServiceStatus(service)
	if err != nil || !ok {
		return ssmStatus, msg, err
	}

	return ssmStatus, "", nil
}

func (s *statusService) sgAPIStatus() (ok bool, msg string, err error) {
	sgApiStatus, msg, err := s.httpReqService.SgAPI()
	if err != nil || !sgApiStatus {
		return false, msg, err
	}

	return sgApiStatus, "", nil
}

// It returns "success" if the checks were successful
// or returns which check failed
func (s *statusService) GetStatus() (health bool, msg string, err error) {
	health = false

	ecsStatus, msg, err := s.ecsStatus()
	if err != nil || !ecsStatus {
		return false, msg, nil
	}

	fluentbitHealth, msg, err := s.fluentbitStatus()
	if err != nil || !fluentbitHealth {
		return false, msg, err
	}

	dockerStatus, msg, err := s.dockerStatus()
	if err != nil || !dockerStatus {
		return false, msg, err
	}

	ssmStatus, msg, err := s.ssmStatus()
	if err != nil || !ssmStatus {
		return false, msg, err
	}

	sgAPIStatus, msg, err := s.sgAPIStatus()
	if err != nil || !sgAPIStatus {
		return sgAPIStatus, msg, err
	}

	return true, msg, nil
}
