package fluentbit

type FluentbitService interface{}

type fluentbitServiceImpl struct{}

func NewFluentbitService() *fluentbitServiceImpl {
	return &fluentbitServiceImpl{}
}

func (s fluentbitServiceImpl) ChangeAzureSASToken() {
	// Fetch the SAS token from SGAPI
	// Change the token in the configuration file
	// Call the fluentbit REST endpoint to hot reload it's config
}
