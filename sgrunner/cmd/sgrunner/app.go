package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/StackGuardian/sgrunner/internal/handlers"
	"github.com/StackGuardian/sgrunner/internal/service/httpreq"
	"github.com/StackGuardian/sgrunner/internal/service/status"
	"github.com/StackGuardian/sgrunner/internal/service/system"
	"github.com/gorilla/mux"
)

func main() {

	sgApiKey := flag.String("sg-node-token", "", "used to communicate with SG API")
	sgApiBaseUri := flag.String("sg-base-uri", "https://api.stackguardian.io", "base uri for stackguardian API")
	flag.Parse()

	networkService := httpreq.NewHttpReqService(&httpreq.SgConfig{
		SgApiKey:     *sgApiKey,
		SgApiBaseUri: *sgApiBaseUri,
	})
	systemService := system.NewSystemService()

	statusService := status.NewStatusService(networkService, systemService)

	httpHandlers := handlers.NewHttpHandler(statusService)

	r := mux.NewRouter()
	r.HandleFunc("/status", httpHandlers.GetStatusHandler)

	srv := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: r,
	}

	go func() {
		log.Println("http server starting at 8080")
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	srv.Shutdown(ctx)
	log.Println("shutting down")
	os.Exit(0)
}
