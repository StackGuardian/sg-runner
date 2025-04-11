package main

import (
	"context"
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
	networkService := httpreq.NewHttpReqService()
	systemService := system.NewSystemService()

	statusService := status.NewStatusService(networkService, systemService)

	httpHandlers := handlers.NewHttpHandler(statusService)

	r := mux.NewRouter()
	r.HandleFunc("/status", httpHandlers.GetStatusHandler)

	srv := &http.Server{
		Addr:         "0.0.0.0:8080",
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}

	go func() {
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
