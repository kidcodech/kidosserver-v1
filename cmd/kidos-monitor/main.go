package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kidcodech/kidosserver-v1/monitoring/sniffer"
	"github.com/kidcodech/kidosserver-v1/webserver"
)

func main() {
	log.Println("Starting Kidos Monitor...")

	// Start sniffer in goroutine
	go func() {
		if err := sniffer.Start("veth-mon"); err != nil {
			log.Fatalf("Sniffer failed: %v", err)
		}
	}()

	// Start webserver in goroutine
	go func() {
		if err := webserver.Start(); err != nil {
			log.Fatalf("Webserver failed: %v", err)
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Println("Kidos Monitor started. Press Ctrl+C to stop")
	<-sigChan

	log.Println("Shutting down...")
}
