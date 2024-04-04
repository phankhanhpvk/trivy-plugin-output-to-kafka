package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/segmentio/kafka-go"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	kafkaTopic := flag.String("topic", "", "Topic kafka")
	if kafkaTopic == nil || *kafkaTopic == "" {
		return fmt.Errorf("topic is required")
	}

	kafkaBrokers := flag.String("brokers", "", "Brokers kafka")
	if kafkaBrokers == nil || *kafkaBrokers == "" {
		return fmt.Errorf("cluster is required")
	}

	flag.Parse()

	// Split the brokers' string into a slice
	brokers := strings.Split(*kafkaBrokers, ",")
	// Initialize a Kafka writer with the desired configuration
	w := kafka.NewWriter(kafka.WriterConfig{
		Brokers: brokers,
		Topic:   *kafkaTopic,                // Replace with your Kafka topic
	})
	defer func() {
		if err := w.Close(); err != nil {
			log.Println("Failed to close Kafka writer:", err)
		}
	}()

	var report types.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}

	reportBytes, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report to json: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte("trivy"),
		Value: reportBytes,
	}

	// Write the message to Kafka
	if err := w.WriteMessages(context.Background(), msg); err != nil {
		return fmt.Errorf("failed to write to Kafka: %w", err)
	}

	// Optionally, you could print a confirmation message or handle logging
	log.Println("Log has been sent to Kafka")

	return nil
}
