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
	"github.com/olekukonko/tablewriter"
	"github.com/segmentio/kafka-go"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	topic := flag.String("topic", "", "Kafka topic")
	brokers := flag.String("brokers", "", "Kafka brokers, comma separated")
	flag.Parse()

	if *topic == "" {
		return fmt.Errorf("topic is required")
	}

	if *brokers == "" {
		return fmt.Errorf("brokers are required")
	}

	kafkaBrokers := strings.Split(*brokers, ",")
	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: kafkaBrokers,
		Topic:   *topic,
	})
	defer writer.Close()

	var report types.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return fmt.Errorf("failed to decode report: %w", err)
	}

	reportBytes, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	message := kafka.Message{Value: reportBytes}
	if err := writer.WriteMessages(context.Background(), message); err != nil {
		return fmt.Errorf("failed to send report to Kafka: %w", err)
	}

	 severityCounts, totalCounts := countSeverities(report.Results)
	 displaySeverityCounts(severityCounts, totalCounts)

	return nil
}

func countSeverities(results []types.Result) (map[string]map[string]int, map[string]int) {
	severityCounts := map[string]map[string]int{}
	totalCounts := map[string]int{}

	for _, result := range results {
		severityCount, ok := severityCounts[result.Target]
		if !ok {
			severityCount = map[string]int{}
			severityCounts[result.Target] = severityCount
		}

		for _, vuln := range result.Vulnerabilities {
			severityCount[vuln.Severity]++
			totalCounts[vuln.Severity]++
		}
	}

	return severityCounts, totalCounts
}

func displaySeverityCounts(severityCounts map[string]map[string]int, totalCounts map[string]int) {
	header := []string{"TARGET"}
	uniqueSeverities := getUniqueSeverities(severityCounts)
	header = append(header, uniqueSeverities...)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)

	 for target, counts := range severityCounts {
		row := []string{target}
		for _, severity := range uniqueSeverities {
			row = append(row, fmt.Sprintf("%d", counts[severity]))
		}
		table.Append(row)
	}

	totalRow := []string{"TOTAL SEVERITY"}
	for _, severity := range uniqueSeverities {
		totalRow = append(totalRow, fmt.Sprintf("%d", totalCounts[severity]))
	}
	table.SetFooter(totalRow)
	table.SetCaption(true, fmt.Sprintf("Total severity: %d", sum(totalCounts)))
	table.Render()
}

func sum(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func getUniqueSeverities(severityCountByTarget map[string]map[string]int) []string {
	uniqueSeverities := map[string]struct{}{}
	for _, severityCounts := range severityCountByTarget {
		for severity := range severityCounts {
			uniqueSeverities[severity] = struct{}{}
		}
	}

	severities := make([]string, 0, len(uniqueSeverities))
	for severity := range uniqueSeverities {
		severities = append(severities, severity)
	}

	return severities
}
