package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli"
)

// URLData holds URL and its domain
type URLData struct {
	URL    string
	Domain string
}

// URLMetadata holds metadata for a URL
type URLMetadata struct {
	URL string `json:"URL"`
}

func extractDomain(urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	return parsedURL.Hostname(), nil
}

func selectURLsPerDomain(inputFile string, outputFile string, numURLs int, searchString string, outputFormat string, sortMode string) {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	urls := strings.Split(string(data), "\n")

	domainMap := make(map[string][]string)

	// Group URLs by domain and filter by search string
	for _, rawURL := range urls {
		if rawURL == "" {
			continue
		}
		if !strings.Contains(rawURL, searchString) {
			continue
		}
		domain, err := extractDomain(rawURL)
		if err != nil {
			continue
		}
		domainMap[domain] = append(domainMap[domain], rawURL)
	}

	var filteredURLs []URLMetadata

	// Select up to `numURLs` URLs per domain
	for _, urlList := range domainMap {
		limit := numURLs
		if len(urlList) < numURLs {
			limit = len(urlList)
		}
		for _, url := range urlList[:limit] {
			filteredURLs = append(filteredURLs, URLMetadata{URL: url})
		}
	}

	// Sort URLs
	if sortMode == "alphabetical" {
		sort.SliceStable(filteredURLs, func(i, j int) bool {
			return filteredURLs[i].URL < filteredURLs[j].URL
		})
	} else if sortMode == "random" {
		// Shuffle URLs randomly
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(filteredURLs), func(i, j int) { filteredURLs[i], filteredURLs[j] = filteredURLs[j], filteredURLs[i] })
	}

	// Write to output file based on format
	switch outputFormat {
	case "csv":
		writeCSV(outputFile, filteredURLs)
	case "json":
		writeJSON(outputFile, filteredURLs)
	default:
		writeTXT(outputFile, filteredURLs)
	}

	log.Printf("Selected %d URLs saved to '%s'.", len(filteredURLs), outputFile)
}

func writeCSV(outputFile string, urls []URLMetadata) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"URL"})
	for _, metadata := range urls {
		writer.Write([]string{metadata.URL})
	}
}

func writeJSON(outputFile string, urls []URLMetadata) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(urls); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

func writeTXT(outputFile string, urls []URLMetadata) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	for _, metadata := range urls {
		fmt.Fprintln(file, metadata.URL)
	}
}

func main() {
	app := &cli.App{
		Name:  "urlx",
		Usage: "Select a limited number of URLs per domain from a file",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "input, i",
				Usage:    "Input file path",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output, o",
				Usage:    "Output file path",
				Required: true,
			},
			&cli.IntFlag{
				Name:  "num, n",
				Usage: "Number of URLs per domain",
				Value: 1,
			},
			&cli.StringFlag{
				Name:  "string, s",
				Usage: "Search string to filter URLs",
			},
			&cli.StringFlag{
				Name:  "format, f",
				Usage: "Output format (txt, csv, json)",
				Value: "txt",
			},
			&cli.StringFlag{
				Name:  "sort, t",
				Usage: "Output sorting mode (alphabetical, random)",
			},
		},
		Action: func(c *cli.Context) error {
			inputFile := c.String("input")
			outputFile := c.String("output")
			numURLs := c.Int("num")
			searchString := c.String("string")
			outputFormat := c.String("format")
			sortMode := c.String("sort")

			selectURLsPerDomain(inputFile, outputFile, numURLs, searchString, outputFormat, sortMode)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
