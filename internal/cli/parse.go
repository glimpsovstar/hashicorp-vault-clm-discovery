package cli

import (
	"strconv"
	"strings"
)

// ParsePorts parses a comma-separated list of TCP port numbers.
func ParsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		ports = append(ports, n)
	}
	return ports, nil
}

// SplitCSV splits a comma-separated string into trimmed non-empty values.
func SplitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
