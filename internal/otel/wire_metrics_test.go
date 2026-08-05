package otel

import (
	"testing"
)

func TestDecodeMetricsRequest_Empty(t *testing.T) {
	data, err := decodeMetricsRequest([]byte{})
	if err != nil {
		t.Fatalf("unexpected error on empty bytes: %v", err)
	}
	if len(data.resourceMetrics) != 0 {
		t.Fatalf("expected 0 resourceMetrics, got %d", len(data.resourceMetrics))
	}
}
