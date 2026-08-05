package otel

import "testing"

func TestDecodeTracesRequest_Empty(t *testing.T) {
	data, err := decodeTracesRequest([]byte{})
	if err != nil {
		t.Fatalf("unexpected error on empty bytes: %v", err)
	}
	if len(data.resourceSpans) != 0 {
		t.Fatalf("expected 0 resourceSpans, got %d", len(data.resourceSpans))
	}
}
