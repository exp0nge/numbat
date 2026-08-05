package otel

import (
	"strings"
	"testing"
)

func TestMetricStore_PrometheusFormat(t *testing.T) {
	ms := NewMetricStore()
	ms.Record("gen_ai_client_token_usage", map[string]string{
		"gen_ai_request_model": "gpt-4o",
		"token_type":           "input",
	}, 150)

	text := ms.RenderPrometheusText()
	if !strings.Contains(text, "gen_ai_client_token_usage{gen_ai_request_model=\"gpt-4o\",token_type=\"input\"} 150") {
		t.Fatalf("unexpected prometheus text rendering:\n%s", text)
	}
}
