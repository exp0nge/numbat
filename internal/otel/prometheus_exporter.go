package otel

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type metricKey struct {
	name   string
	labels string // formatted k="v",k="v"
}

type MetricStore struct {
	mu     sync.RWMutex
	series map[metricKey]float64
}

func NewMetricStore() *MetricStore {
	return &MetricStore{
		series: make(map[metricKey]float64),
	}
}

func (ms *MetricStore) Record(name string, labels map[string]string, val float64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, "-", "_")

	labelPairs := make([]string, 0, len(labels))
	for k, v := range labels {
		kSan := strings.ReplaceAll(k, ".", "_")
		kSan = strings.ReplaceAll(kSan, "-", "_")
		labelPairs = append(labelPairs, fmt.Sprintf("%s=%q", kSan, v))
	}
	sort.Strings(labelPairs)
	key := metricKey{
		name:   name,
		labels: strings.Join(labelPairs, ","),
	}
	ms.series[key] += val
}

func (ms *MetricStore) RenderPrometheusText() string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var sb strings.Builder
	byName := make(map[string][]metricKey)
	for key := range ms.series {
		byName[key.name] = append(byName[key.name], key)
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		sb.WriteString(fmt.Sprintf("# HELP %s OTLP collected metric\n", name))
		sb.WriteString(fmt.Sprintf("# TYPE %s counter\n", name))
		keys := byName[name]
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].labels < keys[j].labels
		})
		for _, key := range keys {
			val := ms.series[key]
			if key.labels != "" {
				sb.WriteString(fmt.Sprintf("%s{%s} %g\n", key.name, key.labels, val))
			} else {
				sb.WriteString(fmt.Sprintf("%s %g\n", key.name, val))
			}
		}
	}
	return sb.String()
}
