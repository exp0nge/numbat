package otel

import (
	"fmt"
	"google.golang.org/protobuf/encoding/protowire"
)

type metricsData struct {
	resourceMetrics []resourceMetrics
}

type resourceMetrics struct {
	resource     resource
	scopeMetrics []scopeMetrics
}

type scopeMetrics struct {
	metrics []metricData
}

type metricData struct {
	name        string
	description string
	unit        string
	dataPoints  []metricDataPoint
}

type metricDataPoint struct {
	attributes   []keyValue
	timeUnixNano uint64
	asInt        int64
	asDouble     float64
}

const (
	fieldExportResourceMetrics       = 1
	fieldResourceMetricsResource     = 1
	fieldResourceMetricsScopeMetrics = 2
	fieldScopeMetricsMetrics         = 2
	fieldMetricName                  = 1
	fieldMetricDescription           = 2
	fieldMetricUnit                  = 3
	fieldMetricSum                   = 5
	fieldMetricGauge                 = 7
	fieldDataPoints                  = 1
	fieldDataPointAttributes         = 1
	fieldDataPointTimeUnixNano       = 2
	fieldDataPointAsInt              = 4
	fieldDataPointAsDouble           = 5
)

func decodeMetricsRequest(b []byte) (metricsData, error) {
	var out metricsData
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return metricsData{}, fmt.Errorf("otlp: bad metrics tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldExportResourceMetrics && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return metricsData{}, fmt.Errorf("otlp: bad resource_metrics: %w", protowire.ParseError(n))
			}
			b = b[n:]
			rm, err := decodeResourceMetrics(msg)
			if err != nil {
				return metricsData{}, err
			}
			out.resourceMetrics = append(out.resourceMetrics, rm)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return metricsData{}, fmt.Errorf("otlp: bad field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeResourceMetrics(b []byte) (resourceMetrics, error) {
	var out resourceMetrics
	var counts decodeCounts
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return resourceMetrics{}, fmt.Errorf("otlp: bad resource_metrics tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldResourceMetricsResource && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return resourceMetrics{}, fmt.Errorf("otlp: bad resource: %w", protowire.ParseError(n))
			}
			b = b[n:]
			res, err := decodeResource(msg, &counts)
			if err != nil {
				return resourceMetrics{}, err
			}
			out.resource = res
		case num == fieldResourceMetricsScopeMetrics && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return resourceMetrics{}, fmt.Errorf("otlp: bad scope_metrics: %w", protowire.ParseError(n))
			}
			b = b[n:]
			sm, err := decodeScopeMetrics(msg)
			if err != nil {
				return resourceMetrics{}, err
			}
			out.scopeMetrics = append(out.scopeMetrics, sm)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return resourceMetrics{}, fmt.Errorf("otlp: bad resource_metrics field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}

func decodeScopeMetrics(b []byte) (scopeMetrics, error) {
	var out scopeMetrics
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return scopeMetrics{}, fmt.Errorf("otlp: bad scope_metrics tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldScopeMetricsMetrics && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return scopeMetrics{}, fmt.Errorf("otlp: bad metric: %w", protowire.ParseError(n))
			}
			b = b[n:]
			m, err := decodeMetric(msg)
			if err != nil {
				return scopeMetrics{}, err
			}
			out.metrics = append(out.metrics, m)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return scopeMetrics{}, fmt.Errorf("otlp: bad scope_metrics field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeMetric(b []byte) (metricData, error) {
	var out metricData
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return metricData{}, fmt.Errorf("otlp: bad metric tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldMetricName && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return metricData{}, fmt.Errorf("otlp: bad metric name: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.name = v
		case num == fieldMetricDescription && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return metricData{}, fmt.Errorf("otlp: bad metric desc: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.description = v
		case num == fieldMetricUnit && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return metricData{}, fmt.Errorf("otlp: bad metric unit: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.unit = v
		case (num == fieldMetricSum || num == fieldMetricGauge) && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return metricData{}, fmt.Errorf("otlp: bad metric data: %w", protowire.ParseError(n))
			}
			b = b[n:]
			dps, err := decodeDataPoints(msg)
			if err != nil {
				return metricData{}, err
			}
			out.dataPoints = append(out.dataPoints, dps...)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return metricData{}, fmt.Errorf("otlp: bad metric field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}

func decodeDataPoints(b []byte) ([]metricDataPoint, error) {
	var out []metricDataPoint
	var counts decodeCounts
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("otlp: bad datapoints tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldDataPoints && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return nil, fmt.Errorf("otlp: bad datapoint: %w", protowire.ParseError(n))
			}
			b = b[n:]
			dp, err := decodeDataPoint(msg, &counts)
			if err != nil {
				return nil, err
			}
			out = append(out, dp)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return nil, fmt.Errorf("otlp: bad datapoint field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeDataPoint(b []byte, counts *decodeCounts) (metricDataPoint, error) {
	var out metricDataPoint
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return metricDataPoint{}, fmt.Errorf("otlp: bad datapoint tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldDataPointAttributes && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return metricDataPoint{}, fmt.Errorf("otlp: bad datapoint attr: %w", protowire.ParseError(n))
			}
			b = b[n:]
			kv, err := decodeKeyValue(msg, counts, 0)
			if err != nil {
				return metricDataPoint{}, err
			}
			out.attributes = append(out.attributes, kv)
		case num == fieldDataPointTimeUnixNano && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return metricDataPoint{}, fmt.Errorf("otlp: bad time_unix_nano: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.timeUnixNano = v
		case num == fieldDataPointAsInt && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return metricDataPoint{}, fmt.Errorf("otlp: bad as_int: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.asInt = int64(v)
		case num == fieldDataPointAsDouble && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return metricDataPoint{}, fmt.Errorf("otlp: bad as_double: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.asDouble = float64(v)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return metricDataPoint{}, fmt.Errorf("otlp: bad datapoint field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}
