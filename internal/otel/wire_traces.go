package otel

import (
	"fmt"
	"google.golang.org/protobuf/encoding/protowire"
)

type tracesData struct {
	resourceSpans []resourceSpans
}

type resourceSpans struct {
	resource   resource
	scopeSpans []scopeSpans
}

type scopeSpans struct {
	spans []spanData
}

type spanData struct {
	traceID           []byte
	spanID            []byte
	name              string
	kind              int32
	startTimeUnixNano uint64
	endTimeUnixNano   uint64
	attributes        []keyValue
}

const (
	fieldExportResourceSpans     = 1
	fieldResourceSpansResource   = 1
	fieldResourceSpansScopeSpans = 2
	fieldScopeSpansSpans         = 2

	fieldSpanTraceID           = 1
	fieldSpanID                = 2
	fieldSpanName              = 5
	fieldSpanKind              = 6
	fieldSpanStartTimeUnixNano = 7
	fieldSpanEndTimeUnixNano   = 8
	fieldSpanAttributes        = 9
)

func decodeTracesRequest(b []byte) (tracesData, error) {
	var out tracesData
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return tracesData{}, fmt.Errorf("otlp: bad traces tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldExportResourceSpans && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return tracesData{}, fmt.Errorf("otlp: bad resource_spans: %w", protowire.ParseError(n))
			}
			b = b[n:]
			rs, err := decodeResourceSpans(msg)
			if err != nil {
				return tracesData{}, err
			}
			out.resourceSpans = append(out.resourceSpans, rs)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return tracesData{}, fmt.Errorf("otlp: bad field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeResourceSpans(b []byte) (resourceSpans, error) {
	var out resourceSpans
	var counts decodeCounts
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return resourceSpans{}, fmt.Errorf("otlp: bad resource_spans tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldResourceSpansResource && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return resourceSpans{}, fmt.Errorf("otlp: bad resource: %w", protowire.ParseError(n))
			}
			b = b[n:]
			res, err := decodeResource(msg, &counts)
			if err != nil {
				return resourceSpans{}, err
			}
			out.resource = res
		case num == fieldResourceSpansScopeSpans && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return resourceSpans{}, fmt.Errorf("otlp: bad scope_spans: %w", protowire.ParseError(n))
			}
			b = b[n:]
			ss, err := decodeScopeSpans(msg)
			if err != nil {
				return resourceSpans{}, err
			}
			out.scopeSpans = append(out.scopeSpans, ss)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return resourceSpans{}, fmt.Errorf("otlp: bad resource_spans field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}

func decodeScopeSpans(b []byte) (scopeSpans, error) {
	var out scopeSpans
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return scopeSpans{}, fmt.Errorf("otlp: bad scope_spans tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldScopeSpansSpans && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return scopeSpans{}, fmt.Errorf("otlp: bad span: %w", protowire.ParseError(n))
			}
			b = b[n:]
			sp, err := decodeSpan(msg)
			if err != nil {
				return scopeSpans{}, err
			}
			out.spans = append(out.spans, sp)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return scopeSpans{}, fmt.Errorf("otlp: bad scope_spans field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeSpan(b []byte) (spanData, error) {
	var out spanData
	var counts decodeCounts
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return spanData{}, fmt.Errorf("otlp: bad span tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldSpanTraceID && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad trace_id: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.traceID = v
		case num == fieldSpanID && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad span_id: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.spanID = v
		case num == fieldSpanName && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad span name: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.name = v
		case num == fieldSpanKind && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad span kind: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.kind = int32(v)
		case num == fieldSpanStartTimeUnixNano && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad start_time_unix_nano: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.startTimeUnixNano = v
		case num == fieldSpanEndTimeUnixNano && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad end_time_unix_nano: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.endTimeUnixNano = v
		case num == fieldSpanAttributes && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad span attr: %w", protowire.ParseError(n))
			}
			b = b[n:]
			kv, err := decodeKeyValue(msg, &counts, 0)
			if err != nil {
				return spanData{}, err
			}
			out.attributes = append(out.attributes, kv)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return spanData{}, fmt.Errorf("otlp: bad span field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}
