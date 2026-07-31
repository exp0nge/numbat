package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestExtractCodexCodeModeCommandAndResult(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"printf 'hello\\n'", workdir:"/tmp", yield_time_ms:10000, max_output_tokens:2000}); text(r.output);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"e1","output":"hello"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2: %s", len(acts), dumpEvents(acts))
	}
	call, result := acts[0], acts[1]
	if call.EventType != model.EventCommandExec || call.Command != "printf 'hello\\n'" || call.ToolName != codexToolExecCommand {
		t.Errorf("call = %+v, want one decoded command.exec", call)
	}
	if result.EventType != model.EventCommandResult || result.ToolCallID != call.ToolCallID || result.ContentPreview != "hello" {
		t.Errorf("result = %+v, want correlated command.result", result)
	}
	if call.Evidence.JSONPointer != "/payload/input" {
		t.Errorf("call evidence pointer = %q, want /payload/input", call.Evidence.JSONPointer)
	}
}

func TestCodexCodeModeCommandAcceptsDocumentedPragmaAndQuotedKeys(t *testing.T) {
	input := "// @exec: {\"yield_time_ms\": 10000}\n" +
		`const result = await tools.exec_command({"cmd":"git status","workdir":"/repo",}); text(JSON.stringify(result));`
	command, ok := codexCodeModeExecCommand(input)
	if !ok || command != "git status" {
		t.Fatalf("command = %q, ok = %v, want git status/true", command, ok)
	}
}

func TestCodexCodeModeCommandAcceptsASIStatementBoundary(t *testing.T) {
	input := "const result = await tools.exec_command({cmd:\"git status\"})\ntext(result.output)"
	command, ok := codexCodeModeExecCommand(input)
	if !ok || command != "git status" {
		t.Fatalf("command = %q, ok = %v, want git status/true", command, ok)
	}
}

func TestExtractCodexAmbiguousCodeModeExecStaysGeneric(t *testing.T) {
	tests := map[string]string{
		"dynamic command":         `const r = await tools.exec_command({cmd: command}); text(r.output);`,
		"template command":        "const r = await tools.exec_command({cmd: `git ${verb}`}); text(r.output);",
		"duplicate command":       `const r = await tools.exec_command({cmd:"git status", cmd:other}); text(r.output);`,
		"spread may override":     `const r = await tools.exec_command({cmd:"git status", ...options}); text(r.output);`,
		"leading computation":     `const command = "git status"; const r = await tools.exec_command({cmd:command}); text(r.output);`,
		"second nested tool":      `const r = await tools.exec_command({cmd:"git status"}); await tools.write_stdin({session_id:r.session_id});`,
		"parallel nested tools":   `const rs = await Promise.all([tools.exec_command({cmd:"git status"}), tools.exec_command({cmd:"git diff"})]); text(rs);`,
		"additional statement":    `const r = await tools.exec_command({cmd:"git status"}); text(r.output); exit();`,
		"missing statement break": `const r = await tools.exec_command({cmd:"git status"}) text(r.output);`,
		"reserved binding":        `const await = await tools.exec_command({cmd:"git status"});`,
		"split text identifier":   `const r = await tools.exec_command({cmd:"git status"}); te xt(r);`,
		"split output identifier": `const r = await tools.exec_command({cmd:"git status"}); text(r.out put);`,
		"shadowed text helper":    `const text = await tools.exec_command({cmd:"git status"}); text(text);`,
		"shadowed JSON helper":    `const JSON = await tools.exec_command({cmd:"git status"}); text(JSON.stringify(JSON));`,
		"empty command":           `const r = await tools.exec_command({cmd:" "}); text(r.output);`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			line := `{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`
			acts := activityEvents(extractCodex(t, line).Events)
			if len(acts) != 1 || acts[0].EventType != model.EventToolCall || acts[0].ToolName != codexToolCodeModeExec || acts[0].Command != "" {
				t.Fatalf("events = %s, want one generic exec tool.call", dumpEvents(acts))
			}
		})
	}
}

func TestExtractCodexCodeModeOutputDoesNotCrossCallKinds(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"same","arguments":"{\"cmd\":\"true\"}"}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"same","input":"const r = await tools.exec_command({cmd:\"id\"}); text(r.output);"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"same","input":"await tools.exec_command({cmd: command})"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"rows"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 4 {
		t.Fatalf("got %d activity events, want 4: %s", len(acts), dumpEvents(acts))
	}
	if acts[3].EventType != model.EventToolResult {
		t.Fatalf("custom output = %s, want tool.result after reused custom-call id", acts[3].EventType)
	}
}

func FuzzCodexCodeModeExecCommand(f *testing.F) {
	for _, seed := range []string{
		`const r = await tools.exec_command({cmd:"git status"}); text(r.output);`,
		`const r = await tools.exec_command({cmd:dynamic});`,
		`const rs = await Promise.all([tools.exec_command({cmd:"a"}), tools.exec_command({cmd:"b"})]);`,
		"// @exec: {\"yield_time_ms\": 10}\nconst r = await tools.exec_command({cmd:\"go test ./...\"});",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		command, ok := codexCodeModeExecCommand(input)
		if ok && strings.TrimSpace(command) == "" {
			t.Fatal("accepted an empty command")
		}
	})
}
