package extract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// artifactCodexRollout is the Evidence.ArtifactType for Codex CLI session
// rollout files (~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl[.zst]).
const artifactCodexRollout = "codex_rollout"

// CodexExtractor parses Codex CLI rollout files. Codex writes one JSON object
// per line, each a {"timestamp","type","payload"} RolloutLine. The first line
// is a session_meta carrying the thread id and working directory; subsequent
// lines are response_item (the OpenAI Responses API ground truth: messages,
// tool calls, tool outputs), event_msg (higher-level derivatives), turn_context
// (per-turn working directory), and compacted (history summaries).
//
// See codex-rs/protocol/src/protocol.rs for the persisted rollout variants.
//
// Two layers persist the same activity: a user prompt is written BOTH as a
// response_item message AND as an event_msg user_message; an apply_patch shows
// up as a function_call AND a patch_apply_end. To avoid double-counting the
// timeline, numbat treats the response_item layer as canonical (it is the raw
// model I/O) and emits from event_msg only the records with no response_item
// equivalent that still carry forensic signal — a turn that aborted and history
// that was rolled back. This mirrors the persistence policy in
// codex-rs/rollout/src/policy.rs, where both layers are written to disk.
//
// Codex rollouts are append-only and event-ordered: unlike Gemini, the file is
// not a mutable history that must be replayed into a canonical conversation, so
// numbat walks it line by line like the Claude transcript parser. session_meta
// and turn_context update the running session identity / working directory that
// later events inherit but are not themselves emitted as events.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value (the default cap).
type CodexExtractor struct {
	maxBytes int
}

// Agent identifies the events this extractor produces.
func (CodexExtractor) Agent() string { return model.AgentCodex }

// codexState is the running session identity carried across lines: the thread
// id from the first session_meta and the working directory, which session_meta
// seeds and each turn_context updates. Every emitted event is stamped with the
// current values so a project path is attributed even when it changes mid-file.
type codexState struct {
	sessionID   string
	projectPath string
	// startIdx is the index of the synthetic session.start event in res.Events,
	// valid only when started is set, so session.end can mirror its identity.
	started  bool
	startIdx int
	// lastTimestamp/lastLine track the most recently seen rollout line so
	// session.end is stamped with the close of the artifact rather than reusing
	// the opener's timestamp and provenance.
	lastTimestamp string
	lastLine      int
	// shellCallIDs is the set of call_ids that were a shell command.exec (a
	// local_shell_call or a shell/shell_command/exec_command function_call), so
	// the paired function_call_output is promoted from tool.result to
	// command.result. A non-shell call's id never enters the set.
	shellCallIDs map[string]struct{}
	// codeMode correlates static exec cells through Codex's internal wait/poll
	// calls so long-running commands keep one semantic identity.
	codeMode codexCodeModeTracker
	// failedMCPCallIDs is the set of call_ids whose mcp_tool_call_end recorded a
	// structured failure. A custom_tool_call_output emitted AFTER its end-event
	// consults this so it still carries the tool-error signal regardless of the
	// order the two layers land in the rollout.
	failedMCPCallIDs map[string]struct{}
}

// noteFailedMCPCall records a call_id whose mcp_tool_call_end reported failure,
// so a not-yet-emitted custom_tool_call_output for it is tagged on arrival.
func (st *codexState) noteFailedMCPCall(id string) {
	if id == "" {
		return
	}
	if st.failedMCPCallIDs == nil {
		st.failedMCPCallIDs = map[string]struct{}{}
	}
	st.failedMCPCallIDs[id] = struct{}{}
}

// takeFailedMCPCall consumes a deferred MCP failure for a tool result.
func (st *codexState) takeFailedMCPCall(id string) bool {
	_, ok := st.failedMCPCallIDs[id]
	delete(st.failedMCPCallIDs, id)
	return ok
}

// noteShellCall records a shell call_id so its paired output correlates to a
// command.result.
func (st *codexState) noteShellCall(id string) {
	if id == "" {
		return
	}
	if st.shellCallIDs == nil {
		st.shellCallIDs = map[string]struct{}{}
	}
	st.shellCallIDs[id] = struct{}{}
}

// takeShellCall consumes the command owner for a function-call output.
func (st *codexState) takeShellCall(id string) bool {
	_, ok := st.shellCallIDs[id]
	delete(st.shellCallIDs, id)
	return ok
}

func (st *codexState) resetCall(id string) {
	delete(st.shellCallIDs, id)
	delete(st.failedMCPCallIDs, id)
	st.codeMode.forgetCall(id)
}

// Extract parses a Codex rollout file. It reads the whole artifact to stamp a
// content hash on every event's evidence, then walks it line by line. The first
// session_meta is canonical for session identity; turn_context lines refresh
// the working directory. Malformed or over-long lines are recorded as
// diagnostics and skipped, because forensic inputs are frequently truncated.
//
// The reader is expected to deliver decompressed bytes: cold rollout files are
// zstd-compressed (.jsonl.zst) but decompression is a discovery/transport
// concern, so the parser always sees plain JSONL.
func (e CodexExtractor) Extract(r io.Reader, src Source) (*Result, error) {
	limit := e.maxBytes
	if limit <= 0 {
		limit = defaultMaxArtifactSize
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", src.Path, err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("read %q: exceeds %d bytes", src.Path, limit)
	}
	sha := model.HashContent(data)

	// The cross-session prompt history shares the agent and the .jsonl
	// extension but not the rollout schema; it is selected by path, like
	// Gemini's logs.json-vs-checkpoint split.
	if isCodexHistory(src.Path) {
		return e.extractHistory(data, sha, src)
	}

	res := &Result{}
	st := &codexState{}
	br := bufio.NewReader(bytes.NewReader(data))
	for line := 1; ; line++ {
		raw, tooLong, err := readLine(br)
		if tooLong {
			res.diag(src.Path, line, "line exceeds size cap; skipped")
			if errors.Is(err, io.EOF) {
				// A truncated final line still ends the stream: close the session
				// so a capped rollout is not left with a start and no end.
				e.emitSessionEnd(res, src, sha, st)
				return res, nil
			}
			continue
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 {
			e.mapLine(res, src, sha, st, line, raw)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				e.emitSessionEnd(res, src, sha, st)
				return res, nil
			}
			return nil, fmt.Errorf("read %q line %d: %w", src.Path, line, err)
		}
	}
}

// emitSessionEnd closes the session at end of stream. It mirrors the
// session.start identity and the running project path (which turn_context may
// have moved), but stamps the LAST observed timestamp and closing line as its
// provenance rather than reusing the opener's. There is no single honest
// closing record to point a JSONPointer at, so the end carries artifact-level
// evidence (path/line/hash) with an empty pointer.
func (e CodexExtractor) emitSessionEnd(res *Result, src Source, sha string, st *codexState) {
	if !st.started {
		return
	}
	ev := res.Events[st.startIdx]
	ev.EventType = model.EventSessionEnd
	ev.EventID = strings.TrimSuffix(ev.EventID, ".start") + ".end"
	ev.ProjectPath = st.projectPath
	if st.lastTimestamp != "" {
		ev.Timestamp = st.lastTimestamp
	}
	ev.Evidence = model.Evidence{
		ArtifactType: artifactCodexRollout,
		LocalPath:    src.Path,
		Line:         st.lastLine,
		SHA256:       sha,
	}
	res.Events = append(res.Events, ev)
}

// mapLine decodes one rollout line and dispatches on the outer "type".
func (e CodexExtractor) mapLine(res *Result, src Source, sha string, st *codexState, line int, raw []byte) {
	var rl codexLine
	if err := json.Unmarshal(raw, &rl); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	if rl.Timestamp != "" {
		st.lastTimestamp = rl.Timestamp
	}
	st.lastLine = line
	switch rl.Type {
	case codexTypeSessionMeta:
		e.applySessionMeta(res, src, sha, st, line, rl.Timestamp, rl.Payload)
	case codexTypeTurnContext:
		e.applyTurnContext(st, rl.Payload)
	case codexTypeResponseItem:
		e.mapResponseItem(res, src, sha, st, line, rl.Timestamp, rl.Payload, src.fullProfile())
	case codexTypeEventMsg:
		e.mapEventMsg(res, src, sha, st, line, rl.Timestamp, rl.Payload)
	case codexTypeCompacted:
		// A history-compaction summary, not agent activity. Skip it like
		// Claude's summary records.
	case "":
		res.diag(src.Path, line, "rollout line missing type")
	default:
		// A future/unknown outer type. Skip rather than diagnose so a format
		// addition is not reported as corruption on every line.
	}
}

// applySessionMeta seeds the running session identity from the first
// session_meta line. Later session_meta lines (resumed sessions re-emit one)
// are ignored for identity — the first is canonical — but a cwd is still taken
// if the running path is empty, so a resume without a leading turn_context
// still attributes a project path. session_meta emits no event itself.
func (e CodexExtractor) applySessionMeta(res *Result, src Source, sha string, st *codexState, line int, ts string, payload json.RawMessage) {
	var meta codexSessionMeta
	if err := json.Unmarshal(payload, &meta); err != nil {
		res.diag(src.Path, line, "malformed session_meta payload")
		return
	}
	if st.sessionID == "" {
		st.sessionID = meta.ID
	}
	if st.projectPath == "" {
		st.projectPath = meta.Cwd
	}
	if st.started {
		return
	}
	// The first session_meta opens the session: emit a session.start carrying
	// the session-context the rollout header records (the cli version, the model
	// provider). The model id is not in session_meta, so it stays empty.
	ev := e.base(src, sha, st, line, ts, 0)
	ev.EventType = model.EventSessionStart
	// The session.start is a synthetic per-session record; its id carries a
	// ".start" suffix so it stays distinct and pairs cleanly with the ".end".
	ev.EventID = ev.EventID + ".start"
	ev.Actor = model.ActorSystem
	ev.Confidence = model.ConfidenceHigh
	ev.CLIVersion = meta.CliVersion
	if src.fullProfile() {
		ev.ModelProvider = meta.ModelProvider
	}
	ev.Evidence.JSONPointer = "/payload"
	st.startIdx = len(res.Events)
	st.started = true
	res.Events = append(res.Events, ev)
}

// applyTurnContext refreshes the working directory from a turn_context line.
// One is written before each turn of a resumed session, so the project path
// tracks the directory the agent was actually working in for the events that
// follow. An empty cwd leaves the running path unchanged.
func (e CodexExtractor) applyTurnContext(st *codexState, payload json.RawMessage) {
	var tc codexTurnContext
	if json.Unmarshal(payload, &tc) != nil {
		return
	}
	if tc.Cwd != "" {
		st.projectPath = tc.Cwd
	}
}

// mapResponseItem decodes a response_item payload and emits an event for the
// variant. This is the canonical timeline layer. Reasoning and tool outputs
// that carry no distinct activity are handled per-variant; an unknown variant
// falls through to a generic tool.call only when it looks like a tool call,
// otherwise it is skipped quietly.
func (e CodexExtractor) mapResponseItem(res *Result, src Source, sha string, st *codexState, line int, ts string, payload json.RawMessage, full bool) {
	var ri codexResponseItem
	if err := json.Unmarshal(payload, &ri); err != nil {
		res.diag(src.Path, line, "malformed response_item payload")
		return
	}
	switch ri.Type {
	case codexRIMessage:
		e.emitMessage(res, src, sha, st, line, ts, &ri)
	case codexRIFunctionCall:
		st.resetCall(ri.CallID)
		if ri.Name == codexToolWait && ri.Namespace == "" && st.codeMode.noteWait(ri.CallID, string(ri.Arguments)) {
			return
		}
		e.emitFunctionCall(res, src, sha, st, line, ts, &ri)
	case codexRILocalShellCall:
		st.resetCall(ri.CallID)
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = codexToolShell
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventCommandExec
		ev.Command = decodeCodexShellAction(ri.Action)
		ev.Evidence.JSONPointer = "/payload/action"
		st.noteShellCall(ri.CallID)
		res.Events = append(res.Events, ev)
	case codexRICustomToolCall:
		// A new call owns a reused id and its next output.
		st.resetCall(ri.CallID)
		if ri.Name == codexToolApplyPatch {
			e.emitApplyPatchCall(res, src, sha, st, line, ts, ri.Name, ri.CallID, string(ri.Input), "/payload/input")
			return
		}
		if ri.Name == codexToolCodeModeExec {
			if call, ok := parseCodexCodeModeExec(string(ri.Input)); ok {
				ev := e.base(src, sha, st, line, ts, 0)
				ev.Actor = model.ActorAssistant
				ev.Confidence = model.ConfidenceHigh
				ev.ToolName = codexToolExecCommand
				ev.ToolCallID = ri.CallID
				ev.EventType = model.EventCommandExec
				ev.Command = call.command
				ev.Evidence.JSONPointer = "/payload/input"
				st.codeMode.noteExec(ri.CallID, call.resultKind)
				res.Events = append(res.Events, ev)
				return
			}
			if st.codeMode.noteWriteStdinPoll(ri.CallID, string(ri.Input)) {
				return
			}
		}
		// A freeform/custom (often MCP-routed) tool call. The name is the only
		// reliably structured field; the input is freeform text. Surface it as
		// a generic tool.call so coverage never drops a call, with the input
		// previewed so a reviewer sees WHAT was requested (e.g. the SQL a
		// db.query tool ran), not just that a call occurred. An MCP-qualified
		// name additionally splits into the typed server/tool fields.
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventToolCall
		ev.ContentPreview = preview(string(ri.Input))
		ev.Evidence.JSONPointer = "/payload/input"
		// An MCP-qualified name splits into typed server/tool fields; when the name
		// is not itself flattened, Codex records the server as a separate namespace
		// (mcp__<server>), so fall back to that — mirroring the function_call path.
		if server, tool, ok := splitMCPName(ri.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		} else if server, ok := codexMCPNamespaceServer(ri.Namespace); ok {
			ev.MCPServer, ev.MCPTool = server, ri.Name
		}
		res.Events = append(res.Events, ev)
	case codexRIFunctionCallOutput, codexRICustomToolCallOut:
		// Tool result. The output is the tool's returned bytes — command stdout,
		// file contents, an MCP response — and is the single richest source of
		// exfiltrated secrets or attacker-controlled data in a session, so it is
		// previewed (string-or-array decoded) rather than recorded as a bare
		// "a result happened".
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolCallID = ri.CallID
		resultBody := decodeCodexOutput(ri.Output)
		ev.Evidence.JSONPointer = "/payload/output"
		// Outputs correlated to a shell call are command.result updates. Static
		// code-mode calls may traverse internal wait/write_stdin calls; those are
		// folded back into the original command identity.
		//
		// Legacy shell outputs persist only prose, so their exit status remains
		// unset. Current code-mode outputs can carry the exec helper's structured
		// result; decode it only when the statically parsed cell forwarded that
		// object, never by interpreting JSON-looking stdout.
		//
		// An MCP tool failure, by contrast, IS recoverable: the persisted
		// mcp_tool_call_end carries a structured Result keyed by this call_id, and
		// mapEventMsg stamps TagToolError on this tool.result when it records a
		// failure. When the end-event already arrived (it preceded this output), the
		// failure was recorded in state, so tag here too.
		var codeModeRef codexCodeModeResultRef
		var codeModeResult bool
		switch ri.Type {
		case codexRICustomToolCallOut:
			codeModeRef, codeModeResult = st.codeMode.takeCustomCall(ri.CallID)
		case codexRIFunctionCallOutput:
			codeModeRef, codeModeResult = st.codeMode.takeWaitCall(ri.CallID)
		}
		shellResult := ri.Type == codexRIFunctionCallOutput && st.takeShellCall(ri.CallID)
		if codeModeResult || shellResult {
			ev.EventType = model.EventCommandResult
			if codeModeResult {
				ev.ToolName = codexToolExecCommand
				outcome := st.codeMode.trackOutcome(codeModeRef, ri.Output)
				if outcome.cellID != "" {
					return
				}
				ev.ToolCallID = codeModeRef.commandCallID
				resultBody = outcome.output
				ev.ExitCode = outcome.exitCode
				ev.DurationMs = outcome.durationMs
				if outcome.toolError {
					ev.Tags = append(ev.Tags, model.TagToolError)
				}
				if !outcome.recognized {
					res.diag(src.Path, line, "unrecognized code-mode result envelope")
				}
			}
		} else {
			ev.EventType = model.EventToolResult
			if st.takeFailedMCPCall(ri.CallID) {
				ev.Tags = append(ev.Tags, model.TagToolError)
			}
		}
		ev.ContentPreview = preview(resultBody)
		res.Events = append(res.Events, ev)
	case codexRIToolSearchOutput:
		// The result of a tool_search_call (the model discovering which tools
		// exist). Unlike function_call_output, the wire shape carries no free-form
		// "output" string; the result is a list of tool definitions under "tools"
		// (ToolSearchOutput in models.rs). numbat surfaces the discovered tool
		// names — a useful lead when an unexpected tool is later invoked.
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolResult
		ev.ToolCallID = ri.CallID
		ev.ContentPreview = preview(decodeCodexToolSearchTools(ri.Tools))
		ev.Evidence.JSONPointer = "/payload/tools"
		res.Events = append(res.Events, ev)
	case codexRIWebSearchCall:
		// Network egress: exactly what a DFIR reviewer hunts for. The action
		// locator (search query, opened url, find-in-page pattern) is previewed
		// so the indicator names WHAT left the box, not just that egress
		// occurred.
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventNetworkIndicator
		ev.ToolCallID = ri.CallID
		ev.ContentPreview = preview(decodeCodexWebSearchAction(ri.Action))
		// When the action opened/searched a concrete url (open_page,
		// find_in_page), promote it to the typed URL field so the egress target
		// is first-class; a bare search query has no url and leaves it empty.
		ev.URL = networkTargetURL(codexWebSearchURL(ri.Action))
		ev.Tags = []string{model.TagNetwork}
		ev.Evidence.JSONPointer = "/payload/action"
		res.Events = append(res.Events, ev)
	case codexRIToolSearchCall:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolCall
		ev.ToolName = codexToolSearch
		ev.ToolCallID = ri.CallID
		ev.ContentPreview = preview(codexArgString(string(ri.Arguments), "query"))
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.Events = append(res.Events, ev)
	case codexRIImageGenerationCall:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolCall
		ev.ToolName = codexToolImage
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload"
		res.Events = append(res.Events, ev)
	case codexRICompaction, codexRICompactionSummary, codexRIContextCompaction:
		// Inner history-compaction variants. The Compaction body carries only
		// opaque encrypted_content and ContextCompaction an optional encrypted
		// blob — neither holds a human-readable summary (verified against
		// models.rs). The reader-facing summary lives on the OUTER "compacted"
		// rollout line, handled in mapLine. These inner variants are therefore
		// an explicit no-op: there is nothing faithful to surface, and saying so
		// here keeps them distinct from a silent unknown-variant fallthrough.
	case codexRIReasoning:
		// Model reasoning is opt-in: it is context, not forensic evidence of an
		// action (mirrors Claude's thinking-block handling), so it surfaces only
		// under the full profile. The reasoning text lives in the summary array
		// (ReasoningItemReasoningSummary in models.rs); an empty body yields
		// nothing.
		if !full {
			break
		}
		text := strings.TrimSpace(decodeCodexReasoningText(ri.Summary, ri.Content))
		if text == "" {
			break
		}
		ev := e.base(src, sha, st, line, ts, 0)
		ev.EventType = model.EventMessageReasoning
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ContentPreview = preview(text)
		ev.Evidence.JSONPointer = "/payload"
		res.Events = append(res.Events, ev)
	case "":
		res.diag(src.Path, line, "response_item missing inner type")
	default:
		// Unknown response_item variant: skip rather than diagnose so a format
		// addition is not flagged as corruption.
	}
}

// emitMessage emits a prompt.user or message.assistant from a response_item
// message. role determines the actor; developer/system messages are skipped
// (instructions, not agent activity). An empty text body yields nothing.
func (e CodexExtractor) emitMessage(res *Result, src Source, sha string, st *codexState, line int, ts string, ri *codexResponseItem) {
	text := strings.TrimSpace(decodeCodexContentText(ri.Content))
	if text == "" {
		return
	}
	ev := e.base(src, sha, st, line, ts, 0)
	ev.Confidence = model.ConfidenceHigh
	ev.ContentPreview = preview(text)
	ev.Evidence.JSONPointer = "/payload/content"
	switch ri.Role {
	case "user":
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
	case "assistant":
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
	default:
		// developer/system: instructions injected into the context, not agent
		// activity. Skip.
		return
	}
	res.Events = append(res.Events, ev)
}

// emitFunctionCall maps a response_item function_call onto the normalized event
// vocabulary, lifting the forensically salient argument (shell command, file
// path, patched files) out of the tool's JSON-encoded arguments string. The
// shell tool's command may be a string or an argv array; apply_patch may touch
// several files, each emitted as its own file.write so the patched paths are
// first-class. Unknown tools fall back to a generic tool.call.
func (e CodexExtractor) emitFunctionCall(res *Result, src Source, sha string, st *codexState, line int, ts string, ri *codexResponseItem) {
	switch ri.Name {
	case codexToolShell, codexToolShellCommand, codexToolExecCommand:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventCommandExec
		ev.Command = codexShellCommand(string(ri.Arguments))
		ev.Evidence.JSONPointer = "/payload/arguments"
		st.noteShellCall(ri.CallID)
		res.Events = append(res.Events, ev)
	case codexToolApplyPatch:
		e.emitApplyPatchCall(res, src, sha, st, line, ts, ri.Name, ri.CallID, string(ri.Arguments), "/payload/arguments")
	case codexToolReadFile:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventFileRead
		ev.FilePath = codexArgString(string(ri.Arguments), "path")
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.Events = append(res.Events, ev)
	case codexToolWriteFile, codexToolEditFile:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventFileWrite
		ev.FilePath = codexArgString(string(ri.Arguments), "path")
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.Events = append(res.Events, ev)
	default:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload/arguments"
		if isCodexMCPFetch(ri.Namespace, ri.Name) {
			// Network egress via the canonical MCP fetch server
			// (modelcontextprotocol/servers src/fetch). Codex routes MCP tools
			// through function_call: depending on Codex version the server/tool
			// pair arrives either flattened as name "mcp__fetch__fetch" or split
			// as namespace "mcp__fetch" (or "mcp__fetch__") + name "fetch". Either
			// way it is the same documented egress tool, whose JSON arguments carry
			// {url, ...}; we
			// surface it on a network indicator naming the url that left the box,
			// mirroring the Claude mcp__fetch__fetch handling. Exact-identity match
			// on the canonical fetch server only, never a heuristic on arbitrary
			// MCP names — every other MCP call stays a generic tool.call below.
			url := codexArgString(string(ri.Arguments), "url")
			ev.EventType = model.EventNetworkIndicator
			ev.URL = networkTargetURL(url)
			ev.ContentPreview = preview(url)
			ev.Tags = []string{model.TagNetwork}
			ev.MCPServer, ev.MCPTool = "fetch", "fetch"
			res.Events = append(res.Events, ev)
			return
		}
		// update_plan, other MCP-namespaced calls, and every other tool map to a
		// generic call, preserving coverage for future/unknown tools; the full
		// name (incl. any mcp__ prefix) is retained as evidence. An MCP-qualified
		// name additionally splits into the typed server/tool fields so a rule or
		// SIEM can pivot without re-parsing the flattened name. Codex also records
		// the server separately as a namespace; when the name is not itself
		// flattened, fall back to that namespace.
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(ri.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		} else if server, ok := codexMCPNamespaceServer(ri.Namespace); ok {
			ev.MCPServer, ev.MCPTool = server, ri.Name
		}
		res.Events = append(res.Events, ev)
	}
}

// emitApplyPatchCall maps both function_call arguments and custom_tool_call
// input through the same patch parser. These records capture requested changes;
// they do not prove that the patch completed.
func (e CodexExtractor) emitApplyPatchCall(res *Result, src Source, sha string, st *codexState, line int, ts, toolName, callID, patch, pointer string) {
	changes := codexApplyPatchChanges(patch)
	diffSHA, diffBytes := codexApplyPatchDiff(patch)
	if len(changes) == 0 {
		changes = []codexPatchChange{{}}
	}
	for i, change := range changes {
		ev := e.base(src, sha, st, line, ts, i)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceMedium
		ev.ToolName = toolName
		ev.ToolCallID = callID
		ev.EventType = model.EventFileWrite
		if change.Delete {
			ev.EventType = model.EventFileDelete
		}
		ev.FilePath = change.Path
		ev.DiffSHA256 = diffSHA
		ev.DiffBytes = diffBytes
		ev.Tags = []string{codexTagPatchRequested}
		ev.Evidence.JSONPointer = pointer
		res.Events = append(res.Events, ev)
	}
}

// mapEventMsg decodes an event_msg payload's inner discriminator and emits only
// the records the response_item layer does not carry: a turn that aborted
// (interrupted/replaced/budget-limited), history that was rolled back, and the
// review-mode / thread-goal state transitions that have no response_item twin.
// All are low-confidence system notes tagged with the record type so the signal
// is visible rather than a silent gap. Every other event_msg type duplicates a
// response_item record and is skipped.
func (e CodexExtractor) mapEventMsg(res *Result, src Source, sha string, st *codexState, line int, ts string, payload json.RawMessage) {
	var em codexEventMsg
	if err := json.Unmarshal(payload, &em); err != nil {
		res.diag(src.Path, line, "malformed event_msg payload")
		return
	}
	switch em.Type {
	case codexEMTurnAborted:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceLow
		ev.Evidence.JSONPointer = "/payload"
		if em.Reason != "" {
			ev.ContentPreview = preview("turn aborted: " + em.Reason)
		}
		ev.Tags = []string{codexEMTurnAborted}
		res.Events = append(res.Events, ev)
	case codexEMThreadRolledBack:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceLow
		ev.Evidence.JSONPointer = "/payload"
		ev.Tags = []string{codexEMThreadRolledBack}
		res.Events = append(res.Events, ev)
	case codexEMEnteredReviewMode, codexEMExitedReviewMode, codexEMThreadGoalUpdated:
		// Session-state transitions with NO response_item twin (verified against
		// policy.rs should_persist_event_msg): the agent entering/leaving a
		// constrained review mode, or its thread goal being rewritten. These are
		// not duplicates of the canonical layer, so — unlike user_message/
		// agent_message/patch_apply_end — they are surfaced as low-confidence
		// system notes, tagged with the transition type, so the state change is
		// on the timeline rather than silently lost.
		ev := e.base(src, sha, st, line, ts, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceLow
		ev.Evidence.JSONPointer = "/payload"
		ev.Tags = []string{em.Type}
		res.Events = append(res.Events, ev)
	case codexEMMcpToolCallEnd:
		// The response_item layer already emitted the tool.call/tool.result for
		// this MCP invocation, so this end-event is NOT re-emitted as its own
		// timeline event (that would double-count). It is read only for its
		// structured result: when that result records a failure, the existing
		// tool.result for the same call_id is tagged TagToolError — the same
		// structured-failure signal Claude/Gemini stamp — so an at-rest MCP tool
		// failure is not a false negative. Only the structured Result is consulted;
		// no prose body is scraped. A success or an unrecognized result shape
		// leaves the tool.result untagged.
		if isErr, ok := codexMcpResultIsError(em.Result); ok && isErr {
			if !markToolResultError(res, em.CallID) {
				// The output has not been emitted yet (end-event preceded it);
				// remember the failure so the later custom_tool_call_output is tagged.
				st.noteFailedMCPCall(em.CallID)
			}
		}
	default:
		// user_message/agent_message/patch_apply_end/... all duplicate a
		// response_item record; skip to keep the timeline single-counted.
		// Unknown/unpersisted types are skipped too.
		//
		// No permission.requested/approved/denied is emitted here: the rollout does
		// not persist a per-request approval decision. Codex's approval flow
		// (ExecApprovalRequest/ApplyPatchApprovalRequest/RequestPermissions) is
		// routed over the app-server JSON-RPC protocol and is explicitly NOT written
		// to disk — codex-rs/rollout/src/policy.rs should_persist_event_msg returns
		// false for every approval variant — and tool_decision is an OTel exporter
		// event (otel/src/events/session_telemetry.rs), never a RolloutItem. The
		// permission.* vocabulary therefore stays reserved for a future on-disk
		// signal rather than being synthesized from a heuristic.
	}
}

// markToolResultError stamps TagToolError on the already-emitted tool.result
// for callID (the custom_tool_call_output the response_item layer produced for
// an MCP invocation), scanning newest-first since the result is the most recent
// matching event. It reports whether such a tool.result was found, so the caller
// can fall back to recording the failure in state when the end-event arrived
// before the output. The tag is added only once.
func markToolResultError(res *Result, callID string) bool {
	if callID == "" {
		return false
	}
	for i := len(res.Events) - 1; i >= 0; i-- {
		ev := &res.Events[i]
		if ev.EventType != model.EventToolResult || ev.ToolCallID != callID {
			continue
		}
		for _, tag := range ev.Tags {
			if tag == model.TagToolError {
				return true
			}
		}
		ev.Tags = append(ev.Tags, model.TagToolError)
		return true
	}
	return false
}

// base builds the evidence- and identity-stamped event skeleton shared by every
// event derived from a rollout line. idx keeps EventID unique when one line
// emits several events (an apply_patch touching multiple files).
func (e CodexExtractor) base(src Source, sha string, st *codexState, line int, ts string, idx int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       codexEventID(src.Path, line, idx),
		SourceAgent:   model.AgentCodex,
		SourceType:    model.SourceArtifact,
		Timestamp:     ts,
		ProjectPath:   st.projectPath,
		SessionID:     st.sessionID,
		Evidence: model.Evidence{
			ArtifactType: artifactCodexRollout,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}
