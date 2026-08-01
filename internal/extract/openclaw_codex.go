package extract

import (
	"encoding/json"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// Codex-flavor mapping for OpenClaw transcripts. OpenClaw embeds Codex as one of
// its harnesses; when a Codex harness writes into the ~/.openclaw/agents tree it
// persists the Codex rollout wire format (outer {timestamp,type,payload} rows,
// response_item payloads), NOT the Anthropic ContentBlock shape. This path
// decodes that format with full fidelity, reusing the Codex wire helpers
// (codex_entry.go) so the two extractors stay in lockstep on the on-disk shape.
//
// Only the structurally-confirmed forensic signals are surfaced: function_call
// (shell→command.exec, apply_patch→file.write/delete, read/write/edit file,
// canonical MCP fetch→network.indicator, else tool.call), function_call_output
// (correlated by call_id to a command.result or tool.result), local_shell_call,
// and web_search_call. From the event_msg layer, only the records with no
// response_item twin are surfaced: a structured mcp_tool_call_end failure tags
// the matching tool.result TagToolError, and the no-twin state transitions
// (turn_aborted / thread_rolled_back / review-mode / thread-goal) become
// low-confidence system notes (see mapCodexEventMsg). Per the high-precision
// boundary, NO shell exit code is emitted (Codex's function_call_output carries
// no structured exit field — see codex.go) and a tool-error tag is set only from
// a structured field.

// mapCodexLine decodes one Codex-flavor OpenClaw line and dispatches on the
// outer record type. A malformed line is a diagnostic and is skipped; the rest of
// the file still parses. session_meta / turn_context seed and update the session
// working directory; response_item carries the tool/message timeline; event_msg
// is routed to mapCodexEventMsg, which surfaces only the no-response_item-twin
// signals (structured MCP tool-error, no-twin state transitions) and skips the
// duplicate types — mirroring the canonical Codex extractor (codex.go mapEventMsg).
func (e OpenClawExtractor) mapCodexLine(res *Result, src Source, sha string, st *openClawState, line int, raw []byte) {
	var lineRec codexLine
	if err := json.Unmarshal(raw, &lineRec); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	// Codex rollout rows carry their timestamp on the outer envelope. Reset it
	// for every row so a legacy/malformed row cannot inherit its predecessor.
	st.currentTimestamp = lineRec.Timestamp
	switch lineRec.Type {
	case openClawTypeSessionMeta:
		st.recognizedRows++
		var meta codexSessionMeta
		if json.Unmarshal(lineRec.Payload, &meta) == nil {
			if st.sessionID == "" {
				st.sessionID = meta.ID
			}
			if st.projectPath == "" {
				st.projectPath = meta.Cwd
			}
		}
	case openClawTypeTurnContext:
		st.recognizedRows++
		var tc codexTurnContext
		if json.Unmarshal(lineRec.Payload, &tc) == nil && tc.Cwd != "" {
			st.projectPath = tc.Cwd
		}
	case openClawTypeResponseItem:
		st.recognizedRows++
		e.mapCodexResponseItem(res, src, sha, st, line, lineRec.Payload)
	case openClawTypeEventMsg:
		// Most event_msg types duplicate a response_item record and are skipped, but
		// a few carry forensic signal with NO response_item twin: the structured MCP
		// tool-error and the no-twin state transitions. mapCodexEventMsg mirrors the
		// canonical Codex extractor (codex.go mapEventMsg) so an embedded-Codex
		// OpenClaw transcript does not silently drop those signals.
		st.recognizedRows++
		e.mapCodexEventMsg(res, src, sha, st, line, lineRec.Payload)
	case codexTypeCompacted:
		// A history-compaction summary, not agent activity. Treat it as a
		// recognized no-op, matching codex.go.
		st.recognizedRows++
	case "":
		res.diag(src.Path, line, "openclaw codex entry missing type")
	default:
		// A future/unknown Codex outer type: surface the gap rather than dropping it.
		res.diag(src.Path, line, "openclaw codex entry type is not modeled")
	}
}

// mapCodexResponseItem decodes a Codex response_item payload and emits an event
// for the variant. The mapping mirrors the Codex extractor (codex.go
// mapResponseItem) but routes through OpenClaw's event id/state so call↔result
// correlation and the tool-activity counter stay consistent with the native
// path. Reasoning/prose are emitted as message events (no preview beyond the
// prose norm); unknown variants are skipped quietly so a format addition is not
// flagged as corruption.
func (e OpenClawExtractor) mapCodexResponseItem(res *Result, src Source, sha string, st *openClawState, line int, payload json.RawMessage) {
	var ri codexResponseItem
	if err := json.Unmarshal(payload, &ri); err != nil {
		res.diag(src.Path, line, "malformed response_item payload")
		return
	}
	switch ri.Type {
	case codexRIMessage:
		e.emitCodexMessage(res, src, sha, st, line, &ri)
	case codexRIFunctionCall:
		e.emitCodexFunctionCall(res, src, sha, st, line, &ri)
	case codexRILocalShellCall:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = codexToolShell
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventCommandExec
		ev.Command = decodeCodexShellAction(ri.Action)
		ev.Evidence.JSONPointer = "/payload/action"
		st.noteCommandCall(ri.CallID)
		res.appendEvent(st, ev, true)
	case codexRIFunctionCallOutput, codexRICustomToolCallOut:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload/output"
		ev.ContentPreview = preview(decodeCodexOutput(ri.Output))
		// An output paired with the matching shell-call variant is a
		// command.result; every other output stays tool.result. No exit code is
		// emitted because Codex does not persist one in these response items.
		if (ri.Type == codexRIFunctionCallOutput && st.isCommandCall(ri.CallID)) ||
			(ri.Type == codexRICustomToolCallOut && st.takeCodexCodeModeCommandCall(ri.CallID)) {
			ev.EventType = model.EventCommandResult
		} else {
			ev.EventType = model.EventToolResult
			// An mcp_tool_call_end may have recorded this call's failure before its
			// output landed (out-of-order); carry the structured tool-error forward so
			// the late output is not a false negative, matching codex.go.
			if st.isFailedMCPCall(ri.CallID) {
				ev.Tags = append(ev.Tags, model.TagToolError)
			}
		}
		res.appendEvent(st, ev, true)
	case codexRIWebSearchCall:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventNetworkIndicator
		ev.ToolCallID = ri.CallID
		// Preview the action locator (search query, opened url, find-in-page
		// pattern) so the indicator names WHAT left the box, not just that egress
		// occurred — mirroring codex.go so a bare query keeps its investigative
		// lead even with no url to promote.
		ev.ContentPreview = preview(decodeCodexWebSearchAction(ri.Action))
		// The egress target must be a real http(s) url with a host; a bare search
		// query (no url) leaves URL empty rather than fabricating a target.
		if httpURL := networkTargetURL(codexWebSearchURL(ri.Action)); httpURL != "" {
			ev.URL = httpURL
		}
		ev.Tags = []string{model.TagNetwork}
		ev.Evidence.JSONPointer = "/payload/action"
		res.appendEvent(st, ev, true)
	case codexRICustomToolCall:
		// A later custom call reusing a malformed call id owns its next output.
		st.forgetCodexCodeModeCommandCall(ri.CallID)
		if ri.Name == codexToolCodeModeExec {
			if command, ok := codexCodeModeExecCommand(string(ri.Input)); ok {
				ev := e.base(src, sha, st, line, 0)
				ev.Actor = model.ActorAssistant
				ev.Confidence = model.ConfidenceHigh
				ev.ToolName = codexToolExecCommand
				ev.ToolCallID = ri.CallID
				ev.EventType = model.EventCommandExec
				ev.Command = command
				ev.Evidence.JSONPointer = "/payload/input"
				st.noteCodexCodeModeCommandCall(ri.CallID)
				res.appendEvent(st, ev, true)
				return
			}
		}
		// A freeform/custom (often MCP-routed) tool call. The name is the only
		// reliably structured field; the input is previewed so a reviewer sees
		// WHAT was requested. An MCP-qualified name splits into typed server/tool
		// fields, falling back to the separate namespace — mirroring codex.go.
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventToolCall
		ev.ContentPreview = preview(string(ri.Input))
		ev.Evidence.JSONPointer = "/payload/input"
		if server, tool, ok := splitMCPName(ri.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		} else if server, ok := codexMCPNamespaceServer(ri.Namespace); ok {
			ev.MCPServer, ev.MCPTool = server, ri.Name
		}
		res.appendEvent(st, ev, true)
	case codexRIToolSearchOutput:
		// The result of a tool_search_call: a list of discovered tool definitions
		// under "tools" (no free-form output string), surfaced as the lead.
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolResult
		ev.ToolCallID = ri.CallID
		ev.ContentPreview = preview(decodeCodexToolSearchTools(ri.Tools))
		ev.Evidence.JSONPointer = "/payload/tools"
		res.appendEvent(st, ev, true)
	case codexRIToolSearchCall:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolCall
		ev.ToolName = codexToolSearch
		ev.ToolCallID = ri.CallID
		ev.ContentPreview = preview(codexArgString(string(ri.Arguments), "query"))
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.appendEvent(st, ev, true)
	case codexRIImageGenerationCall:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolCall
		ev.ToolName = codexToolImage
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload"
		res.appendEvent(st, ev, true)
	case codexRIReasoning:
		// Model reasoning is context, not an action record (mirrors Claude's
		// thinking-block handling and Codex's reasoning posture). It is prose, so it
		// is a NO-OP under data minimization — recognized, never previewed.
	case codexRICompaction, codexRICompactionSummary, codexRIContextCompaction:
		// History-compaction inner variants carry only opaque encrypted content;
		// an explicit, recognized no-op.
	case "":
		res.diag(src.Path, line, "openclaw codex response_item missing inner type")
	default:
		// Unknown response_item variant: skip rather than diagnose so a format
		// addition is not flagged as corruption (mirrors the Codex extractor).
	}
}

// mapCodexEventMsg decodes a Codex-flavor event_msg payload and surfaces only the
// records the response_item layer does not carry, reusing the same wire types and
// helpers as the canonical extractor (codexEventMsg / codexMcpResultIsError /
// markToolResultError) routed through OpenClaw's event base/id/state. It is the
// OpenClaw mirror of codex.go mapEventMsg:
//   - mcp_tool_call_end: read ONLY the structured Result; on a recorded failure tag
//     the already-emitted tool.result for the call_id TagToolError, or — when the
//     end-event preceded the output — note the failed call_id so the later output is
//     tagged. Success / unrecognized shape leaves the tool.result untagged (never
//     scrape prose).
//   - turn_aborted / thread_rolled_back / entered_review_mode / exited_review_mode /
//     thread_goal_updated: low-confidence message.assistant system notes tagged with
//     the transition type, JSONPointer /payload (the OpenClaw outer row is
//     {timestamp,type,payload}, so /payload resolves).
//   - every other type duplicates a response_item record and is skipped.
//
// A malformed payload is a diagnostic and skipped (no panic).
func (e OpenClawExtractor) mapCodexEventMsg(res *Result, src Source, sha string, st *openClawState, line int, payload json.RawMessage) {
	var em codexEventMsg
	if err := json.Unmarshal(payload, &em); err != nil {
		res.diag(src.Path, line, "malformed event_msg payload")
		return
	}
	switch em.Type {
	case codexEMTurnAborted:
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceLow
		ev.Evidence.JSONPointer = "/payload"
		if em.Reason != "" {
			ev.ContentPreview = preview("turn aborted: " + em.Reason)
		}
		ev.Tags = []string{codexEMTurnAborted}
		res.appendEvent(st, ev, false)
	case codexEMThreadRolledBack, codexEMEnteredReviewMode, codexEMExitedReviewMode, codexEMThreadGoalUpdated:
		// State transitions with NO response_item twin: emitted as low-confidence
		// system notes tagged with the transition type so the state change is on the
		// timeline rather than silently lost (same posture as codex.go mapEventMsg).
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceLow
		ev.Evidence.JSONPointer = "/payload"
		ev.Tags = []string{em.Type}
		res.appendEvent(st, ev, false)
	case codexEMMcpToolCallEnd:
		// The response_item layer already emitted the tool.call/tool.result for this
		// MCP invocation, so this end-event is NOT re-emitted (that would double-count
		// the timeline). It is read ONLY for its structured Result: on a recorded
		// failure the matching tool.result for the call_id is tagged TagToolError,
		// falling back to noting the failed call_id when the output has not landed yet
		// (out-of-order). Success / unrecognized shape leaves the result untagged; no
		// prose body is scraped.
		if isErr, ok := codexMcpResultIsError(em.Result); ok && isErr {
			if !markToolResultError(res, em.CallID) {
				st.noteFailedMCPCall(em.CallID)
			}
		}
	default:
		// user_message / agent_message / patch_apply_end / ... duplicate a
		// response_item record; unknown/unpersisted types are skipped too. Same
		// single-counted-timeline posture as codex.go (no permission.* synthesized).
	}
}

// emitCodexMessage emits a prompt.user or message.assistant from a Codex
// response_item message. role determines the actor; developer/system messages are
// instructions, not agent activity, and are skipped. An empty body yields
// nothing. Prose is a message event (not a tool event), so it does not advance
// the tool-activity counter.
func (e OpenClawExtractor) emitCodexMessage(res *Result, src Source, sha string, st *openClawState, line int, ri *codexResponseItem) {
	text := strings.TrimSpace(decodeCodexContentText(ri.Content))
	if text == "" {
		return
	}
	ev := e.base(src, sha, st, line, 0)
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
		// developer/system: instructions injected into context, not agent activity.
		return
	}
	res.appendEvent(st, ev, false)
}

// emitCodexFunctionCall maps a Codex response_item function_call onto the
// normalized vocabulary, lifting the forensically salient argument out of the
// tool's JSON-encoded arguments string: shell→command.exec, apply_patch→one
// file.write/file.delete per touched file (with the diff digest/size, REQUESTED
// not confirmed), read/write/edit file→file.read/write, canonical MCP
// fetch→network.indicator, and every other tool→a generic tool.call. Mirrors
// codex.go emitFunctionCall but routes through OpenClaw's id/state/counter.
func (e OpenClawExtractor) emitCodexFunctionCall(res *Result, src Source, sha string, st *openClawState, line int, ri *codexResponseItem) {
	switch ri.Name {
	case codexToolShell, codexToolShellCommand, codexToolExecCommand:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventCommandExec
		ev.Command = codexShellCommand(string(ri.Arguments))
		ev.Evidence.JSONPointer = "/payload/arguments"
		st.noteCommandCall(ri.CallID)
		res.appendEvent(st, ev, true)
	case codexToolApplyPatch:
		// apply_patch is a REQUEST to change files, not a confirmed write: the
		// function_call records intent. numbat emits the requested changes at
		// medium confidence with an intent tag, the same single-layer posture
		// as the Codex extractor (no cross-layer correlation to a patch_apply_end).
		changes := codexApplyPatchChanges(string(ri.Arguments))
		diffSHA, diffBytes := codexApplyPatchDiff(string(ri.Arguments))
		if len(changes) == 0 {
			ev := e.base(src, sha, st, line, 0)
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceMedium
			ev.ToolName = ri.Name
			ev.ToolCallID = ri.CallID
			ev.EventType = model.EventFileWrite
			ev.DiffSHA256 = diffSHA
			ev.DiffBytes = diffBytes
			ev.Tags = []string{codexTagPatchRequested}
			ev.Evidence.JSONPointer = "/payload/arguments"
			res.appendEvent(st, ev, true)
			return
		}
		for i, c := range changes {
			ev := e.base(src, sha, st, line, i)
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceMedium
			ev.ToolName = ri.Name
			ev.ToolCallID = ri.CallID
			if c.Delete {
				ev.EventType = model.EventFileDelete
			} else {
				ev.EventType = model.EventFileWrite
			}
			ev.FilePath = c.Path
			ev.DiffSHA256 = diffSHA
			ev.DiffBytes = diffBytes
			ev.Tags = []string{codexTagPatchRequested}
			ev.Evidence.JSONPointer = "/payload/arguments"
			res.appendEvent(st, ev, true)
		}
	case codexToolReadFile:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventFileRead
		ev.FilePath = codexArgString(string(ri.Arguments), "path")
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.appendEvent(st, ev, true)
	case codexToolWriteFile, codexToolEditFile:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventFileWrite
		ev.FilePath = codexArgString(string(ri.Arguments), "path")
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.appendEvent(st, ev, true)
	default:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload/arguments"
		if isCodexMCPFetch(ri.Namespace, ri.Name) {
			// Network egress via the canonical MCP fetch server. The url must be a
			// real http(s) target; reuse the networkTargetURL validator so a hostless
			// or non-http value leaves URL empty rather than fabricating a target.
			if httpURL := networkTargetURL(codexArgString(string(ri.Arguments), "url")); httpURL != "" {
				ev.URL = httpURL
			}
			ev.EventType = model.EventNetworkIndicator
			ev.Tags = []string{model.TagNetwork}
			ev.MCPServer, ev.MCPTool = "fetch", "fetch"
			res.appendEvent(st, ev, true)
			return
		}
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(ri.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		} else if server, ok := codexMCPNamespaceServer(ri.Namespace); ok {
			ev.MCPServer, ev.MCPTool = server, ri.Name
		}
		res.appendEvent(st, ev, true)
	}
}
