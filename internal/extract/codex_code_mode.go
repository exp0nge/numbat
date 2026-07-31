package extract

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Codex code mode persists one JavaScript cell as a custom tool call. Promote
// only the common, unambiguous shape whose first operation is one static shell
// call; arbitrary or compound programs stay generic tool.call events.
var codexCodeModeExecPrefix = regexp.MustCompile(`^const[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)[[:space:]]*=[[:space:]]*await[[:space:]]+tools\.exec_command[[:space:]]*\([[:space:]]*`)

func codexCodeModeExecCommand(input string) (string, bool) {
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "// @exec:") {
		newline := strings.IndexByte(s, '\n')
		if newline < 0 {
			return "", false
		}
		s = strings.TrimSpace(s[newline+1:])
	}

	match := codexCodeModeExecPrefix.FindStringSubmatchIndex(s)
	if match == nil || !isCodexCodeModeBindingName(s[match[2]:match[3]]) {
		return "", false
	}
	resultName := s[match[2]:match[3]]

	command, end, ok := parseCodexCodeModeExecArgs(s, match[1])
	if !ok {
		return "", false
	}
	end = skipASCIIWhitespace(s, end)
	if end >= len(s) || s[end] != ')' {
		return "", false
	}
	end++
	var lineBreak bool
	end, lineBreak = skipCodexCodeModeStatementSpace(s, end)
	separated := lineBreak
	if end < len(s) && s[end] == ';' {
		end++
		separated = true
	}
	if skipASCIIWhitespace(s, end) < len(s) && !separated {
		return "", false
	}

	// Accept only an empty tail or the common result-forwarding forms. Any other
	// JavaScript may contain another operation or alter the meaning of the output.
	if !isCodexCodeModeResultTail(s[end:], resultName) {
		return "", false
	}
	return command, true
}

func isCodexCodeModeResultTail(s, resultName string) bool {
	tokens, ok := codexCodeModeTailTokens(s)
	if !ok {
		return false
	}
	if len(tokens) == 0 {
		return true
	}
	if tokens[len(tokens)-1] == ";" {
		tokens = tokens[:len(tokens)-1]
	}
	// These declarations shadow helpers used by the corresponding tail shape.
	if resultName == "text" {
		return false
	}
	if codexCodeModeTokensEqual(tokens, "text", "(", resultName, ")") ||
		codexCodeModeTokensEqual(tokens, "text", "(", resultName, ".", "output", ")") {
		return true
	}
	return resultName != "JSON" && codexCodeModeTokensEqual(tokens,
		"text", "(", "JSON", ".", "stringify", "(", resultName, ")", ")")
}

func codexCodeModeTailTokens(s string) ([]string, bool) {
	var tokens []string
	for i := 0; ; {
		i = skipASCIIWhitespace(s, i)
		if i == len(s) {
			return tokens, true
		}
		if isJSIdentifierStart(s[i]) {
			end := i + 1
			for end < len(s) && isJSIdentifierContinue(s[end]) {
				end++
			}
			tokens = append(tokens, s[i:end])
			i = end
			continue
		}
		switch s[i] {
		case '(', ')', '.', ';':
			tokens = append(tokens, s[i:i+1])
			i++
		default:
			return nil, false
		}
	}
}

func codexCodeModeTokensEqual(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func parseCodexCodeModeExecArgs(s string, start int) (string, int, bool) {
	i := skipASCIIWhitespace(s, start)
	if i >= len(s) || s[i] != '{' {
		return "", 0, false
	}
	i++

	var command string
	seenCommand := false
	for {
		i = skipASCIIWhitespace(s, i)
		if i >= len(s) {
			return "", 0, false
		}
		if s[i] == '}' {
			if !seenCommand || strings.TrimSpace(command) == "" {
				return "", 0, false
			}
			return command, i + 1, true
		}

		key, next, ok := parseCodexCodeModePropertyName(s, i)
		if !ok {
			return "", 0, false
		}
		i = skipASCIIWhitespace(s, next)
		if i >= len(s) || s[i] != ':' {
			return "", 0, false
		}
		i = skipASCIIWhitespace(s, i+1)

		var value any
		decoder := json.NewDecoder(strings.NewReader(s[i:]))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil || decoder.InputOffset() <= 0 {
			return "", 0, false
		}
		i += int(decoder.InputOffset())
		if key == "cmd" {
			if seenCommand {
				return "", 0, false
			}
			var isString bool
			command, isString = value.(string)
			if !isString {
				return "", 0, false
			}
			seenCommand = true
		}

		i = skipASCIIWhitespace(s, i)
		if i >= len(s) {
			return "", 0, false
		}
		switch s[i] {
		case '}':
			if !seenCommand || strings.TrimSpace(command) == "" {
				return "", 0, false
			}
			return command, i + 1, true
		case ',':
			i++
			if next := skipASCIIWhitespace(s, i); next < len(s) && s[next] == '}' {
				if !seenCommand || strings.TrimSpace(command) == "" {
					return "", 0, false
				}
				return command, next + 1, true
			}
		default:
			return "", 0, false
		}
	}
}

func parseCodexCodeModePropertyName(s string, start int) (string, int, bool) {
	if start >= len(s) {
		return "", 0, false
	}
	if s[start] == '"' {
		var key string
		decoder := json.NewDecoder(strings.NewReader(s[start:]))
		if err := decoder.Decode(&key); err != nil || decoder.InputOffset() <= 0 {
			return "", 0, false
		}
		return key, start + int(decoder.InputOffset()), true
	}
	if !isJSIdentifierStart(s[start]) {
		return "", 0, false
	}
	end := start + 1
	for end < len(s) && isJSIdentifierContinue(s[end]) {
		end++
	}
	return s[start:end], end, true
}

func isJSIdentifierStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$'
}

func isJSIdentifierContinue(c byte) bool {
	return isJSIdentifierStart(c) || c >= '0' && c <= '9'
}

func isCodexCodeModeBindingName(name string) bool {
	switch name {
	case "await", "break", "case", "catch", "class", "const", "continue",
		"debugger", "default", "delete", "do", "else", "enum", "eval",
		"export", "extends", "false", "finally", "for", "function", "if",
		"implements", "import", "in", "instanceof", "interface", "let", "new",
		"null", "package", "private", "protected", "public", "return", "static",
		"super", "switch", "this", "throw", "tools", "true", "try", "typeof",
		"var", "void", "while", "with", "yield", "arguments":
		return false
	default:
		return true
	}
}

func skipASCIIWhitespace(s string, start int) int {
	for start < len(s) {
		switch s[start] {
		case ' ', '\t', '\r', '\n', '\f':
			start++
		default:
			return start
		}
	}
	return start
}

func skipCodexCodeModeStatementSpace(s string, start int) (int, bool) {
	lineBreak := false
	for start < len(s) {
		switch s[start] {
		case '\r', '\n':
			lineBreak = true
			start++
		case ' ', '\t', '\f':
			start++
		default:
			return start, lineBreak
		}
	}
	return start, lineBreak
}
