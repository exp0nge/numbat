package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	kimiNumbatBlockStart = "# BEGIN numbat Kimi Code hooks"
	kimiNumbatBlockEnd   = "# END numbat Kimi Code hooks"
)

type kimiHookEvent struct {
	event     string
	lifecycle string
	timeout   int
}

var kimiHookEvents = []kimiHookEvent{
	{event: "SessionStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{event: "UserPromptSubmit", lifecycle: "prompt-submit", timeout: promptHookTimeoutSeconds},
	{event: "PreToolUse", lifecycle: "pre-tool", timeout: fastHookTimeoutSeconds},
	{event: "PostToolUse", lifecycle: "post-tool", timeout: fastHookTimeoutSeconds},
	{event: "PostToolUseFailure", lifecycle: "post-tool", timeout: fastHookTimeoutSeconds},
	{event: "PermissionRequest", lifecycle: "permission-request", timeout: fastHookTimeoutSeconds},
	{event: "PermissionResult", lifecycle: "permission-request", timeout: fastHookTimeoutSeconds},
	{event: "Stop", lifecycle: "stop", timeout: stopHookTimeoutSeconds},
	{event: "SessionEnd", lifecycle: "session-end", timeout: fastHookTimeoutSeconds},
	{event: "SubagentStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{event: "SubagentStop", lifecycle: "session-end", timeout: fastHookTimeoutSeconds},
}

func KimiConfigPath(home string) string {
	root := os.Getenv("KIMI_CODE_HOME")
	if root == "" {
		root = filepath.Join(home, ".kimi-code")
	}
	return filepath.Join(root, "config.toml")
}

func kimiCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentKimi, runtimeArgs, enforce)
}

func renderKimiHookBlock(binary string, runtimeArgs []string, enforce bool) string {
	var b strings.Builder
	b.WriteString(kimiNumbatBlockStart)
	b.WriteByte('\n')
	for _, event := range kimiHookEvents {
		b.WriteString("[[hooks]]\n")
		fmt.Fprintf(&b, "event = %s\n", tomlString(event.event))
		fmt.Fprintf(&b, "command = %s\n", tomlString(kimiCommandWithArgs(binary, event.lifecycle, runtimeArgs, enforce && event.event == "PreToolUse")))
		fmt.Fprintf(&b, "timeout = %d\n\n", event.timeout)
	}
	b.WriteString(kimiNumbatBlockEnd)
	b.WriteByte('\n')
	return b.String()
}

func kimiConfigWithoutNumbat(body string) (string, error) {
	starts := strings.Count(body, kimiNumbatBlockStart)
	ends := strings.Count(body, kimiNumbatBlockEnd)
	if starts != ends || starts > 1 {
		return "", fmt.Errorf("malformed numbat marker block in Kimi config")
	}
	if starts == 0 {
		return body, nil
	}
	out, changed := removeMarkedBlock(body, kimiNumbatBlockStart, kimiNumbatBlockEnd)
	if !changed {
		return "", fmt.Errorf("malformed numbat marker block in Kimi config")
	}
	out = strings.TrimRight(out, "\n")
	if strings.TrimSpace(out) == "" {
		return "", nil
	}
	return out + "\n", nil
}

func kimiConfigWithNumbat(body, binary string, runtimeArgs []string, enforce bool) (string, error) {
	clean, err := kimiConfigWithoutNumbat(body)
	if err != nil {
		return "", err
	}
	clean = strings.TrimRight(clean, "\n")
	if clean != "" {
		clean += "\n\n"
	}
	return clean + renderKimiHookBlock(binary, runtimeArgs, enforce), nil
}

func installKimiWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentKimi, SettingsPath: path, Supported: true}
	body, err := readOptionalText(path)
	if err != nil {
		return rep, err
	}
	body, err = kimiConfigWithNumbat(body, binary, runtimeArgs, enforce)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeFileAtomic(path, []byte(body)); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = installMessage(enforce)
	return rep, nil
}

func uninstallKimi(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentKimi, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no config file; nothing to remove"
		return rep, nil
	}
	body, err := readOptionalText(path)
	if err != nil {
		return rep, err
	}
	clean, err := kimiConfigWithoutNumbat(body)
	if err != nil {
		return rep, err
	}
	if clean == body {
		rep.Message = "no numbat hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeFileAtomic(path, []byte(clean)); err != nil {
		return rep, err
	}
	rep.Changed, rep.Message = true, "removed numbat hooks"
	return rep, nil
}

func statusKimi(path string) InstallReport {
	rep := InstallReport{Agent: AgentKimi, SettingsPath: path, Supported: true}
	body, err := readOptionalText(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	starts := strings.Count(body, kimiNumbatBlockStart)
	ends := strings.Count(body, kimiNumbatBlockEnd)
	any := starts > 0 || ends > 0
	block := ""
	if starts == 1 && ends == 1 {
		start := strings.Index(body, kimiNumbatBlockStart)
		end := strings.Index(body[start:], kimiNumbatBlockEnd)
		if end >= 0 {
			block = body[start : start+end]
		}
	}
	complete := block != "" && strings.Count(block, "[[hooks]]") == len(kimiHookEvents)
	for _, event := range kimiHookEvents {
		complete = complete && strings.Count(block, "event = "+tomlString(event.event)) == 1
	}
	rep.Installed = complete
	if complete {
		rep.Message = "numbat hooks installed"
	} else if any {
		rep.Message = "partial or malformed numbat Kimi hook install"
	} else {
		rep.Message = "numbat hooks not installed"
	}
	return rep
}
