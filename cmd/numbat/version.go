package main

import (
	"fmt"
	"io"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/version"
)

// versionString formats the tool name, build version, and schema version.
func versionString() string {
	return fmt.Sprintf("%s %s (schema %s)", model.ToolName, version.String(), model.SchemaVersion)
}

func versionUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: numbat version")
	fmt.Fprintln(w, "\nPrint the tool version and record schema version.")
}
