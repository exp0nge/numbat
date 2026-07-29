//go:build windows

package casebundle

import "github.com/perplexityai/numbat/internal/winfile"

func renameNoReplace(from, to string) error {
	return winfile.RenameNoReplace(from, to)
}
