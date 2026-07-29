//go:build windows

package hook

import "github.com/perplexityai/numbat/internal/winfile"

func replaceFile(from, to string) error {
	return winfile.Replace(from, to)
}
