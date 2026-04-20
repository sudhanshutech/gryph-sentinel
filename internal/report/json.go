package report

import (
	"encoding/json"

	"github.com/safedep/gryph-sentinel/internal/analyzer"
)

func RenderJSON(in analyzer.Report) (string, error) {
	data, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
