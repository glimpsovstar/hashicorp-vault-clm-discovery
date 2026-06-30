package report

import "encoding/json"

// RenderJSON returns the structured report document as JSON bytes.
func RenderJSON(doc Document) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}
