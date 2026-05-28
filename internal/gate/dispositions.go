package gate

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
)

// ReadDispositions parses an existing dispositions.jsonl file.
// Useful for tests, audits, and replaying decisions.
func ReadDispositions(path string) ([]Disposition, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readDispositions(f)
}

func readDispositions(r io.Reader) ([]Disposition, error) {
	var out []Disposition
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		var d Disposition
		if err := json.Unmarshal(line, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, scan.Err()
}
