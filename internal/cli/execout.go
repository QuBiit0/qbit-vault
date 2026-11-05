package cli

import (
	"encoding/json"
	"io"
	"sync"
)

// execBody is the --json result of a captured run (CONTRACT § exec).
type execBody struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	Redactions int    `json:"redactions"`
	Truncated  bool   `json:"truncated"`
}

// execFinal is the last line of the NDJSON stream.
type execFinal struct {
	ExitCode   int   `json:"exit_code"`
	DurationMS int64 `json:"duration_ms"`
	Redactions int   `json:"redactions"`
}

type chunkLine struct {
	Stream string `json:"stream"`
	Chunk  string `json:"chunk"`
}

// chunkWriter turns each write into one NDJSON line. Both streams share the
// destination, so writes are serialized.
type chunkWriter struct {
	mu     *sync.Mutex
	dst    io.Writer
	stream string
}

type chunkWriters struct{ stdout, stderr io.Writer }

func newChunkWriters(dst io.Writer) chunkWriters {
	mu := &sync.Mutex{}
	return chunkWriters{
		stdout: chunkWriter{mu, dst, "stdout"},
		stderr: chunkWriter{mu, dst, "stderr"},
	}
}

// Write emits {"stream":…,"chunk":…}. The chunk is a JSON string, so bytes
// that are not valid UTF-8 (a character split across chunks) come out as
// U+FFFD.
func (c chunkWriter) Write(p []byte) (int, error) {
	b, err := json.Marshal(chunkLine{Stream: c.stream, Chunk: string(p)})
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.dst.Write(append(b, '\n')); err != nil {
		return 0, err
	}
	return len(p), nil
}
