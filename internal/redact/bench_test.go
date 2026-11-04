package redact

import (
	"fmt"
	"io"
	"math/rand"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// benchInput returns about size bytes of printable text with secrets
// sprinkled in.
func benchInput(size int, values []string) []byte {
	rng := rand.New(rand.NewSource(3))
	const alphabet = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=+/.-_\n"
	b := make([]byte, 0, size+64)
	for len(b) < size {
		if rng.Intn(2000) == 0 {
			b = append(b, values[rng.Intn(len(values))]...)
			continue
		}
		b = append(b, alphabet[rng.Intn(len(alphabet))])
	}
	return b
}

func benchRedactor(b *testing.B) (*Redactor, []byte) {
	var secs []secret.Secret
	var values []string
	for i := 0; i < 16; i++ {
		v := fmt.Sprintf("TESTSECRET_bench_%02d_%016x", i, rand.New(rand.NewSource(int64(i))).Uint64())
		values = append(values, v)
		secs = append(secs, secret.New(fmt.Sprintf("BENCH_%02d", i), []byte(v)))
	}
	r, err := New(secs)
	if err != nil {
		b.Fatal(err)
	}
	return r, benchInput(1<<20, values)
}

// BenchmarkRedact measures 1 MiB of input against 16 secrets.
func BenchmarkRedact(b *testing.B) {
	r, in := benchRedactor(b)
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Bytes(in)
	}
}

// BenchmarkRedactStream is the same input in 4 KiB writes.
func BenchmarkRedactStream(b *testing.B) {
	r, in := benchRedactor(b)
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := r.Writer(io.Discard)
		for off := 0; off < len(in); off += 4096 {
			end := min(off+4096, len(in))
			if _, err := w.Write(in[off:end]); err != nil {
				b.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
