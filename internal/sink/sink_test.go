package sink

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockWriter implements io.WriteCloser and simulates network latency or blocking.
type mockWriter struct {
	mu           sync.Mutex
	buf          bytes.Buffer
	writeLatency time.Duration
	writeError   error
	closed       bool
}

func (m *mockWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, errors.New("write to closed writer")
	}
	if m.writeError != nil {
		return 0, m.writeError
	}

	if m.writeLatency > 0 {
		time.Sleep(m.writeLatency)
	}

	return m.buf.Write(p)
}

func (m *mockWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func TestBoundedBufferWriter_NormalWrite(t *testing.T) {
	mock := &mockWriter{}
	// Set buffer to 10KB
	w := NewBoundedBufferWriter(mock, 10*1024)
	defer w.Close()

	data := []byte("hello-world")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected to write %d bytes, wrote %d", len(data), n)
	}

	// Give queue time to process
	time.Sleep(50 * time.Millisecond)

	mock.mu.Lock()
	written := mock.buf.String()
	mock.mu.Unlock()

	if written != "hello-world" {
		t.Errorf("expected 'hello-world', got '%s'", written)
	}
}

func TestBoundedBufferWriter_BufferExceeded_Blocks(t *testing.T) {
	mock := &mockWriter{
		writeLatency: 100 * time.Millisecond, // slow write
	}
	// Limit memory buffer to 10 bytes
	w := NewBoundedBufferWriter(mock, 10)
	defer w.Close()

	// Write 8 bytes (fits)
	_, err := w.Write([]byte("12345678"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	start := time.Now()
	done := make(chan bool)

	// Write another 8 bytes (exceeds 10-byte cap, should block)
	go func() {
		_, err = w.Write([]byte("abcdefgh"))
		if err != nil {
			t.Errorf("unexpected error on block-write: %v", err)
		}
		done <- true
	}()

	select {
	case <-done:
		duration := time.Since(start)
		if duration < 50*time.Millisecond {
			t.Errorf("expected block-write to take at least 50ms, took %v", duration)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("blocked write timed out")
	}

	// Flush and close the writer to ensure the background queue is fully drained
	w.Close()

	// Verify both chunks committed to disk/stream after queue finished
	mock.mu.Lock()
	written := mock.buf.String()
	mock.mu.Unlock()

	if written != "12345678abcdefgh" {
		t.Errorf("expected '12345678abcdefgh', got '%s'", written)
	}
}

func TestBoundedBufferWriter_UnderlyingError(t *testing.T) {
	mock := &mockWriter{
		writeError: errors.New("network disconnect"),
	}
	w := NewBoundedBufferWriter(mock, 100)

	_, _ = w.Write([]byte("some data"))
	time.Sleep(50 * time.Millisecond) // wait for async processing

	// Subsequent writes should detect the background write error
	_, err := w.Write([]byte("more data"))
	if err == nil || err.Error() != "network disconnect" {
		t.Errorf("expected 'network disconnect' error, got %v", err)
	}

	err = w.Close()
	if err == nil || err.Error() != "network disconnect" {
		t.Errorf("expected Close to return write error, got %v", err)
	}
}
