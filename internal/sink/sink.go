package sink

import (
	"io"
	"sync"
)

// BoundedBufferWriter wraps an underlying io.Writer (e.g. file, pipe)
// to prevent memory exhaustion (DoS) during high-throughput captures.
// Instead of dropping bytes (which corrupts PCAP files), it applies backpressure
// by blocking the Write call when the buffer exceeds MaxBufferBytes.
type BoundedBufferWriter struct {
	underlying io.Writer
	mu         sync.Mutex
	cond       *sync.Cond

	// MaxBufferBytes is the maximum allocated memory buffer (default 50MB)
	MaxBufferBytes int64

	// currentBytes tracks the current memory allocation
	currentBytes int64

	// totalBytes tracks the total committed bytes written to the writer
	totalBytes int64

	// writeQueue carries chunks to be written asynchronously
	writeQueue chan []byte

	// stopChan signals the background writer to exit
	stopChan chan struct{}

	// wg tracks background goroutine lifecycle
	wg sync.WaitGroup

	// closeOnce ensures Close() is idempotent
	closeOnce sync.Once

	// writeErr stores any asynchronous write error
	writeErr error
}

// NewBoundedBufferWriter wraps an io.Writer with a bounded memory buffer.
func NewBoundedBufferWriter(underlying io.Writer, maxBufferBytes int64) *BoundedBufferWriter {
	if maxBufferBytes <= 0 {
		maxBufferBytes = 50 * 1024 * 1024 // Default: 50 MB
	}

	w := &BoundedBufferWriter{
		underlying:     underlying,
		MaxBufferBytes: maxBufferBytes,
		writeQueue:     make(chan []byte, 1000),
		stopChan:       make(chan struct{}),
	}
	w.cond = sync.NewCond(&w.mu)

	w.wg.Add(1)
	go w.processQueue()

	return w
}

// Write blocks (backpressure) if the buffer exceeds MaxBufferBytes.
func (w *BoundedBufferWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writeErr != nil {
		return 0, w.writeErr
	}

	chunkSize := int64(len(p))

	// Apply Backpressure: Wait until there is enough space in the buffer.
	for w.currentBytes+chunkSize > w.MaxBufferBytes && w.writeErr == nil {
		select {
		case <-w.stopChan:
			return 0, io.ErrClosedPipe
		default:
			w.cond.Wait()
		}
	}

	if w.writeErr != nil {
		return 0, w.writeErr
	}

	w.currentBytes += chunkSize

	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case w.writeQueue <- buf:
		w.totalBytes += chunkSize
		return len(p), nil
	case <-w.stopChan:
		w.currentBytes -= chunkSize
		return 0, io.ErrClosedPipe
	}
}

// TotalBytesWritten returns the total bytes successfully processed by the writer.
func (w *BoundedBufferWriter) TotalBytesWritten() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.totalBytes
}

// Close flushes the queue, waits for final writes to commit, and releases resources.
func (w *BoundedBufferWriter) Close() error {
	w.closeOnce.Do(func() {
		close(w.stopChan)
		w.mu.Lock()
		w.cond.Broadcast() // wake up any waiting writers
		w.mu.Unlock()

		w.wg.Wait()

		if closer, ok := w.underlying.(io.Closer); ok {
			if err := closer.Close(); err != nil && w.writeErr == nil {
				w.writeErr = err
			}
		}
	})

	return w.writeErr
}

// processQueue runs in a background goroutine to execute raw writes sequentially.
func (w *BoundedBufferWriter) processQueue() {
	defer w.wg.Done()

	for {
		select {
		case chunk := <-w.writeQueue:
			_, err := w.underlying.Write(chunk)

			w.mu.Lock()
			w.currentBytes -= int64(len(chunk))
			w.cond.Signal() // notify blocked writers
			if err != nil && w.writeErr == nil {
				w.writeErr = err
			}
			w.mu.Unlock()

			if err != nil {
				return
			}
		case <-w.stopChan:
			// Flush remaining items
			for {
				select {
				case chunk := <-w.writeQueue:
					_, err := w.underlying.Write(chunk)
					if err != nil {
						w.mu.Lock()
						if w.writeErr == nil {
							w.writeErr = err
						}
						w.mu.Unlock()
						return
					}
				default:
					return
				}
			}
		}
	}
}
