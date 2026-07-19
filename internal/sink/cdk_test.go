package sink

import (
	"context"
	"testing"

	"gocloud.dev/blob/memblob"
)

func TestCDKSink_InMemoryMockBucket(t *testing.T) {
	ctx := context.Background()

	// Create a mock in-memory bucket to simulate a cloud storage provider (S3/GCS/Azure)
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()

	// Initialize our CDKSink directly wrapping the mock bucket
	blobName := "test-capture.pcap"
	writer, err := bucket.NewWriter(ctx, blobName, nil)
	if err != nil {
		t.Fatalf("failed to open mock writer: %v", err)
	}

	sink := &CDKSink{
		bucket: bucket,
		writer: writer,
	}

	// Write mock packet stream bytes
	data := []byte("pcap-stream-data")
	n, err := sink.Write(data)
	if err != nil {
		t.Fatalf("unexpected write error on mock sink: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected to write %d bytes, wrote %d", len(data), n)
	}

	// Close the writer specifically (flushes data to the mock bucket)
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	// Verify that the blob was successfully written to the mock bucket
	exists, err := bucket.Exists(ctx, blobName)
	if err != nil {
		t.Fatalf("failed to verify blob existence in mock bucket: %v", err)
	}
	if !exists {
		t.Error("expected blob to exist in mock bucket after close, but it does not")
	}

	// Read and verify the content
	reader, err := bucket.NewReader(ctx, blobName, nil)
	if err != nil {
		t.Fatalf("failed to open reader on mock bucket: %v", err)
	}
	defer reader.Close()

	buf := make([]byte, len(data))
	_, err = reader.Read(buf)
	if err != nil {
		t.Fatalf("failed to read written blob: %v", err)
	}

	if string(buf) != string(data) {
		t.Errorf("expected content '%s', got '%s'", string(data), string(buf))
	}
}
