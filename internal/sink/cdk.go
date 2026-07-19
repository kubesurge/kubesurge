// Package sink — cdk.go
//
// Implements the universal cloud storage sink using the Go Cloud Development Kit (Go CDK).
// By abstracting GCS, S3, Azure Blob, and local file storage behind the `blob.Bucket` URL format,
// we decouple KubeSurge from cloud-vendor specific SDK implementations.
package sink

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"
)

// CDKSink wraps the Go CDK blob.Bucket and blob.Writer to implement our Sink interface.
type CDKSink struct {
	bucket *blob.Bucket
	writer *blob.Writer
}

// NewCDKSink opens the cloud bucket using the provided URL string and prepares a writer
// for the given blob name.
//
// Example URLs:
//
//	s3://my-bucket/
//	gs://my-bucket/
//	azblob://my-container/
//	file:///mnt/my-pv-dir/ (requires absolute directory path)
func NewCDKSink(ctx context.Context, sinkURL string, blobName string) (*CDKSink, error) {
	parsedURL, err := url.Parse(sinkURL)
	if err != nil {
		return nil, fmt.Errorf("invalid sink URL: %w", err)
	}

	var finalSinkURL string
	var finalBlobName string

	// For local file paths (like ./capture.pcap or file:///)
	if parsedURL.Scheme == "" || parsedURL.Scheme == "file" {
		var path string
		if parsedURL.Scheme == "file" {
			path = parsedURL.Path
		} else {
			path = sinkURL
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve local path: %w", err)
		}

		dir := filepath.Dir(absPath)
		finalBlobName = filepath.Base(absPath)

		// Convert backslashes for Windows path strings
		dir = strings.ReplaceAll(dir, "\\", "/")
		if !strings.HasPrefix(dir, "/") {
			dir = "/" + dir
		}

		finalSinkURL = "file://" + dir
	} else {
		finalSinkURL = sinkURL
		finalBlobName = blobName
	}

	bucket, err := blob.OpenBucket(ctx, finalSinkURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage bucket: %w\n"+
			"  → Verify that your cloud credential environment variables are configured correctly", err)
	}

	writer, err := bucket.NewWriter(ctx, finalBlobName, nil)
	if err != nil {
		bucket.Close()
		return nil, fmt.Errorf("failed to open output blob writer: %w", err)
	}

	return &CDKSink{
		bucket: bucket,
		writer: writer,
	}, nil
}

// Write streams input bytes to the active cloud writer.
func (s *CDKSink) Write(p []byte) (int, error) {
	return s.writer.Write(p)
}

// Close flushes buffer streams and closes both the cloud writer and the bucket.
func (s *CDKSink) Close() error {
	var writeErr error
	if s.writer != nil {
		writeErr = s.writer.Close()
	}
	if err := s.bucket.Close(); err != nil && writeErr == nil {
		writeErr = err
	}
	return writeErr
}
