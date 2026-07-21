package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OtlpFlowLog represents a packet event in OpenTelemetry LogRecord format.
type OtlpFlowLog struct {
	TimestampUnixNano int64              `json:"timeUnixNano"`
	Body              OtlpBodyVal        `json:"body"`
	Attributes        []OtlpAttributeKey `json:"attributes"`
}

type OtlpBodyVal struct {
	StringValue string `json:"stringValue"`
}

type OtlpAttributeKey struct {
	Key   string       `json:"key"`
	Value OtlpValueVal `json:"value"`
}

type OtlpValueVal struct {
	StringValue string `json:"stringValue,omitempty"`
	IntValue    int64  `json:"intValue,omitempty"`
}

// OtlpClient exports network flow logs to an OTel Collector over HTTP/JSON.
type OtlpClient struct {
	Endpoint   string
	httpClient *http.Client
}

// NewOtlpClient initializes the OTLP JSON client.
func NewOtlpClient(endpoint string) *OtlpClient {
	return &OtlpClient{
		Endpoint:   endpoint,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// ExportFlow translates a Pcap packet event into an OTLP LogRecord and posts it.
func (c *OtlpClient) ExportFlow(ctx context.Context, srcIP, dstIP string, proto string, len int64) error {
	flowDesc := fmt.Sprintf("%s ⇄ %s (%s, %d bytes)", srcIP, dstIP, proto, len)

	logRecord := OtlpFlowLog{
		TimestampUnixNano: time.Now().UnixNano(),
		Body:              OtlpBodyVal{StringValue: flowDesc},
		Attributes: []OtlpAttributeKey{
			{Key: "source.ip", Value: OtlpValueVal{StringValue: srcIP}},
			{Key: "destination.ip", Value: OtlpValueVal{StringValue: dstIP}},
			{Key: "network.transport", Value: OtlpValueVal{StringValue: proto}},
			{Key: "packet.length", Value: OtlpValueVal{IntValue: len}},
			{Key: "k8s.service", Value: OtlpValueVal{StringValue: "kubesurge-debug"}},
		},
	}

	// Wrap in ResourceLogs structure
	payload := map[string]interface{}{
		"resourceLogs": []interface{}{
			map[string]interface{}{
				"scopeLogs": []interface{}{
					map[string]interface{}{
						"logRecords": []OtlpFlowLog{logRecord},
					},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OTLP collector returned non-2xx: %d", resp.StatusCode)
	}

	return nil
}
