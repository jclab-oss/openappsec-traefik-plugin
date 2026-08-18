// Package openappsec_traefik_plugin is a traefik middleware plugin that sends
// HTTP traffic to the openappsec-traefik-daemon for inspection by the
// open-appsec nano agent. The plugin is pure Go (stdlib only) so it can run
// under traefik's Yaegi interpreter; all shared-memory IPC with the agent is
// delegated to the daemon.
package openappsec_traefik_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// blockResponse describes what to return to the client on a drop verdict.
type blockResponse struct {
	Code    int               `json:"code"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// verdictReply is the daemon's answer for every inspection call.
type verdictReply struct {
	SessionID    uint32         `json:"sessionId,omitempty"`
	Verdict      string         `json:"verdict"`
	Response     *blockResponse `json:"response,omitempty"`
	Body         []byte         `json:"body,omitempty"`
	BodyModified bool           `json:"bodyModified,omitempty"`
}

type startRequest struct {
	ClientIP      string      `json:"clientIp"`
	ClientPort    uint16      `json:"clientPort"`
	ListeningIP   string      `json:"listeningIp"`
	ListeningPort uint16      `json:"listeningPort"`
	Protocol      string      `json:"protocol"`
	Method        string      `json:"method"`
	Host          string      `json:"host"`
	URI           string      `json:"uri"`
	Headers       [][2]string `json:"headers"`
	ContainsBody  bool        `json:"containsBody"`
}

type responseHeadersRequest struct {
	Code          int         `json:"code"`
	ContentLength uint64      `json:"contentLength"`
	Headers       [][2]string `json:"headers"`
}

type daemonClient struct {
	baseURL    string
	httpClient *http.Client
}

// maxDaemonConns bounds the pool of connections kept open to the daemon.
// Inspecting one request takes several calls — start, each body chunk, the
// response stages — so the default idle-connection limit of two per host makes
// almost every call dial anew. Under load that churn is what starves the
// connection pool and makes calls fail, which either fails open (traffic goes
// uninspected) or fails closed (traffic is rejected), depending on config.
const maxDaemonConns = 512

func newTransport(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext:         dial,
		MaxIdleConns:        maxDaemonConns,
		MaxIdleConnsPerHost: maxDaemonConns,
		MaxConnsPerHost:     maxDaemonConns,
		IdleConnTimeout:     90 * time.Second,
	}
}

func newDaemonClient(addr string, timeout time.Duration) *daemonClient {
	if strings.HasPrefix(addr, "unix://") {
		socketPath := strings.TrimPrefix(addr, "unix://")
		transport := newTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		})
		return &daemonClient{
			baseURL:    "http://openappsec-daemon",
			httpClient: &http.Client{Transport: transport, Timeout: timeout},
		}
	}
	return &daemonClient{
		baseURL:    strings.TrimSuffix(addr, "/"),
		httpClient: &http.Client{Transport: newTransport(nil), Timeout: timeout},
	}
}

func (c *daemonClient) do(method, path, contentType string, body io.Reader) (*verdictReply, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	// A connection only goes back to the pool once its body is read to EOF and
	// closed. The decoder stops at the end of the JSON value and leaves the
	// trailing newline behind, which is enough to keep the connection out of
	// the pool and force the next call to dial again.
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned status %d", resp.StatusCode)
	}
	var reply verdictReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *daemonClient) startTransaction(data *startRequest) (*verdictReply, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return c.do(http.MethodPost, "/api/v1/session", "application/json", bytes.NewReader(payload))
}

func (c *daemonClient) sendRequestBody(sid uint32, chunk []byte) (*verdictReply, error) {
	return c.do(
		http.MethodPost,
		fmt.Sprintf("/api/v1/session/%d/request-body", sid),
		"application/octet-stream",
		bytes.NewReader(chunk),
	)
}

func (c *daemonClient) endRequest(sid uint32) (*verdictReply, error) {
	return c.do(http.MethodPost, fmt.Sprintf("/api/v1/session/%d/request-end", sid), "", nil)
}

func (c *daemonClient) sendResponseHeaders(sid uint32, data *responseHeadersRequest) (*verdictReply, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return c.do(
		http.MethodPost,
		fmt.Sprintf("/api/v1/session/%d/response-headers", sid),
		"application/json",
		bytes.NewReader(payload),
	)
}

func (c *daemonClient) sendResponseBody(sid uint32, chunk []byte) (*verdictReply, error) {
	return c.do(
		http.MethodPost,
		fmt.Sprintf("/api/v1/session/%d/response-body", sid),
		"application/octet-stream",
		bytes.NewReader(chunk),
	)
}

func (c *daemonClient) endResponse(sid uint32) (*verdictReply, error) {
	return c.do(http.MethodPost, fmt.Sprintf("/api/v1/session/%d/response-end", sid), "", nil)
}

func (c *daemonClient) finiSession(sid uint32) {
	// Best effort cleanup; errors are ignored on purpose.
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/session/%d", c.baseURL, sid), nil)
	if err != nil {
		return
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
