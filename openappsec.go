package openappsec_traefik_plugin

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	verdictInspect = "inspect"
	verdictAccept  = "accept"
	verdictDrop    = "drop"
	verdictNoop    = "noop"
)

// Config is the traefik middleware plugin configuration.
type Config struct {
	// DaemonAddr is the address of the openappsec-traefik-daemon, either
	// "http://host:port" or "unix:///path/to.sock".
	DaemonAddr string `json:"daemonAddr,omitempty"`
	// ResponseInspection enables inspection of upstream responses.
	ResponseInspection bool `json:"responseInspection,omitempty"`
	// MaxRequestBodySize is the maximum number of request body bytes that are
	// buffered and sent for inspection. Bigger bodies are only partially
	// inspected.
	MaxRequestBodySize int64 `json:"maxRequestBodySize,omitempty"`
	// FailClose blocks traffic when the daemon cannot be reached. The default
	// (fail-open) forwards traffic without inspection.
	FailClose bool `json:"failClose,omitempty"`
	// TimeoutMs is the per-call timeout towards the daemon.
	TimeoutMs int `json:"timeoutMs,omitempty"`
	// ErrorBackoffMs is how long inspection is skipped after a daemon
	// communication failure.
	ErrorBackoffMs int `json:"errorBackoffMs,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		DaemonAddr:         "http://127.0.0.1:8579",
		ResponseInspection: true,
		MaxRequestBodySize: 10 * 1024 * 1024,
		FailClose:          false,
		TimeoutMs:          30000,
		ErrorBackoffMs:     2000,
	}
}

// Middleware is the open-appsec traefik middleware.
type Middleware struct {
	next               http.Handler
	name               string
	client             *daemonClient
	responseInspection bool
	maxRequestBodySize int64
	failClose          bool
	errorBackoff       time.Duration

	mu        sync.Mutex
	failUntil time.Time
}

// New creates the open-appsec middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}
	daemonAddr := config.DaemonAddr
	if daemonAddr == "" {
		daemonAddr = "http://127.0.0.1:8579"
	}
	timeout := time.Duration(config.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	backoff := time.Duration(config.ErrorBackoffMs) * time.Millisecond
	if backoff <= 0 {
		backoff = 2 * time.Second
	}
	maxBody := config.MaxRequestBodySize
	if maxBody <= 0 {
		maxBody = 10 * 1024 * 1024
	}
	return &Middleware{
		next:               next,
		name:               name,
		client:             newDaemonClient(daemonAddr, timeout),
		responseInspection: config.ResponseInspection,
		maxRequestBodySize: maxBody,
		failClose:          config.FailClose,
		errorBackoff:       backoff,
	}, nil
}

func (m *Middleware) inBackoff() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return time.Now().Before(m.failUntil)
}

func (m *Middleware) noteFailure(err error) {
	mode := "fail-open"
	if m.failClose {
		mode = "fail-close"
	}
	log.Printf("[openappsec] daemon communication failure (%s): %v", mode, err)
	m.mu.Lock()
	m.failUntil = time.Now().Add(m.errorBackoff)
	m.mu.Unlock()
}

// restoredBody re-exposes an already (partially) consumed request body.
type restoredBody struct {
	reader io.Reader
	closer io.Closer
}

func (b *restoredBody) Read(p []byte) (int, error) { return b.reader.Read(p) }

func (b *restoredBody) Close() error { return b.closer.Close() }

// handleUninspected is called when inspection is impossible (daemon down or
// erroring): fail-open forwards the request, fail-close blocks it.
func (m *Middleware) handleUninspected(rw http.ResponseWriter, req *http.Request) {
	if m.failClose {
		writeBlock(rw, nil)
		return
	}
	m.next.ServeHTTP(rw, req)
}

func writeBlock(rw http.ResponseWriter, block *blockResponse) {
	code := http.StatusForbidden
	body := "Request blocked by open-appsec"
	if block != nil {
		if block.Code != 0 {
			code = block.Code
		}
		body = block.Body
		for key, value := range block.Headers {
			rw.Header().Set(key, value)
		}
	}
	if body != "" && rw.Header().Get("Content-Type") == "" {
		rw.Header().Set("Content-Type", "text/html")
	}
	rw.Header().Set("Content-Length", strconv.Itoa(len(body)))
	rw.WriteHeader(code)
	if body != "" {
		_, _ = rw.Write([]byte(body))
	}
}

func splitHostPort(addr string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint16(port)
}

func (m *Middleware) buildStartRequest(req *http.Request) *startRequest {
	clientIP, clientPort := splitHostPort(req.RemoteAddr)

	listeningIP := "0.0.0.0"
	var listeningPort uint16
	// The nil check is not redundant: Yaegi (the traefik plugin interpreter)
	// panics on a comma-ok type assertion of a nil interface value.
	if v := req.Context().Value(http.LocalAddrContextKey); v != nil {
		if localAddr, ok := v.(net.Addr); ok {
			listeningIP, listeningPort = splitHostPort(localAddr.String())
		}
	}
	if listeningPort == 0 {
		if req.TLS != nil {
			listeningPort = 443
		} else {
			listeningPort = 80
		}
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		host = h
	}

	headers := make([][2]string, 0, len(req.Header)+1)
	headers = append(headers, [2]string{"Host", req.Host})
	for key, values := range req.Header {
		for _, value := range values {
			headers = append(headers, [2]string{key, value})
		}
	}

	uri := req.URL.RequestURI()
	if uri == "" {
		uri = req.RequestURI
	}

	return &startRequest{
		ClientIP:      clientIP,
		ClientPort:    clientPort,
		ListeningIP:   listeningIP,
		ListeningPort: listeningPort,
		Protocol:      req.Proto,
		Method:        req.Method,
		Host:          host,
		URI:           uri,
		Headers:       headers,
		ContainsBody:  req.ContentLength > 0 || req.ContentLength == -1,
	}
}

// inspectRequestBody buffers the request body (up to maxRequestBodySize),
// sends it for inspection and restores req.Body for the upstream. It returns
// the last daemon reply, or an error on communication failure.
func (m *Middleware) inspectRequestBody(sid uint32, req *http.Request) (*verdictReply, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return m.client.endRequest(sid)
	}

	buffered, err := io.ReadAll(io.LimitReader(req.Body, m.maxRequestBodySize))
	if err != nil {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buffered), req.Body))
		return nil, err
	}
	// Restore the body: buffered part first, then whatever was not read (only
	// present when the body is larger than maxRequestBodySize).
	req.Body = &restoredBody{
		reader: io.MultiReader(bytes.NewReader(buffered), req.Body),
		closer: req.Body,
	}

	if len(buffered) > 0 {
		reply, err := m.client.sendRequestBody(sid, buffered)
		if err != nil {
			return nil, err
		}
		if reply.Verdict != verdictInspect {
			return reply, nil
		}
	}
	return m.client.endRequest(sid)
}

// ServeHTTP implements the middleware.
func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m.inBackoff() {
		m.handleUninspected(rw, req)
		return
	}

	start := m.buildStartRequest(req)
	reply, err := m.client.startTransaction(start)
	if err != nil {
		m.noteFailure(err)
		m.handleUninspected(rw, req)
		return
	}

	switch reply.Verdict {
	case verdictDrop:
		writeBlock(rw, reply.Response)
		return
	case verdictAccept, verdictNoop:
		m.next.ServeHTTP(rw, req)
		return
	}

	sid := reply.SessionID
	sessionActive := true
	defer func() {
		if sessionActive {
			m.client.finiSession(sid)
		}
	}()

	// Inspect the request body (if any) and always end the request phase so
	// the agent state machine advances before response inspection, mirroring
	// the envoy/kong attachments.
	reply, err = m.inspectRequestBody(sid, req)
	if err != nil {
		m.noteFailure(err)
		if m.failClose {
			writeBlock(rw, nil)
			return
		}
		// Fail-open: forward without further inspection.
		m.next.ServeHTTP(rw, req)
		return
	}
	switch reply.Verdict {
	case verdictDrop:
		sessionActive = false
		writeBlock(rw, reply.Response)
		return
	case verdictAccept, verdictNoop:
		sessionActive = false
		m.next.ServeHTTP(rw, req)
		return
	}

	if !m.responseInspection {
		m.next.ServeHTTP(rw, req)
		return
	}

	inspector := newResponseInspector(rw, m, sid)
	m.next.ServeHTTP(inspector, req)
	inspector.finish()
	if inspector.sessionDone {
		sessionActive = false
	}
}
