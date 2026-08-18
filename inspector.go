package openappsec_traefik_plugin

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strconv"
)

// responseInspector wraps the downstream http.ResponseWriter and feeds the
// upstream response (headers and body chunks) to the daemon before forwarding
// it to the client.
type responseInspector struct {
	rw  http.ResponseWriter
	m   *Middleware
	sid uint32

	wroteHeader bool // response status was forwarded downstream (or block was written)
	passthrough bool // inspection ended (accept / fail-open); forward everything as-is
	dropped     bool // block response was written; swallow the rest
	bodyWritten bool
	sessionDone bool // the daemon finalized the session
}

func newResponseInspector(rw http.ResponseWriter, m *Middleware, sid uint32) *responseInspector {
	return &responseInspector{rw: rw, m: m, sid: sid}
}

func collectHeaders(h http.Header) [][2]string {
	headers := make([][2]string, 0, len(h))
	for key, values := range h {
		for _, value := range values {
			headers = append(headers, [2]string{key, value})
		}
	}
	return headers
}

// inspectHeaders sends the response headers to the daemon. forward controls
// whether the status is forwarded downstream on a non-drop verdict.
func (i *responseInspector) inspectHeaders(statusCode int, forward bool) {
	contentLength, _ := strconv.ParseUint(i.rw.Header().Get("Content-Length"), 10, 64)
	reply, err := i.m.client.sendResponseHeaders(i.sid, &responseHeadersRequest{
		Code:          statusCode,
		ContentLength: contentLength,
		Headers:       collectHeaders(i.rw.Header()),
	})
	if err != nil {
		i.m.noteFailure(err)
		if i.m.failClose {
			i.dropped = true
			i.sessionDone = true
			writeBlock(i.rw, nil)
			i.wroteHeader = true
			return
		}
		i.passthrough = true
	} else {
		switch reply.Verdict {
		case verdictDrop:
			i.dropped = true
			i.sessionDone = true
			writeBlock(i.rw, reply.Response)
			i.wroteHeader = true
			return
		case verdictAccept:
			i.sessionDone = true
			i.passthrough = true
		case verdictNoop:
			i.passthrough = true
		}
	}
	if forward {
		i.rw.WriteHeader(statusCode)
		i.wroteHeader = true
	}
}

// Header implements http.ResponseWriter.
func (i *responseInspector) Header() http.Header {
	return i.rw.Header()
}

// WriteHeader implements http.ResponseWriter.
func (i *responseInspector) WriteHeader(statusCode int) {
	if i.wroteHeader || i.dropped {
		return
	}
	if i.passthrough {
		i.rw.WriteHeader(statusCode)
		i.wroteHeader = true
		return
	}
	i.inspectHeaders(statusCode, true)
}

// Write implements http.ResponseWriter.
func (i *responseInspector) Write(data []byte) (int, error) {
	if i.dropped {
		// Pretend the write succeeded so upstream copying does not error out.
		return len(data), nil
	}
	if !i.wroteHeader {
		i.WriteHeader(http.StatusOK)
		if i.dropped {
			return len(data), nil
		}
	}
	if i.passthrough {
		return i.rw.Write(data)
	}
	if len(data) == 0 {
		return 0, nil
	}

	reply, err := i.m.client.sendResponseBody(i.sid, data)
	if err != nil {
		i.m.noteFailure(err)
		if i.m.failClose {
			i.dropped = true
			panic(http.ErrAbortHandler)
		}
		i.passthrough = true
		return i.rw.Write(data)
	}

	switch reply.Verdict {
	case verdictDrop:
		i.dropped = true
		i.sessionDone = true
		// Headers were already sent; the only way to block is to abort the
		// connection (mirrors the kong plugin closing the connection).
		panic(http.ErrAbortHandler)
	case verdictAccept:
		i.sessionDone = true
		i.passthrough = true
	case verdictNoop:
		i.passthrough = true
	}

	i.bodyWritten = true
	if reply.BodyModified {
		if _, err := i.rw.Write(reply.Body); err != nil {
			return 0, err
		}
		return len(data), nil
	}
	return i.rw.Write(data)
}

// finish must be called after the upstream handler returned. It closes the
// response inspection for the session.
func (i *responseInspector) finish() {
	if i.dropped || i.passthrough {
		return
	}
	if !i.wroteHeader {
		// The upstream handler wrote nothing; net/http will emit an empty 200
		// once the middleware chain returns. Inspect that empty response
		// without forwarding the header so the default behavior is preserved.
		i.inspectHeaders(http.StatusOK, false)
		if i.dropped || i.passthrough {
			return
		}
	}

	reply, err := i.m.client.endResponse(i.sid)
	if err != nil {
		i.m.noteFailure(err)
		return
	}
	// The daemon always finalizes the session on response-end.
	i.sessionDone = true
	if reply.Verdict == verdictDrop {
		if !i.wroteHeader {
			i.dropped = true
			writeBlock(i.rw, reply.Response)
			i.wroteHeader = true
			return
		}
		// Too late to change the status; abort the connection.
		panic(http.ErrAbortHandler)
	}
}

// Flush implements http.Flusher.
func (i *responseInspector) Flush() {
	if flusher, ok := i.rw.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker (used for websocket upgrades). Hijacked
// connections bypass response inspection.
func (i *responseInspector) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := i.rw.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying ResponseWriter does not support hijacking")
	}
	i.passthrough = true
	i.wroteHeader = true
	return hijacker.Hijack()
}
