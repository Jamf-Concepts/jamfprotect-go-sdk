// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// redactedValue replaces secret values in bodies handed to a Logger.
const redactedValue = "[REDACTED]"

// secretFields lists GraphQL field and variable names whose string values are
// redacted before request and response bodies reach a Logger.
var secretFields = map[string]bool{
	"azureClientSecret":      true,
	"csr":                    true,
	"offlineDeploymentToken": true,
	"password":               true,
	"sharedKey":              true,
	"token":                  true,
	"url":                    true,
	"websocket_auth":         true,
}

// Logger is an interface for logging HTTP requests and responses.
type Logger interface {
	LogRequest(ctx context.Context, method, url string, headers http.Header, body []byte)
	LogResponse(ctx context.Context, statusCode int, headers http.Header, body []byte)
}

// httpDoer is an interface that matches the Do method of http.Client, allowing for easier testing and logging.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// loggingDoer is an httpDoer that logs requests and responses using a Logger.
type loggingDoer struct {
	base    httpDoer
	logger  Logger
	maxBody int64
}

// Do implements the httpDoer interface, logging the request and response.
func (d *loggingDoer) Do(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		var err error
		reqBody, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	if d.logger != nil {
		d.logger.LogRequest(req.Context(), req.Method, req.URL.String(), redactRequestHeaders(req.Header), redactBody(reqBody))
	}

	resp, err := d.base.Do(req)
	if err != nil {
		return resp, err
	}
	if resp != nil && resp.Body != nil {
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, d.maxBody+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		if d.logger != nil {
			logged := []byte("[response body exceeds size limit]")
			if int64(len(respBody)) <= d.maxBody {
				logged = redactBody(respBody)
			}
			d.logger.LogResponse(req.Context(), resp.StatusCode, resp.Header, logged)
		}
	}
	return resp, nil
}

// redactRequestHeaders creates a redacted version of the request headers for logging, hiding sensitive information like the Authorization header.
func redactRequestHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	clone := headers.Clone()
	if clone.Get("Authorization") != "" {
		clone.Set("Authorization", "[REDACTED]")
	}
	return clone
}

// redactBody returns a copy of a JSON body with secret values replaced, so it
// can be logged. Bodies that are not JSON, or that contain no secrets, are
// copied unchanged.
func redactBody(body []byte) []byte {
	v, ok := decodeJSON(body)
	if !ok || !redactValue(v, "") {
		return bytes.Clone(body)
	}
	out, ok := encodeJSON(v)
	if !ok {
		return []byte(redactedValue)
	}
	return out
}

// redactValue replaces secret values inside a decoded JSON value in place and
// reports whether anything was replaced. parent is the key the value was found
// under. Besides fields named in secretFields it redacts the value of every
// HTTP header object under a "headers" key, and descends into JSON documents
// embedded as strings (AWSJSON).
func redactValue(v any, parent string) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && s != "" && (secretFields[k] || (parent == "headers" && k == "value")) {
				t[k] = redactedValue
				changed = true
			} else if r, ok := redactNested(val, k); ok {
				t[k] = r
				changed = true
			}
		}
	case []any:
		for i, val := range t {
			if r, ok := redactNested(val, parent); ok {
				t[i] = r
				changed = true
			}
		}
	}
	return changed
}

// redactNested redacts secrets nested in val, found under key, and returns the
// replacement value. A string is treated as a possibly embedded JSON document.
func redactNested(val any, key string) (any, bool) {
	s, ok := val.(string)
	if !ok {
		return val, redactValue(val, key)
	}
	inner, ok := decodeJSON([]byte(s))
	if !ok || !redactValue(inner, key) {
		return val, false
	}
	out, ok := encodeJSON(inner)
	if !ok {
		return redactedValue, true
	}
	return string(out), true
}

// decodeJSON decodes b if it holds a JSON object or array, preserving numbers.
func decodeJSON(b []byte) (any, bool) {
	if !looksLikeJSON(b) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

// encodeJSON encodes v without HTML escaping so logged bodies stay readable.
func encodeJSON(v any) ([]byte, bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true
}
