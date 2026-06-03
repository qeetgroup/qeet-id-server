package qeetid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const defaultBaseURL = "https://api.qeetid.com"

// Options configures the client. APIKey is required (a server-side `qk_…` key).
type Options struct {
	APIKey     string
	BaseURL    string       // default https://api.qeetid.com
	HTTPClient *http.Client // default: 10s timeout
	MaxRetries int          // default 2 (429 + 5xx on idempotent calls)
}

type httpClient struct {
	apiKey     string
	baseURL    string
	hc         *http.Client
	maxRetries int
}

// do executes a request with auth, JSON (de)serialisation, typed errors, and
// backoff on 429/5xx. idempotent governs whether 5xx is retried.
func (c *httpClient) do(ctx context.Context, method, path string, query url.Values, body, out any, idempotent bool) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("qeetid: marshal body: %w", err)
		}
		payload = b
	}

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, bytesReader(payload))
		if err != nil {
			return fmt.Errorf("qeetid: build request: %w", err)
		}
		// Qeet ID API keys use the `ApiKey` auth scheme (not Bearer).
		req.Header.Set("Authorization", "ApiKey "+c.apiKey)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		res, err := c.hc.Do(req)
		if err != nil {
			if idempotent && attempt < c.maxRetries {
				sleep(ctx, backoff(attempt))
				continue
			}
			return &Error{Code: "network_error", Message: err.Error()}
		}

		retryable := res.StatusCode == http.StatusTooManyRequests || (res.StatusCode >= 500 && idempotent)
		if retryable && attempt < c.maxRetries {
			wait := retryAfter(res)
			res.Body.Close()
			if wait <= 0 {
				wait = backoff(attempt)
			}
			sleep(ctx, wait)
			continue
		}

		defer res.Body.Close()
		requestID := res.Header.Get("X-Request-Id")
		if res.StatusCode == http.StatusNoContent {
			return nil
		}
		data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if res.StatusCode >= 300 {
			return parseError(res.StatusCode, data, requestID, int(retryAfter(res)/time.Second))
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("qeetid: decode response: %w", err)
			}
		}
		return nil
	}
}

func bytesReader(b []byte) io.Reader {
	if b == nil {
		return nil
	}
	return bytes.NewReader(b)
}

func parseError(status int, body []byte, requestID string, retryAfterSec int) error {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &env)
	code := env.Error.Code
	if code == "" {
		code = "http_" + strconv.Itoa(status)
	}
	msg := env.Error.Message
	if msg == "" {
		msg = "request failed with status " + strconv.Itoa(status)
	}
	return &Error{Status: status, Code: code, Message: msg, RequestID: requestID, RetryAfterSeconds: retryAfterSec}
}

func retryAfter(res *http.Response) time.Duration {
	if v := res.Header.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

func backoff(attempt int) time.Duration {
	base := 250 * time.Millisecond * (1 << attempt)
	return base + time.Duration(rand.Intn(100))*time.Millisecond
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
