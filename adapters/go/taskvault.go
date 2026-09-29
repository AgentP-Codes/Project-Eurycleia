// Copyright 2026 AgentP-Codes
// SPDX-License-Identifier: Apache-2.0

// Package taskvault lets Go agents use taskvault. No dependencies: the Go standard library only.
//
// It is a thin client for `taskvault api` running on the same computer. Every check, placeholder,
// pseudonym, audit entry and block happens in taskvault itself; this package only carries requests and
// runs the actions (email, refunds, ...) that taskvault has approved, using handlers you register.
package taskvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ToolSpec describes a tool the model may call (JSON Schema in InputSchema).
type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// Result of a tool call, read or action. A blocked call is not an error: check Blocked.
type Result struct {
	OK      bool
	Blocked bool
	Reason  string // why it was blocked (safe to show the model)
	Error   string // what went wrong (real values already masked)
	Value   any    // the result when OK
}

// ActionHandler runs an approved action. args holds REAL values (e.g. the real card number): don't log
// them or give them to the model. Whatever you return is masked by taskvault before the model sees it.
type ActionHandler func(ctx context.Context, args map[string]any) (any, error)

// Error is returned when taskvault can't be reached or rejects a request.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return "taskvault: " + e.Message }

// Client talks to `taskvault api`.
type Client struct {
	base     string
	token    string
	http     *http.Client
	mu       sync.RWMutex
	handlers map[string]ActionHandler
}

// String never includes the token.
func (c *Client) String() string { return "taskvault.Client(" + c.base + ")" }

// New makes a client for the given address (must be on this computer) and token.
func New(address, token string) (*Client, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return nil, &Error{Message: "taskvault api only runs on this computer (http://127.0.0.1)"}
	}
	if token == "" {
		return nil, &Error{Message: "missing token"}
	}
	hc := &http.Client{
		Timeout:       10 * time.Minute,
		Transport:     &http.Transport{Proxy: nil}, // this computer: never through a proxy
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects refused") },
	}
	// The server listens on IPv4 only: never let "localhost" go to ::1, where another program could listen.
	base := "http://127.0.0.1"
	if p := u.Port(); p != "" {
		base += ":" + p
	}
	return &Client{base: base, token: token, http: hc, handlers: map[string]ActionHandler{}}, nil
}

// Connect uses TASKVAULT_URL and TASKVAULT_TOKEN, or the file `taskvault api` writes.
func Connect(ctx context.Context) (*Client, error) {
	addr, token := os.Getenv("TASKVAULT_URL"), os.Getenv("TASKVAULT_TOKEN")
	if addr == "" || token == "" {
		home := os.Getenv("TASKVAULT_HOME")
		if home == "" {
			h, _ := os.UserHomeDir()
			home = filepath.Join(h, ".taskvault")
		}
		data, err := os.ReadFile(filepath.Join(home, "api.json"))
		if err != nil {
			return nil, &Error{Message: "can't find a running taskvault: start `taskvault api`, or set TASKVAULT_URL and TASKVAULT_TOKEN"}
		}
		var info struct{ URL, Token string }
		if err := json.Unmarshal(data, &info); err != nil {
			return nil, &Error{Message: "the taskvault connection file is damaged"}
		}
		addr, token = info.URL, info.Token
	}
	c, err := New(addr, token)
	if err != nil {
		return nil, err
	}
	if _, err := c.request(ctx, http.MethodGet, "/v1/health", nil); err != nil {
		return nil, err
	}
	return c, nil
}

// OnAction registers the code that runs an action once taskvault has approved it.
func (c *Client) OnAction(sink string, h ActionHandler) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[sink] = h
	return c
}

// StartTask starts a task. trusted must come from your app (e.g. the logged-in customer), never the model.
func (c *Client) StartTask(ctx context.Context, template string, trusted map[string]any) (*Task, error) {
	if trusted == nil {
		trusted = map[string]any{}
	}
	out, err := c.request(ctx, http.MethodPost, "/v1/tasks", map[string]any{"template": template, "trusted": trusted})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Task  string     `json:"task"`
		Tools []ToolSpec `json:"tools"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, &Error{Message: "unexpected reply from taskvault"}
	}
	return &Task{c: c, id: parsed.Task, Tools: parsed.Tools}, nil
}

func (c *Client) mac(parts ...string) []byte {
	m := hmac.New(sha256.New, []byte(c.token))
	m.Write([]byte(strings.Join(parts, "\n")))
	return m.Sum(nil)
}

func hexSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// request signs the request with the token (which itself never goes over the connection) and only trusts
// a reply carrying the server's signature, so another program listening on the port can't pose as taskvault.
func (c *Client) request(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return nil, err
	}
	nonce, ts := hex.EncodeToString(nb), strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-taskvault-time", ts)
	req.Header.Set("x-taskvault-nonce", nonce)
	req.Header.Set("x-taskvault-auth", hex.EncodeToString(c.mac("TV1", method, path, ts, nonce, hexSHA(payload))))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Error{Message: "can't reach taskvault at " + c.base}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, &Error{Message: "reading taskvault's reply failed"}
	}
	got, _ := hex.DecodeString(resp.Header.Get("x-taskvault-auth"))
	if !hmac.Equal(got, c.mac("TV1-RESPONSE", nonce, strconv.Itoa(resp.StatusCode), hexSHA(data))) {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, &Error{Status: 401, Message: "taskvault refused the request: wrong token, or this computer's clock is off by more than 2 minutes"}
		}
		return nil, &Error{Status: resp.StatusCode, Message: "the server at " + c.base + " couldn't prove it is taskvault; not trusting its reply"}
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("taskvault replied %d", resp.StatusCode)
		}
		return nil, &Error{Status: resp.StatusCode, Message: e.Error}
	}
	return data, nil
}

type reply struct {
	Status  string         `json:"status"`
	Result  any            `json:"result"`
	Reason  string         `json:"reason"`
	Message string         `json:"message"`
	Exec    string         `json:"exec"`
	Sink    string         `json:"sink"`
	Args    map[string]any `json:"args"`
}

func (c *Client) run(ctx context.Context, path string, body any) (*Result, error) {
	data, err := c.request(ctx, http.MethodPost, path, body)
	for {
		if err != nil {
			return nil, err
		}
		var r reply
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, &Error{Message: "unexpected reply from taskvault"}
		}
		switch r.Status {
		case "ok":
			return &Result{OK: true, Value: r.Result}, nil
		case "blocked":
			return &Result{Blocked: true, Reason: r.Reason}, nil
		case "execute":
			c.mu.RLock()
			h := c.handlers[r.Sink]
			c.mu.RUnlock()
			var back map[string]any
			if h == nil {
				back = map[string]any{"error": "no handler registered for " + r.Sink + " (use OnAction)"}
			} else if v, herr := safeRun(ctx, h, r.Args); herr != nil {
				back = map[string]any{"error": herr.Error()}
			} else if _, merr := json.Marshal(v); merr != nil {
				back = map[string]any{"error": "the handler's result can't be sent as JSON: " + merr.Error()}
			} else {
				back = map[string]any{"result": v}
			}
			data, err = c.request(ctx, http.MethodPost, "/v1/exec/"+url.PathEscape(r.Exec), back)
		default:
			return &Result{Error: r.Message}, nil
		}
	}
}

func safeRun(ctx context.Context, h ActionHandler, args map[string]any) (v any, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("handler panicked: %v", p)
		}
	}()
	return h(ctx, args)
}

// Task is one running task.
type Task struct {
	c     *Client
	id    string
	Tools []ToolSpec
}

func (t *Task) path(op string) string { return "/v1/tasks/" + url.PathEscape(t.id) + "/" + op }

// Call runs a tool the model asked for.
func (t *Task) Call(ctx context.Context, name string, args map[string]any) (*Result, error) {
	if args == nil {
		args = map[string]any{}
	}
	return t.c.run(ctx, t.path("call"), map[string]any{"name": name, "arguments": args})
}

// CallForModel is Call, as the text to hand back to the model.
func (t *Task) CallForModel(ctx context.Context, name string, args map[string]any) (string, error) {
	r, err := t.Call(ctx, name, args)
	if err != nil {
		return "", err
	}
	switch {
	case r.OK:
		if s, ok := r.Value.(string); ok {
			return s, nil
		}
		b, _ := json.Marshal(r.Value)
		return string(b), nil
	case r.Blocked:
		return "Blocked by taskvault: " + r.Reason, nil
	default:
		return "Error: " + r.Error, nil
	}
}

// Read reads from a source directly (code-first apps). key and fields may be nil.
func (t *Task) Read(ctx context.Context, source string, key any, fields []string) (*Result, error) {
	body := map[string]any{"source": source, "key": key}
	if fields != nil {
		body["fields"] = fields
	}
	return t.c.run(ctx, t.path("read"), body)
}

// Act asks for an action directly (code-first apps). Runs your OnAction handler if approved.
func (t *Task) Act(ctx context.Context, sink string, args map[string]any) (*Result, error) {
	if args == nil {
		args = map[string]any{}
	}
	return t.c.run(ctx, t.path("act"), map[string]any{"sink": sink, "args": args})
}

// End ends the task.
func (t *Task) End(ctx context.Context) error {
	_, err := t.c.request(ctx, http.MethodPost, t.path("end"), map[string]any{})
	return err
}

// OpenAITools is the chat-completions `tools` array (also Ollama and most OpenAI-compatible servers).
func (t *Task) OpenAITools() []map[string]any {
	out := make([]map[string]any, 0, len(t.Tools))
	for _, s := range t.Tools {
		out = append(out, map[string]any{"type": "function", "function": map[string]any{
			"name": s.Name, "description": s.Description, "parameters": s.InputSchema}})
	}
	return out
}

// AnthropicTools is the Messages API `tools` array.
func (t *Task) AnthropicTools() []map[string]any {
	out := make([]map[string]any, 0, len(t.Tools))
	for _, s := range t.Tools {
		out = append(out, map[string]any{"name": s.Name, "description": s.Description, "input_schema": s.InputSchema})
	}
	return out
}
