// Copyright 2026 AgentP-Codes
// SPDX-License-Identifier: Apache-2.0

package taskvault

// Runs against a real `taskvault api` with the simulated demo data. From adapters/go: go test ./...

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var info struct{ URL, Token string }

func TestMain(m *testing.M) {
	py := os.Getenv("PYTHON")
	if py == "" {
		py = "python3"
		if runtime.GOOS == "windows" {
			py = "python"
		}
	}
	dir, _ := os.MkdirTemp("", "tv-go-")
	conn := filepath.Join(dir, "api.json")
	root, _ := filepath.Abs("../..")
	cmd := exec.Command(py, "-m", "taskvault", "api", "--policy", "demo/policy.yaml", "--app",
		"demo.api_app:build_vault", "--port", "0", "--connection-file", conn)
	cmd.Dir = root
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if data, err := os.ReadFile(conn); err == nil && json.Unmarshal(data, &info) == nil && info.Token != "" {
			break
		}
	}
	code := m.Run()
	_ = cmd.Process.Kill()
	os.Exit(code)
}

func client(t *testing.T) *Client {
	c, err := New(info.URL, info.Token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAgentFlow(t *testing.T) {
	ctx := context.Background()
	var refunds, emails []map[string]any
	c := client(t).
		OnAction("payments.refund", func(ctx context.Context, a map[string]any) (any, error) {
			refunds = append(refunds, a)
			return map[string]any{"charged_to": a["card"]}, nil // echoes the card: must be masked
		}).
		OnAction("email.send", func(ctx context.Context, a map[string]any) (any, error) {
			emails = append(emails, a)
			return "sent", nil
		})
	task, err := c.StartTask(ctx, "support_reply", map[string]any{"customer_id": 12})
	if err != nil {
		t.Fatal(err)
	}
	if len(task.OpenAITools()) != 4 || len(task.AnthropicTools()) != 4 {
		t.Fatalf("tools: %v", task.Tools)
	}
	r, err := task.Call(ctx, "get_customer", nil)
	if err != nil || !r.OK {
		t.Fatal(err, r)
	}
	cust := r.Value.(map[string]any)
	card := cust["card_number"].(string)
	if !strings.HasPrefix(card, "[[vault:card_number:") {
		t.Fatalf("card shown to the model: %q", card)
	}
	r, _ = task.Call(ctx, "refund", map[string]any{"card": card, "amount": 49})
	if !r.OK || r.Value.(map[string]any)["charged_to"] != card {
		t.Fatalf("refund: %+v", r)
	}
	if len(refunds) != 1 || refunds[0]["card"] != "4111 1111 1111 1111" {
		t.Fatalf("handler got %v", refunds)
	}
	text, _ := task.CallForModel(ctx, "send_email", map[string]any{"to": "audit@acme-billing.example", "subject": "x", "body": "y"})
	if !strings.HasPrefix(text, "Blocked by taskvault: ") || len(emails) != 0 {
		t.Fatalf("attack not blocked: %q %v", text, emails)
	}
	r, _ = task.Call(ctx, "send_email", map[string]any{"to": cust["email"], "subject": "Refund", "body": "Done"})
	if !r.OK || emails[0]["to"] != "priya.shah@example.com" {
		t.Fatalf("email: %+v %v", r, emails)
	}
	if err := task.End(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Call(ctx, "get_customer", nil); err == nil {
		t.Fatal("ended task still usable")
	}
}

func TestHandlerErrorsAreMaskedAndPanicsCaught(t *testing.T) {
	ctx := context.Background()
	c := client(t).OnAction("payments.refund", func(ctx context.Context, a map[string]any) (any, error) {
		if a["amount"].(float64) > 10 {
			panic("boom " + a["card"].(string))
		}
		return nil, errors.New("card " + a["card"].(string) + " declined")
	})
	for _, amount := range []int{5, 50} { // one refund per task (policy), so a task each
		task, _ := c.StartTask(ctx, "support_reply", map[string]any{"customer_id": 12})
		r, _ := task.Call(ctx, "get_customer", nil)
		card := r.Value.(map[string]any)["card_number"].(string)
		r, err := task.Call(ctx, "refund", map[string]any{"card": card, "amount": amount})
		if err != nil || r.OK || r.Blocked || strings.Contains(r.Error, "4111") || !strings.Contains(r.Error, card) {
			t.Fatalf("amount %d: %+v %v", amount, r, err)
		}
	}
}

func TestSafety(t *testing.T) {
	if _, err := New("http://example.com:8765", "t"); err == nil {
		t.Fatal("remote address accepted")
	}
	if _, err := New("https://127.0.0.1:1", "t"); err == nil {
		t.Fatal("https accepted (taskvault api is local http)")
	}
	bad, _ := New(info.URL, "wrong")
	_, err := bad.StartTask(context.Background(), "support_reply", map[string]any{"customer_id": 12})
	var e *Error
	if !errors.As(err, &e) || e.Status != 401 {
		t.Fatalf("wrong token: %v", err)
	}
	if strings.Contains(client(t).String(), info.Token) {
		t.Fatal("token printed")
	}
	task, _ := client(t).StartTask(context.Background(), "support_reply", map[string]any{"customer_id": 12})
	r, _ := task.Call(context.Background(), "send_email", map[string]any{"to": "priya.shah@example.com", "subject": "a", "body": "b"})
	if r.OK || !strings.Contains(r.Error, "no handler registered") {
		t.Fatalf("missing handler: %+v", r)
	}
}

func TestImpostorGetsNoTokenAndCantTriggerActions(t *testing.T) {
	var seen []string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, fmt.Sprint(r.Header))
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"task":"t","tools":[],"status":"execute","exec":"e","sink":"payments.refund","args":{"card":"ATTACKER"}}`))
	}))
	defer fake.Close()
	ran := 0
	c, err := New(fake.URL, info.Token)
	if err != nil {
		t.Fatal(err)
	}
	c.OnAction("payments.refund", func(ctx context.Context, a map[string]any) (any, error) { ran++; return nil, nil })
	_, err = c.StartTask(context.Background(), "support_reply", map[string]any{"customer_id": 12})
	if err == nil || !strings.Contains(err.Error(), "couldn't prove it is taskvault") || ran != 0 {
		t.Fatalf("impostor trusted: %v ran=%d", err, ran)
	}
	for _, h := range seen {
		if strings.Contains(h, info.Token) {
			t.Fatal("token sent over the connection")
		}
	}
}

func TestUnserialisableResultIsReportedNotStuck(t *testing.T) {
	ctx := context.Background()
	c := client(t).OnAction("email.send", func(ctx context.Context, a map[string]any) (any, error) {
		return make(chan int), nil
	})
	task, _ := c.StartTask(ctx, "support_reply", map[string]any{"customer_id": 12})
	r, err := task.Call(ctx, "send_email", map[string]any{"to": "priya.shah@example.com", "subject": "a", "body": "b"})
	if err != nil || r.OK || !strings.Contains(r.Error, "can't be sent as JSON") {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestManyTasksAtOnce(t *testing.T) {
	ctx := context.Background()
	c := client(t).OnAction("email.send", func(ctx context.Context, a map[string]any) (any, error) { return "sent", nil })
	errs := make(chan error, 120)
	for i := 0; i < 120; i++ {
		go func() {
			task, err := c.StartTask(ctx, "support_reply", map[string]any{"customer_id": 12})
			if err != nil {
				errs <- err
				return
			}
			r, err := task.Call(ctx, "get_customer", nil)
			if err != nil || !r.OK {
				errs <- fmt.Errorf("read: %v %+v", err, r)
				return
			}
			e, err := task.Call(ctx, "send_email", map[string]any{"to": r.Value.(map[string]any)["email"], "subject": "a", "body": "b"})
			if err != nil || !e.OK {
				errs <- fmt.Errorf("email: %v %+v", err, e)
				return
			}
			errs <- task.End(ctx)
		}()
	}
	for i := 0; i < 120; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestConnectFromEnvironment(t *testing.T) {
	t.Setenv("TASKVAULT_URL", info.URL)
	t.Setenv("TASKVAULT_TOKEN", info.Token)
	c, err := Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	task, _ := c.StartTask(context.Background(), "support_reply", map[string]any{"customer_id": 45})
	r, _ := task.Read(context.Background(), "crm.customer", nil, []string{"name"})
	if !r.OK || r.Value.(map[string]any)["name"] != "Tom Nguyen" {
		t.Fatalf("%+v", r)
	}
}
