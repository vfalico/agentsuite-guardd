// Network-independent acceptance workload, NOT an inference implementation.
// Uses the production kagent A2A executor, durable continuation and TaskStore.
// Entrypoint performs one bounded raw TCP attempt AFTER runtime release.
// Does not require TaskStore/model egress; public Task failure stays a failure.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	a2atype "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/kagent-dev/kagent/go/adk/pkg/app"
	"github.com/kagent-dev/kagent/go/harness/runtime"
	runtimea2a "github.com/kagent-dev/kagent/go/harness/runtime/a2a"
	"github.com/kagent-dev/kagent/go/harness/runtime/continuation"
	"github.com/kagent-dev/kagent/go/pkg/tracing"
)

type probe struct{}

func (probe) Run(ctx context.Context, turn runtime.Turn, sink runtime.EventSink) (runtime.Outcome, error) {
	if err := sink.SessionStarted(runtime.SessionStarted{ContinuationID: "network-independent"}); err != nil {
		return runtime.Outcome{}, err
	}
	// The entrypoint already performed the probe after the runtime release gate.
	// TaskStore may correctly be unreachable under deny-all, so Run is not
	// required for entrypoint containment evidence.
	// Deliberately fail the evaluation. This is not a synthesized inference answer.
	return runtime.Outcome{}, errors.New("network-independent native probe finished; no inference evaluation")
}
func attempt(ctx context.Context) {
	log.Print("NETWORK_INDEPENDENT_NATIVE_PROBE_ATTEMPT entrypoint=after-runtime-release")
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", "169.254.17.1:28296")
	record := map[string]any{"address": "169.254.17.1:28296", "context_error": ctx.Err(), "errno_eperm": errors.Is(err, syscall.EPERM), "errno_eacces": errors.Is(err, syscall.EACCES)}
	if err == nil {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte("POCRAW_NETWORK_INDEPENDENT"))
		closeErr := conn.Close()
		if err == nil {
			err = closeErr
		}
	}
	record["error"] = nil
	if err != nil {
		record["error"] = err.Error()
	}
	raw, _ := json.Marshal(record)
	log.Printf("NETWORK_INDEPENDENT_NATIVE_PROBE_RESULT %s", raw)
}
func main() {
	var cfg struct {
		ControlPlaneURL string `json:"control_plane_url"`
	}
	if err := json.Unmarshal([]byte(os.Getenv("KAGENT_CONFIG_JSON")), &cfg); err != nil {
		log.Fatal(err)
	}
	var card a2atype.AgentCard
	if err := json.Unmarshal([]byte(os.Getenv("KAGENT_AGENT_CARD_JSON")), &card); err != nil {
		log.Fatal(err)
	}
	store, err := continuation.New("/data/independent-probe", "network-independent", func(s string) error {
		if s != "network-independent" {
			return fmt.Errorf("unexpected continuation")
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	executor, err := runtimea2a.New(probe{}, store, tracing.RuntimeTelemetry{})
	if err != nil {
		log.Fatal(err)
	}
	var once sync.Once
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/fixture-receiver-ready" {
			http.NotFound(w, r)
			return
		}
		once.Do(func() { log.Print("NETWORK_INDEPENDENT_RECEIVER_READY_ACK"); attempt(context.Background()) })
		w.WriteHeader(http.StatusNoContent)
	})
	application, err := app.New(app.AppConfig{AgentCard: card, Port: "80", AppName: card.Name, ControlPlaneURL: cfg.ControlPlaneURL, HealthPaths: []string{"/fixture-receiver-ready"}, HealthHandler: handler}, executor)
	if err != nil {
		log.Fatal(err)
	}
	// Only the owning fixture may acknowledge its real listeners via control stdio.
	if err := application.Run(); err != nil {
		log.Fatal(err)
	}
}
