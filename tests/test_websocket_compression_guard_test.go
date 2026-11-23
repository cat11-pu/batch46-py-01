package task

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-d-05"
)

func wsParams() taskpkg.Params {
	return taskpkg.Params{
		MaxWindowBits:        15,
		MaxMessageSize:       1000,
		MaxContexts:          4,
		CompressionThreshold: 100,
	}
}

func mustWsGuard(t *testing.T, p taskpkg.Params) *taskpkg.WsCompressionGuard {
	t.Helper()
	g := taskpkg.NewWsCompressionGuard(p)
	if g == nil {
		t.Fatalf("NewWsCompressionGuard returned nil")
	}
	return g
}

func mustOpen(t *testing.T, g *taskpkg.WsCompressionGuard, id string) {
	t.Helper()
	if err := g.Open(id); err != nil {
		t.Fatalf("Open(%q): %v", id, err)
	}
}

func mustNegotiate(t *testing.T, g *taskpkg.WsCompressionGuard, id string, offers []string) string {
	t.Helper()
	out, err := g.Negotiate(id, offers)
	if err != nil {
		t.Fatalf("Negotiate(%q): %v", id, err)
	}
	return out
}

func dataFrame(fin, rsv1 bool, opcode int, decompressed int64) taskpkg.Frame {
	return taskpkg.Frame{Fin: fin, RSV1: rsv1, Opcode: opcode, DecompressedLen: decompressed}
}

func controlFrame(fin, rsv1 bool, opcode, payload int) taskpkg.Frame {
	return taskpkg.Frame{Fin: fin, RSV1: rsv1, Opcode: opcode, PayloadLen: payload}
}

// Negotiated response values are deterministic and reflect the configured
// no-context-takeover and window bits.
func TestNegotiateDefaults(t *testing.T) {
	now := wsParams()
	g := mustWsGuard(t, now)
	mustOpen(t, g, "c1")
	if got := mustNegotiate(t, g, "c1", []string{"permessage-deflate"}); got != "permessage-deflate" {
		t.Fatalf("response = %q, want permessage-deflate", got)
	}
	p2 := wsParams()
	p2.ServerNoContextTakeover = true
	g2 := mustWsGuard(t, p2)
	mustOpen(t, g2, "c1")
	if got := mustNegotiate(t, g2, "c1", []string{"permessage-deflate"}); got != "permessage-deflate; server_no_context_takeover" {
		t.Fatalf("no-context-takeover response = %q", got)
	}
	p3 := wsParams()
	p3.MaxWindowBits = 12
	g3 := mustWsGuard(t, p3)
	mustOpen(t, g3, "c1")
	if got := mustNegotiate(t, g3, "c1", []string{"permessage-deflate"}); got != "permessage-deflate; server_max_window_bits=12" {
		t.Fatalf("window-bits response = %q", got)
	}
}

// Invalid parameters are rejected and a connection without offers stays
// uncompressed.
func TestNegotiateParamsAndErrors(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	if _, err := g.Negotiate("c1", []string{"permessage-deflate; server_max_window_bits=7"}); !errors.Is(err, taskpkg.ErrParam) {
		t.Fatalf("window bits 7: want ErrParam, got %v", err)
	}
	if _, err := g.Negotiate("c1", []string{"permessage-deflate; client_max_window_bits=x"}); !errors.Is(err, taskpkg.ErrParam) {
		t.Fatalf("non-numeric window bits: want ErrParam, got %v", err)
	}
	if _, err := g.Negotiate("ghost", []string{"permessage-deflate"}); !errors.Is(err, taskpkg.ErrNoConnection) {
		t.Fatalf("unknown connection: want ErrNoConnection, got %v", err)
	}
	mustOpen(t, g, "c2")
	out, err := g.Negotiate("c2", nil)
	if err != nil {
		t.Fatalf("no offers: %v", err)
	}
	if out != "" {
		t.Fatalf("no offers response = %q, want empty", out)
	}
	neg, err := g.Negotiated("c2")
	if err != nil {
		t.Fatalf("Negotiated: %v", err)
	}
	if neg {
		t.Fatalf("compression negotiated without an offer")
	}
}

// Compressed connections are capped by MaxContexts.
func TestContextLimit(t *testing.T) {
	p := wsParams()
	p.MaxContexts = 1
	g := mustWsGuard(t, p)
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	mustOpen(t, g, "c2")
	if _, err := g.Negotiate("c2", []string{"permessage-deflate"}); !errors.Is(err, taskpkg.ErrContextLimit) {
		t.Fatalf("second compressed connection: want ErrContextLimit, got %v", err)
	}
	if err := g.Close("c1"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := mustNegotiate(t, g, "c2", []string{"permessage-deflate"}); got != "permessage-deflate" {
		t.Fatalf("negotiation after release = %q", got)
	}
}

// A connection id is opened once, closed once, and state is only visible
// while it is open.
func TestOpenCloseState(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	if err := g.Open("c1"); !errors.Is(err, taskpkg.ErrConnExists) {
		t.Fatalf("duplicate open: want ErrConnExists, got %v", err)
	}
	if _, err := g.State("c1"); err != nil {
		t.Fatalf("State: %v", err)
	}
	if err := g.Close("c1"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := g.State("c1"); !errors.Is(err, taskpkg.ErrNoConnection) {
		t.Fatalf("state after close: want ErrNoConnection, got %v", err)
	}
	if err := g.Close("c1"); !errors.Is(err, taskpkg.ErrNoConnection) {
		t.Fatalf("second close: want ErrNoConnection, got %v", err)
	}
	counters := g.Counters()
	if counters.Opened != 1 || counters.Closed != 1 {
		t.Fatalf("counters = %+v, want Opened=1 Closed=1", counters)
	}
}

// Control frames must be final, short and uncompressed.
func TestControlFrameRules(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", controlFrame(true, false, taskpkg.OpPing, 1)); err != nil {
		t.Fatalf("valid ping: %v", err)
	}
	if err := g.AcceptFrame("c1", controlFrame(true, true, taskpkg.OpPing, 0)); !errors.Is(err, taskpkg.ErrControl) {
		t.Fatalf("compressed ping: want ErrControl, got %v", err)
	}
	if err := g.AcceptFrame("c1", controlFrame(false, false, taskpkg.OpClose, 0)); !errors.Is(err, taskpkg.ErrControl) {
		t.Fatalf("fragmented close: want ErrControl, got %v", err)
	}
	if err := g.AcceptFrame("c1", controlFrame(true, false, taskpkg.OpPing, 126)); !errors.Is(err, taskpkg.ErrControl) {
		t.Fatalf("oversized control payload: want ErrControl, got %v", err)
	}
	counters := g.Counters()
	if counters.FramesAccepted != 1 || counters.FramesRejected != 3 {
		t.Fatalf("counters = %+v, want FramesAccepted=1 FramesRejected=3", counters)
	}
}

// Continuations require an open message and data frames cannot start while a
// message is open.
func TestOpcodeSequence(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpContinuation, 0)); !errors.Is(err, taskpkg.ErrOpcode) {
		t.Fatalf("continuation without message: want ErrOpcode, got %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, 3, 0)); !errors.Is(err, taskpkg.ErrOpcode) {
		t.Fatalf("reserved opcode: want ErrOpcode, got %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(false, false, taskpkg.OpText, 0)); err != nil {
		t.Fatalf("first text fragment: %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpText, 0)); !errors.Is(err, taskpkg.ErrOpcode) {
		t.Fatalf("new message inside message: want ErrOpcode, got %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpContinuation, 0)); err != nil {
		t.Fatalf("final continuation: %v", err)
	}
	counters := g.Counters()
	if counters.FramesAccepted != 2 || counters.FramesRejected != 3 || counters.MessagesCompleted != 1 {
		t.Fatalf("counters = %+v", counters)
	}
}

// RSV1 is only legal on the first data frame and only when compression was
// negotiated.
func TestRSV1Rules(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 10)); !errors.Is(err, taskpkg.ErrRSV1) {
		t.Fatalf("compressed frame without negotiation: want ErrRSV1, got %v", err)
	}
	g2 := mustWsGuard(t, wsParams())
	mustOpen(t, g2, "c2")
	mustNegotiate(t, g2, "c2", []string{"permessage-deflate"})
	if err := g2.AcceptFrame("c2", dataFrame(false, false, taskpkg.OpText, 10)); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if err := g2.AcceptFrame("c2", dataFrame(false, true, taskpkg.OpContinuation, 10)); !errors.Is(err, taskpkg.ErrRSV1) {
		t.Fatalf("RSV1 on continuation: want ErrRSV1, got %v", err)
	}
	if err := g2.AcceptFrame("c2", dataFrame(true, false, taskpkg.OpContinuation, 10)); err != nil {
		t.Fatalf("final continuation: %v", err)
	}
}

// The sum of decompressed fragment sizes is capped and the oversized message
// is discarded.
func TestMessageSizeCap(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", dataFrame(false, false, taskpkg.OpText, 600)); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpContinuation, 500)); !errors.Is(err, taskpkg.ErrMessageTooLarge) {
		t.Fatalf("message over cap: want ErrMessageTooLarge, got %v", err)
	}
	st, err := g.State("c1")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.MessageOpen {
		t.Fatalf("oversized message was not discarded: %+v", st)
	}
	counters := g.Counters()
	if counters.BombsRejected != 1 || counters.FramesRejected != 1 {
		t.Fatalf("counters = %+v, want BombsRejected=1 FramesRejected=1", counters)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpText, 100)); err != nil {
		t.Fatalf("message after bomb rejection: %v", err)
	}
	if got := g.Counters().MessagesCompleted; got != 1 {
		t.Fatalf("MessagesCompleted = %d, want 1", got)
	}
}

// Fragment sizes and frames are accounted on the connection.
func TestFragmentAccounting(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", dataFrame(false, false, taskpkg.OpText, 100)); err != nil {
		t.Fatalf("fragment 1: %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(false, false, taskpkg.OpContinuation, 100)); err != nil {
		t.Fatalf("fragment 2: %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpContinuation, 100)); err != nil {
		t.Fatalf("fragment 3: %v", err)
	}
	st, err := g.State("c1")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.MessageOpen || st.MessageBytes != 300 || st.Frames != 3 {
		t.Fatalf("state = %+v, want closed message with 300 bytes in 3 frames", st)
	}
	counters := g.Counters()
	if counters.BytesAccepted != 300 || counters.FramesAccepted != 3 || counters.MessagesCompleted != 1 {
		t.Fatalf("counters = %+v", counters)
	}
}

// Small messages, uncompressed connections and oversized messages are not
// worth compressing.
func TestCompressibleThreshold(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	if g.Compressible("c1", 500) {
		t.Fatalf("unnegotiated connection reported compressible")
	}
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if g.Compressible("c1", 50) {
		t.Fatalf("message below threshold reported compressible")
	}
	if !g.Compressible("c1", 100) {
		t.Fatalf("message at threshold reported incompressible")
	}
	if !g.Compressible("c1", 1000) {
		t.Fatalf("message at size cap reported incompressible")
	}
	if g.Compressible("c1", 1001) {
		t.Fatalf("message over size cap reported compressible")
	}
	if g.Compressible("ghost", 500) {
		t.Fatalf("unknown connection reported compressible")
	}
}

// With server_no_context_takeover the next compressed message must wait for a
// context reset.
func TestNoContextTakeoverRequiresReset(t *testing.T) {
	p := wsParams()
	p.ServerNoContextTakeover = true
	g := mustWsGuard(t, p)
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 10)); err != nil {
		t.Fatalf("first compressed message: %v", err)
	}
	st, err := g.State("c1")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if !st.ContextDirty {
		t.Fatalf("context not marked dirty after no-context-takeover message")
	}
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 10)); !errors.Is(err, taskpkg.ErrContextStale) {
		t.Fatalf("compressed message on dirty context: want ErrContextStale, got %v", err)
	}
	if err := g.ResetContext("c1"); err != nil {
		t.Fatalf("ResetContext: %v", err)
	}
	st, err = g.State("c1")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.ContextDirty || st.ContextGeneration != 1 {
		t.Fatalf("state after reset = %+v", st)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 10)); err != nil {
		t.Fatalf("compressed message after reset: %v", err)
	}
	if got := g.Counters().ContextsReset; got != 1 {
		t.Fatalf("ContextsReset = %d, want 1", got)
	}
}

// With context takeover compressed messages may follow each other without a
// reset, and an explicit reset is still allowed.
func TestContextTakeoverPersists(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 10)); err != nil {
		t.Fatalf("first compressed message: %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 10)); err != nil {
		t.Fatalf("second compressed message: %v", err)
	}
	st, err := g.State("c1")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.ContextDirty || st.ContextGeneration != 0 {
		t.Fatalf("state = %+v, want clean persistent context", st)
	}
	if err := g.ResetContext("c1"); err != nil {
		t.Fatalf("ResetContext: %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 10)); err != nil {
		t.Fatalf("compressed message after explicit reset: %v", err)
	}
}

// A restart must preserve a half-assembled fragmented message so the final
// continuation can complete it.
func TestSnapshotRestoresFragment(t *testing.T) {
	p := wsParams()
	g := mustWsGuard(t, p)
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", dataFrame(false, true, taskpkg.OpText, 500)); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := taskpkg.NewWsCompressionGuardFromSnapshot(p, []byte("broken")); !errors.Is(err, taskpkg.ErrSnapshot) {
		t.Fatalf("corrupt snapshot: want ErrSnapshot, got %v", err)
	}
	restored, err := taskpkg.NewWsCompressionGuardFromSnapshot(p, snap)
	if err != nil {
		t.Fatalf("NewWsCompressionGuardFromSnapshot: %v", err)
	}
	st, err := restored.State("c1")
	if err != nil {
		t.Fatalf("State after restore: %v", err)
	}
	if !st.MessageOpen || !st.MessageCompressed || st.MessageBytes != 500 {
		t.Fatalf("restored state = %+v, want open compressed message with 500 bytes", st)
	}
	if err := restored.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpContinuation, 200)); err != nil {
		t.Fatalf("final continuation after restore: %v", err)
	}
	st, err = restored.State("c1")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.MessageOpen || st.MessageBytes != 700 {
		t.Fatalf("state after completion = %+v, want closed message with 700 bytes", st)
	}
	if got := restored.Counters().MessagesCompleted; got != 1 {
		t.Fatalf("MessagesCompleted = %d, want 1", got)
	}
}

// Concurrent continuations on one connection must all be accounted for.
func TestConcurrentContinuations(t *testing.T) {
	p := wsParams()
	p.MaxMessageSize = 10000
	g := mustWsGuard(t, p)
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", dataFrame(false, false, taskpkg.OpBinary, 0)); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	const n = 50
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = g.AcceptFrame("c1", dataFrame(false, false, taskpkg.OpContinuation, 100))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("continuation %d: %v", i, err)
		}
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpContinuation, 0)); err != nil {
		t.Fatalf("final continuation: %v", err)
	}
	st, err := g.State("c1")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.MessageOpen || st.MessageBytes != int64(n*100) {
		t.Fatalf("state = %+v, want closed message with %d bytes", st, n*100)
	}
	if got := g.Counters().BytesAccepted; got != int64(n*100) {
		t.Fatalf("BytesAccepted = %d, want %d", got, n*100)
	}
	if got := g.Counters().MessagesCompleted; got != 1 {
		t.Fatalf("MessagesCompleted = %d, want 1", got)
	}
}

// Every counter reflects exactly one accepted or rejected operation.
func TestCountersExact(t *testing.T) {
	g := mustWsGuard(t, wsParams())
	mustOpen(t, g, "c1")
	mustNegotiate(t, g, "c1", []string{"permessage-deflate"})
	if err := g.AcceptFrame("c1", controlFrame(true, false, taskpkg.OpPing, 0)); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpText, 10)); err != nil {
		t.Fatalf("text message: %v", err)
	}
	if err := g.AcceptFrame("c1", controlFrame(true, true, taskpkg.OpClose, 0)); !errors.Is(err, taskpkg.ErrControl) {
		t.Fatalf("compressed close: want ErrControl, got %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, false, taskpkg.OpContinuation, 0)); !errors.Is(err, taskpkg.ErrOpcode) {
		t.Fatalf("orphan continuation: want ErrOpcode, got %v", err)
	}
	if err := g.AcceptFrame("c1", dataFrame(true, true, taskpkg.OpText, 1001)); !errors.Is(err, taskpkg.ErrMessageTooLarge) {
		t.Fatalf("oversized compressed message: want ErrMessageTooLarge, got %v", err)
	}
	if err := g.ResetContext("c1"); err != nil {
		t.Fatalf("ResetContext: %v", err)
	}
	if err := g.Close("c1"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	want := taskpkg.Stats{
		Opened:            1,
		Closed:            1,
		FramesAccepted:    2,
		FramesRejected:    3,
		MessagesCompleted: 1,
		BytesAccepted:     10,
		ContextsReset:     1,
		BombsRejected:     1,
	}
	if got := g.Counters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Counters = %+v, want %+v", got, want)
	}
}
