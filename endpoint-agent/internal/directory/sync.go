package directory

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Uploader posts one gzip-compressed JSON batch to path with the sync token.
type Uploader interface {
	UploadDirectoryBatch(ctx context.Context, path, token string, gz []byte) error
}

// statusError is implemented by client.HTTPError.
type statusError interface{ StatusCode() int }

// Result summarises a run (for the agent log; the server gets the final batch).
type Result struct {
	Status    string // succeeded | failed
	Error     string
	Totals    Totals
	Truncated bool
	Batches   int
	Server    string
}

// Runner executes directory syncs. Zero values are replaced by defaults.
type Runner struct {
	Connect Connector
	Upload  Uploader
	// RetryDelays between upload attempts (network errors / 5xx / 429).
	RetryDelays []time.Duration
	// FinalTimeout bounds the final "failed" batch sent after cancellation.
	FinalTimeout time.Duration
	Now          func() time.Time
}

var errCapReached = errors.New("max_objects reached")

// errUploadStopped: the server refused a batch permanently; no final batch is sent.
type errUploadStopped struct{ err error }

func (e errUploadStopped) Error() string { return "upload refused by the server: " + e.err.Error() }

// Redact removes secret values from a message.
func Redact(msg string, secrets ...string) string {
	for _, s := range secrets {
		if len(s) >= 3 {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return msg
}

// Run performs one sync. It never panics on bad data and always tries to send
// a final batch (unless the server permanently refused the upload).
func (r *Runner) Run(ctx context.Context, p *Params) Result {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	start := now()
	runCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	s := &syncState{r: r, p: p, ctx: runCtx}
	err := s.collect()
	res := Result{Totals: s.totals, Truncated: s.truncated, Server: s.server}
	var stopped errUploadStopped
	if errors.As(err, &stopped) {
		res.Status, res.Error, res.Batches = "failed", Redact(err.Error(), p.Secrets()...), s.seq
		return res
	}
	final := Batch{Seq: s.seq, Final: true, Computers: s.computers, Users: s.users, Truncated: s.truncated,
		Totals: &s.totals, Server: s.server}
	final.Status = "succeeded"
	if err != nil {
		final.Status = "failed"
		switch {
		case ctx.Err() != nil:
			final.Error = "cancelled: the agent is stopping"
		case runCtx.Err() == context.DeadlineExceeded:
			final.Error = fmt.Sprintf("timed out after %s", p.Timeout)
		default:
			final.Error = err.Error()
		}
		final.Error = clean(Redact(final.Error, p.Secrets()...), 2000)
		// A failed run uploads no further objects (the buffered rest is dropped);
		// the server never marks objects missing after an incomplete run.
		final.Computers, final.Users = []Computer{}, []User{}
	}
	final.DurationMS = now().Sub(start).Milliseconds()
	sendCtx := runCtx
	if runCtx.Err() != nil {
		// Cancelled / timed out: best effort with a fresh, short context.
		ft := r.FinalTimeout
		if ft == 0 {
			ft = 15 * time.Second
		}
		var c context.CancelFunc
		sendCtx, c = context.WithTimeout(context.WithoutCancel(ctx), ft)
		defer c()
	}
	uerr := s.send(sendCtx, final)
	res.Status, res.Error, res.Batches = final.Status, final.Error, s.seq
	if uerr != nil {
		res.Status = "failed"
		res.Error = Redact("final batch not delivered: "+uerr.Error(), p.Secrets()...)
	}
	return res
}

type syncState struct {
	r         *Runner
	p         *Params
	ctx       context.Context
	seq       int
	computers []Computer
	users     []User
	totals    Totals
	truncated bool
	server    string
	seen      map[string]struct{} // objectGUIDs, only when several base DNs could overlap
}

func (s *syncState) pending() int { return len(s.computers) + len(s.users) }

func (s *syncState) collect() error {
	if s.r.Connect == nil {
		return errors.New("no directory connector")
	}
	conn, err := s.r.Connect(s.ctx, s.p)
	if err != nil {
		return err
	}
	defer conn.Close()
	s.server = conn.Server()
	bases := s.p.SearchBases()
	if len(bases) > 1 {
		s.seen = map[string]struct{}{}
	}
	s.computers, s.users = []Computer{}, []User{}
	for _, scope := range s.p.Scopes {
		filter, attrs := ComputerFilter, ComputerAttributes
		if scope == ScopeUsers {
			filter, attrs = UserFilter, UserAttributes
		}
		for _, base := range bases {
			err := conn.Search(s.ctx, base, filter, attrs, s.p.PageSize, func(e Entry) error {
				return s.add(scope, e)
			})
			if errors.Is(err, errCapReached) {
				s.truncated = true
				return nil
			}
			if err != nil {
				if s.ctx.Err() != nil {
					return s.ctx.Err()
				}
				var stopped errUploadStopped
				if errors.As(err, &stopped) {
					return err
				}
				return fmt.Errorf("searching %s under %s: %w", scope, base, err)
			}
		}
	}
	return nil
}

func (s *syncState) add(scope string, e Entry) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.totals.Computers+s.totals.Users >= s.p.MaxObjects {
		return errCapReached
	}
	var guid string
	if scope == ScopeComputers {
		c, ok := ComputerFromEntry(e)
		if !ok {
			return nil
		}
		guid = c.ObjectGUID
		if s.dup(guid) {
			return nil
		}
		s.computers = append(s.computers, c)
		s.totals.Computers++
	} else {
		u, ok := UserFromEntry(e)
		if !ok {
			return nil
		}
		guid = u.ObjectGUID
		if s.dup(guid) {
			return nil
		}
		s.users = append(s.users, u)
		s.totals.Users++
	}
	if s.pending() >= s.p.BatchSize {
		b := Batch{Seq: s.seq, Computers: s.computers, Users: s.users}
		if err := s.send(s.ctx, b); err != nil {
			return err
		}
		s.computers, s.users = []Computer{}, []User{}
	}
	return nil
}

func (s *syncState) dup(guid string) bool {
	if s.seen == nil {
		return false
	}
	if _, ok := s.seen[guid]; ok {
		return true
	}
	s.seen[guid] = struct{}{}
	return false
}

// send uploads one batch with retries; seq advances only on success.
func (s *syncState) send(ctx context.Context, b Batch) error {
	gz, err := encode(b)
	if err != nil {
		return err
	}
	delays := s.r.RetryDelays
	if delays == nil {
		delays = []time.Duration{2 * time.Second, 10 * time.Second}
	}
	for attempt := 0; ; attempt++ {
		err = s.r.Upload.UploadDirectoryBatch(ctx, s.p.UploadPath, s.p.UploadToken, gz)
		if err == nil {
			s.seq++
			return nil
		}
		var se statusError
		if errors.As(err, &se) {
			code := se.StatusCode()
			if code >= 400 && code < 500 && code != 408 && code != 429 {
				return errUploadStopped{err}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err() // cancelled / timed out: Run sends the final batch
		}
		if attempt >= len(delays) {
			return errUploadStopped{err}
		}
		t := time.NewTimer(delays[attempt])
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func encode(b Batch) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
