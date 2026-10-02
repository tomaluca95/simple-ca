package types

import (
	"context"
	"log/slog"
)

// Logger is the logging surface of the whole program. Message arguments are
// alternating key/value pairs, exactly like log/slog. The context is passed
// through so per-request attributes (see WithRequestId) land on every record
// of the same request, which is how one request can be traced together.
type Logger interface {
	// With returns a logger that adds the given key/value pairs to every
	// record, used to bind long-lived attributes such as the CA id.
	With(args ...any) Logger
	DebugContext(ctx context.Context, msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
}

// StdLogger logs through log/slog. The zero value uses slog.Default(), so
// callers that do not care about the output format can keep using
// &StdLogger{} unchanged.
type StdLogger struct {
	logger *slog.Logger
}

func NewStdLogger(logger *slog.Logger) *StdLogger {
	return &StdLogger{logger: logger}
}

func (l *StdLogger) getLogger() *slog.Logger {
	if l.logger != nil {
		return l.logger
	}
	return slog.Default()
}

func (l *StdLogger) With(args ...any) Logger {
	return &StdLogger{logger: l.getLogger().With(args...)}
}

func (l *StdLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.getLogger().DebugContext(ctx, msg, args...)
}

func (l *StdLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.getLogger().InfoContext(ctx, msg, args...)
}

func (l *StdLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.getLogger().WarnContext(ctx, msg, args...)
}

func (l *StdLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.getLogger().ErrorContext(ctx, msg, args...)
}

type requestIdCtxKey struct{}

// WithRequestId returns a context carrying the given request id, so that every
// log record emitted with this context is tagged with it.
func WithRequestId(ctx context.Context, requestId string) context.Context {
	return context.WithValue(ctx, requestIdCtxKey{}, requestId)
}

// RequestIdFromContext returns the request id previously stored with
// WithRequestId, or the empty string when there is none.
func RequestIdFromContext(ctx context.Context) string {
	requestId, _ := ctx.Value(requestIdCtxKey{}).(string)
	return requestId
}

// requestTracingHandler is a slog.Handler that copies the request id carried
// by the context onto every log record.
type requestTracingHandler struct {
	base slog.Handler
}

func (h requestTracingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

func (h requestTracingHandler) Handle(ctx context.Context, record slog.Record) error {
	if requestId := RequestIdFromContext(ctx); requestId != "" {
		record.AddAttrs(slog.String("request_id", requestId))
	}
	return h.base.Handle(ctx, record)
}

func (h requestTracingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return requestTracingHandler{base: h.base.WithAttrs(attrs)}
}

func (h requestTracingHandler) WithGroup(name string) slog.Handler {
	return requestTracingHandler{base: h.base.WithGroup(name)}
}

// NewLogHandler wraps a handler so that log records pick up the request id
// stored in the context.
func NewLogHandler(base slog.Handler) slog.Handler {
	return requestTracingHandler{base: base}
}
