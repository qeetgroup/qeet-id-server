// Package idempotency makes retried requests safe: a request sent again with
// the same Idempotency-Key gets the answer the first one got, instead of the
// action happening twice. Keys are scoped to the caller and kept for a day.
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Header is the request header that names a request's idempotency key.
const Header = "Idempotency-Key"

// Retention is how long a key's answer is kept.
const Retention = 24 * time.Hour

// abandonedAfter is how long a claimed key may go unanswered before a retry
// takes it over, as when the instance answering it stopped.
const abandonedAfter = time.Minute

// purpose is the encryption context of a stored answer.
const purpose = "idempotency"

// platformScope stands in for the tenant in the encryption context of a
// caller with none.
var platformScope = uuid.NewSHA1(uuid.NameSpaceOID, []byte("qeet-id idempotency"))

// Store keeps the answers to requests sent with an Idempotency-Key.
type Store struct {
	pool   *pgxpool.Pool
	cipher *envelope.Cipher
}

// NewStore returns a Store over pool, sealing answers with cipher.
func NewStore(pool *pgxpool.Pool, cipher *envelope.Cipher) *Store {
	return &Store{pool: pool, cipher: cipher}
}

// Middleware applies idempotency keys to routes, "METHOD /pattern" entries
// matched as chi matches them. It runs after authentication: keys are scoped
// to the caller. A request without the header passes through.
func (s *Store) Middleware(routes []string) func(http.Handler) http.Handler {
	listed := chi.NewRouter()
	for _, route := range routes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("idempotency: route without a method: " + route)
		}
		listed.MethodFunc(method, pattern, func(http.ResponseWriter, *http.Request) {})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(Header)
			if key == "" || !listed.Match(chi.NewRouteContext(), r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if !validKey(key) {
				httpx.WriteError(w, r, errs.ErrIdempotencyKeyInvalid)
				return
			}
			s.serve(w, r, next, key)
		})
	}
}

// validKey reports whether key is 1 to 255 printable ASCII characters.
func validKey(key string) bool {
	if len(key) > 255 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return false
		}
	}
	return true
}

func (s *Store) serve(w http.ResponseWriter, r *http.Request, next http.Handler, key string) {
	ctx := r.Context()
	body, err := io.ReadAll(io.LimitReader(r.Body, httpx.MaxJSONBodyBytes+1))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256([]byte(r.Method + "\n" + r.URL.Path + "\n" + string(body)))
	hash := hex.EncodeToString(sum[:])
	scope, sealAs := scopeOf(r)

	claimed, err := s.claim(ctx, scope, key, hash)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !claimed {
		s.replay(w, r, scope, key, hash, sealAs)
		return
	}
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	next.ServeHTTP(rec, r)
	// The answer is stored once the request has finished, whether or not the
	// client is still there to read it.
	done := context.WithoutCancel(ctx)
	if rec.status >= http.StatusInternalServerError {
		// A server error may not have acted: the key is free to try again.
		if _, err := s.pool.Exec(done, `DELETE FROM platform.idempotency_keys WHERE scope = $1 AND key = $2`, scope, key); err != nil {
			slog.Warn("idempotency: release key", "err", err)
		}
		return
	}
	enc, nonce, err := s.cipher.Seal(sealAs, purpose, scope+"|"+key, rec.body.Bytes())
	if err == nil {
		_, err = s.pool.Exec(done, `
			UPDATE platform.idempotency_keys
			SET status = $3, content_type = $4, body_enc = $5, body_nonce = $6, completed_at = NOW()
			WHERE scope = $1 AND key = $2
		`, scope, key, rec.status, rec.Header().Get("Content-Type"), enc, nonce)
	}
	if err != nil {
		slog.Warn("idempotency: store answer", "err", err)
	}
}

// claim records key as taken by this request, or takes over one abandoned
// unanswered. It reports false when the key is someone else's.
func (s *Store) claim(ctx context.Context, scope, key, hash string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO platform.idempotency_keys (scope, key, request_hash) VALUES ($1, $2, $3)
		ON CONFLICT (scope, key) DO UPDATE SET request_hash = EXCLUDED.request_hash, created_at = NOW()
		WHERE idempotency_keys.completed_at IS NULL AND idempotency_keys.created_at < $4
	`, scope, key, hash, time.Now().Add(-abandonedAfter))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// replay answers a request whose key was already taken: with the stored answer
// when it is the same request and has been answered.
func (s *Store) replay(w http.ResponseWriter, r *http.Request, scope, key, hash string, sealAs uuid.UUID) {
	var (
		storedHash  string
		status      *int
		contentType *string
		enc, nonce  []byte
	)
	err := s.pool.QueryRow(r.Context(), `
		SELECT request_hash, status, content_type, body_enc, body_nonce
		FROM platform.idempotency_keys WHERE scope = $1 AND key = $2
	`, scope, key).Scan(&storedHash, &status, &contentType, &enc, &nonce)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Released by a server error since the claim failed: retry now.
		httpx.WriteError(w, r, errs.ErrIdempotencyKeyInProgress)
		return
	case err != nil:
		httpx.WriteError(w, r, err)
		return
	case storedHash != hash:
		httpx.WriteError(w, r, errs.ErrIdempotencyKeyReused)
		return
	case status == nil:
		httpx.WriteError(w, r, errs.ErrIdempotencyKeyInProgress)
		return
	}
	body, err := s.cipher.Open(sealAs, purpose, scope+"|"+key, enc, nonce)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if contentType != nil && *contentType != "" {
		w.Header().Set("Content-Type", *contentType)
	}
	w.Header().Set("Idempotent-Replayed", "true")
	w.WriteHeader(*status)
	_, _ = w.Write(body) // #nosec G705 -- this server's own earlier answer, replayed with its Content-Type
}

// scopeOf returns whose key a request's is, its tenant and principal, and the
// tenant its answer is sealed under.
func scopeOf(r *http.Request) (string, uuid.UUID) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return "anonymous", platformScope
	}
	sealAs, tenant := platformScope, "-"
	if p.TenantID != nil {
		sealAs, tenant = *p.TenantID, p.TenantID.String()
	}
	return tenant + "|" + p.ActorType + ":" + p.Subject, sealAs
}

// Purge deletes keys older than Retention and returns how many.
func Purge(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM platform.idempotency_keys WHERE created_at < $1`, time.Now().Add(-Retention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// recorder copies an answer as it is written.
type recorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *recorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}
