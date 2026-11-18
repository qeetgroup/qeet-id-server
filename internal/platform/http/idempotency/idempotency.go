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
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Header is the request header that names a request's idempotency key.
const Header = "Idempotency-Key"

// Retention is how long a key's answer is kept.
const Retention = 24 * time.Hour

// abandonedAfter is how long a claimed key may go unanswered before a retry is
// told the first request's outcome is unknown, as when the instance answering
// it stopped, rather than that it is still in progress. The request may have
// taken effect, so it is never run again under the same key.
const abandonedAfter = time.Minute

// purpose is the encryption context of a stored answer.
const purpose = "idempotency"

// platformScope stands in for the organization in the encryption context of a
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
				httpx.WriteError(w, r, ErrKeyInvalid)
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

	attempt, claimed, err := s.claim(ctx, scope, key, hash)
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
		if err := s.release(done, scope, key, attempt); err != nil {
			slog.Warn("idempotency: release key", "err", err)
		}
		return
	}
	stored, err := s.complete(done, scope, key, attempt, sealAs, rec.status, rec.Header().Get("Content-Type"), rec.body.Bytes())
	switch {
	case err != nil:
		slog.Warn("idempotency: store answer", "err", err)
	case !stored:
		slog.Warn("idempotency: the key's claim is no longer this request's; its answer is not stored")
	}
}

// claim records key as taken by a new attempt of this request and returns the
// attempt. It reports false when the key is already taken, answered or not: an
// unanswered claim is never taken over, as its request may have taken effect.
func (s *Store) claim(ctx context.Context, scope, key, hash string) (uuid.UUID, bool, error) {
	attempt := uuid.New()
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO platform.idempotency_keys (scope, key, request_hash, attempt) VALUES ($1, $2, $3, $4)
		ON CONFLICT (scope, key) DO NOTHING
	`, scope, key, hash, attempt)
	if err != nil {
		return uuid.Nil, false, err
	}
	return attempt, tag.RowsAffected() == 1, nil
}

// complete stores the answer to the request that attempt claimed key for, and
// reports false when the claim is no longer attempt's, so a late attempt never
// overwrites another's answer.
func (s *Store) complete(ctx context.Context, scope, key string, attempt, sealAs uuid.UUID, status int, contentType string, body []byte) (bool, error) {
	enc, nonce, err := s.cipher.Seal(sealAs, purpose, scope+"|"+key, body)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE platform.idempotency_keys
		SET status = $4, content_type = $5, body_enc = $6, body_nonce = $7, completed_at = NOW()
		WHERE scope = $1 AND key = $2 AND attempt = $3 AND completed_at IS NULL
	`, scope, key, attempt, status, contentType, enc, nonce)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// release frees key after a server error, but only while attempt's claim of
// it is unanswered.
func (s *Store) release(ctx context.Context, scope, key string, attempt uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM platform.idempotency_keys
		WHERE scope = $1 AND key = $2 AND attempt = $3 AND completed_at IS NULL
	`, scope, key, attempt)
	return err
}

// replay answers a request whose key was already taken: with the stored answer
// when it is the same request and has been answered.
func (s *Store) replay(w http.ResponseWriter, r *http.Request, scope, key, hash string, sealAs uuid.UUID) {
	var (
		storedHash  string
		status      *int
		contentType *string
		enc, nonce  []byte
		abandoned   bool
	)
	err := s.pool.QueryRow(r.Context(), `
		SELECT request_hash, status, content_type, body_enc, body_nonce,
		       created_at < NOW() - make_interval(secs => $3)
		FROM platform.idempotency_keys WHERE scope = $1 AND key = $2
	`, scope, key, abandonedAfter.Seconds()).Scan(&storedHash, &status, &contentType, &enc, &nonce, &abandoned)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Released by a server error since the claim failed: retry now.
		httpx.WriteError(w, r, ErrKeyInProgress)
		return
	case err != nil:
		httpx.WriteError(w, r, err)
		return
	case storedHash != hash:
		httpx.WriteError(w, r, ErrKeyReused)
		return
	case status == nil && abandoned:
		// The first request stopped unanswered and may have taken effect.
		httpx.WriteError(w, r, ErrOutcomeUnknown)
		return
	case status == nil:
		httpx.WriteError(w, r, ErrKeyInProgress)
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

// scopeOf returns whose key a request's is, its organization and principal, and the
// organization its answer is sealed under.
func scopeOf(r *http.Request) (string, uuid.UUID) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return "anonymous", platformScope
	}
	organization := "-"
	if p.OrganizationID != nil {
		organization = p.OrganizationID.String()
	}
	scope := organization + "|" + p.ActorType + ":" + p.Subject
	return scope, SealedAs(scope)
}

// SealedAs returns the organization the answer stored for scope is sealed under: the
// caller's organization, or a fixed stand-in for a caller with none.
func SealedAs(scope string) uuid.UUID {
	organization, _, _ := strings.Cut(scope, "|")
	if id, err := uuid.Parse(organization); err == nil {
		return id
	}
	return platformScope
}

// Purge deletes keys older than Retention and returns how many.
func Purge(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	return postgres.PurgeInBatches(ctx, pool, `DELETE FROM platform.idempotency_keys WHERE ctid = ANY(ARRAY(
		SELECT k.ctid FROM platform.idempotency_keys k WHERE k.created_at < $1 LIMIT $2))`,
		time.Now().Add(-Retention))
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
