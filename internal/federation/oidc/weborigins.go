package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// webOriginsTTL is how long the set of every application's web origins is
// kept before it is read again: an origin added or removed takes effect for
// CORS within it.
const webOriginsTTL = time.Minute

// maxWebOrigins bounds the web origins one application lists.
const maxWebOrigins = 50

// OptionalOrigins is a JSON list of web origins that can be left out, null or
// a list: Set reports whether the request named it, and a nil Origins (null)
// means the origins of the application's redirect URIs.
type OptionalOrigins struct {
	Set     bool
	Origins []string
}

// UnmarshalJSON implements json.Unmarshaler.
func (o *OptionalOrigins) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Origins = nil
		return nil
	}
	o.Origins = []string{}
	return json.Unmarshal(b, &o.Origins)
}

// originOf is the web origin of an http(s) URI, or "" for another scheme
// (a native app's redirect, say) or one that doesn't parse.
func originOf(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// checkWebOrigins refuses a list with more than maxWebOrigins entries or an
// entry that isn't a bare origin: https, or http only on a loopback host, with
// no user, path, query or fragment, and never "*". It returns the list in
// lower case, each origin once.
func checkWebOrigins(origins []string) ([]string, error) {
	if len(origins) > maxWebOrigins {
		return nil, errs.ErrOIDCWebOriginInvalid.WithDetail("at most 50 web origins")
	}
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		u, err := url.Parse(strings.TrimSpace(o))
		if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, errs.ErrOIDCWebOriginInvalid.WithDetail(o)
		}
		host := u.Hostname()
		loopback := host == "localhost" || net.ParseIP(host).IsLoopback()
		if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
			return nil, errs.ErrOIDCWebOriginInvalid.WithDetail(o)
		}
		origin := strings.ToLower(u.Scheme + "://" + u.Host)
		if !slices.Contains(out, origin) {
			out = append(out, origin)
		}
	}
	return out, nil
}

// effectiveWebOrigins is the web origins an application allows: the ones it
// set, or with none set (nil) the origins of its redirect URIs.
func effectiveWebOrigins(redirectURIs, set []string) []string {
	if set != nil {
		return set
	}
	out := []string{}
	for _, uri := range redirectURIs {
		if o := originOf(uri); o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// clientWebOrigins fills each client's WebOrigins, read for the whole tenant
// at once.
func (s *Service) clientWebOrigins(ctx context.Context, tenantID uuid.UUID, clients []Client) error {
	rows, err := s.q.ListClientWebOrigins(ctx, tenantID)
	if err != nil {
		return err
	}
	set := make(map[uuid.UUID][]string, len(rows))
	for _, r := range rows {
		set[r.ID] = r.WebOrigins
	}
	for i := range clients {
		clients[i].WebOrigins = effectiveWebOrigins(clients[i].RedirectURIs, set[clients[i].ID])
	}
	return nil
}

// setWebOrigins stores, in tx, the web origins an application sets; nil keeps
// none of its own, so its redirect URIs' origins apply.
func (s *Service) setWebOrigins(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID, origins []string) error {
	if origins != nil {
		var err error
		if origins, err = checkWebOrigins(origins); err != nil {
			return err
		}
	}
	err := s.q.WithTx(tx).SetClientWebOrigins(ctx, dbgen.SetClientWebOriginsParams{ID: id, TenantID: tenantID, WebOrigins: origins})
	s.webOrigins.forget()
	return err
}

// AllowsWebOrigin reports whether some application allows origin to call the
// OAuth endpoints from a browser. The endpoints take no cookie, so CORS lets a
// page read only what its own request, holding its own code or token, gets.
// A set that can't be read allows nothing.
func (s *Service) AllowsWebOrigin(ctx context.Context, origin string) bool {
	set, err := s.webOrigins.get(ctx, s.q)
	if err != nil {
		slog.Warn("oidc: read the applications' web origins", "err", err)
		return false
	}
	_, ok := set[strings.ToLower(origin)]
	return ok
}

// originCache is the set of every application's web origins, read again once
// it is older than webOriginsTTL or forgotten.
type originCache struct {
	mu     sync.Mutex
	set    map[string]struct{}
	readAt time.Time
}

func (c *originCache) get(ctx context.Context, q *dbgen.Queries) (map[string]struct{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set != nil && time.Since(c.readAt) < webOriginsTTL {
		return c.set, nil
	}
	rows, err := q.ListAllWebOrigins(ctx)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, r := range rows {
		for _, o := range effectiveWebOrigins(r.RedirectUris, r.WebOrigins) {
			set[o] = struct{}{}
		}
	}
	c.set, c.readAt = set, time.Now()
	return set, nil
}

// forget makes the next get read the set again.
func (c *originCache) forget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.set = nil
}
