package ldap

import (
	"context"
	"crypto/tls"
	"net/url"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// tlsConfig verifies the directory's certificate unless the connection turns
// that off and allowSkipVerify permits it (see SetAllowSkipTLSVerify).
func (c *connFull) tlsConfig(allowSkipVerify bool) *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: c.SkipTLSVerify && allowSkipVerify} // #nosec G402 -- only with SERVICE_ENV=dev; refused elsewhere
	if host := hostOnly(c.ServerURL); host != "" {
		cfg.ServerName = host
	}
	return cfg
}

func hostOnly(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// dial opens a connection, applying LDAPS or StartTLS as configured.
func (c *connFull) dial(ctx context.Context, policy *egress.Policy, allowSkipVerify bool) (*goldap.Conn, error) {
	u, err := policy.ValidateLDAPURL(c.ServerURL)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateHost(ctx, u.Hostname()); err != nil {
		return nil, err
	}
	conn, err := goldap.DialURL(c.ServerURL, goldap.DialWithDialer(policy.NetDialer(dialTimeout)), goldap.DialWithTLSConfig(c.tlsConfig(allowSkipVerify)))
	if err != nil {
		return nil, err
	}
	if c.StartTLS && strings.HasPrefix(strings.ToLower(c.ServerURL), "ldap://") {
		if err := conn.StartTLS(c.tlsConfig(allowSkipVerify)); err != nil {
			conn.Close() // #nosec G104 -- the StartTLS error is returned instead
			return nil, err
		}
	}
	return conn, nil
}

// TestBind dials and binds with the service account — proving the connection
// settings are correct without authenticating any end user.
func (s *Service) TestBind(ctx context.Context, c *connFull) error {
	if err := s.checkTLSVerify(c.SkipTLSVerify); err != nil {
		return err
	}
	conn, err := c.dial(ctx, s.egress, s.allowSkipVerify)
	if err != nil {
		return ErrDialFailed.Wrap(err)
	}
	defer conn.Close()
	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		return ErrServiceBindFailed.Wrap(err)
	}
	return nil
}

// ldapUser is the directory user a bind proved: Profile is what the
// connection's attribute mapping made of its attributes.
type ldapUser struct {
	DN      string
	Email   string
	Name    string
	Profile map[string]any
	Groups  []string // the connection's groups mapping's values, else memberOf's
}

// authenticate binds the service account, finds the user, then verifies the
// password by binding as the user's DN. Returns the resolved directory user.
func (s *Service) authenticate(ctx context.Context, c *connFull, username, password string) (*ldapUser, error) {
	if err := s.checkTLSVerify(c.SkipTLSVerify); err != nil {
		return nil, err
	}
	conn, err := c.dial(ctx, s.egress, s.allowSkipVerify)
	if err != nil {
		return nil, ErrDirectoryUnreachable.Wrap(err)
	}
	defer conn.Close()

	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		return nil, ErrServiceBindFailed.Wrap(err)
	}

	filter := strings.ReplaceAll(c.UserFilter, "%s", goldap.EscapeFilter(username))
	attributes := []string{c.EmailAttribute, c.NameAttribute, groupsAttr}
	if s.mapper != nil {
		mapped, err := s.mapper.SourceAttributes(ctx, c.OrganizationID, c.ID.String())
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, mapped...)
	}
	req := goldap.NewSearchRequest(
		c.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 2, int(dialTimeout.Seconds()), false,
		filter, attributes, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, ErrInvalidCredentials.Wrap(err)
	}
	if len(res.Entries) != 1 {
		// Zero or ambiguous match — don't reveal which.
		return nil, ErrInvalidCredentials
	}
	entry := res.Entries[0]

	// Verify the password by binding as the user. A fresh conn keeps the
	// service-account binding intact and side-steps connection-state quirks.
	userConn, err := c.dial(ctx, s.egress, s.allowSkipVerify)
	if err != nil {
		return nil, ErrDirectoryUnreachable.Wrap(err)
	}
	defer userConn.Close()
	if err := userConn.Bind(entry.DN, password); err != nil {
		return nil, ErrInvalidCredentials.Wrap(err)
	}

	email := strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(c.EmailAttribute)))
	name := entry.GetAttributeValue(c.NameAttribute)
	groups := entry.GetAttributeValues(groupsAttr)
	var profile map[string]any
	if s.mapper != nil {
		source := map[string]any{}
		for _, attribute := range attributes {
			values := entry.GetAttributeValues(attribute)
			if len(values) > 0 {
				source[attribute] = values
			}
		}
		profile, err = s.mapper.MapProfile(ctx, c.OrganizationID, c.ID.String(), source, false)
		if err != nil {
			return nil, err
		}
		if mapped, ok := profile["email"].(string); ok {
			email = strings.ToLower(mapped)
		}
		if mapped, ok := profile["display_name"].(string); ok {
			name = mapped
		}
		if mapped, ok := profile["groups"].([]string); ok {
			groups = mapped
		}
	}
	if email == "" {
		return nil, ErrEmailAttributeMissing
	}
	return &ldapUser{DN: entry.DN, Email: email, Name: name, Profile: profile, Groups: groups}, nil
}
