package branding

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// EmailIdentitySource returns the name and reply-to address a tenant's email
// is sent with.
type EmailIdentitySource interface {
	EmailIdentity(context.Context, uuid.UUID) (name, replyTo string, err error)
}

// Sender is a notifier.Sender that sends a tenant's email from its own name
// and reply-to address.
type Sender struct {
	Source EmailIdentitySource
	Next   notifier.Sender
}

// EmailAppearance returns the name, logo and primary colour of the tenant's
// email.
func (r *Repository) EmailAppearance(ctx context.Context, tenantID uuid.UUID) (name, logo, primary string, err error) {
	brand, err := r.Get(ctx, tenantID)
	if err != nil {
		return "", "", "", err
	}
	if brand.EmailFromName != nil {
		name = *brand.EmailFromName
	}
	if brand.LogoURL != nil {
		logo = *brand.LogoURL
	}
	if brand.PrimaryColor != nil {
		primary = *brand.PrimaryColor
	}
	return name, logo, primary, nil
}

// EmailIdentity returns the name and reply-to address of the tenant's email.
func (r *Repository) EmailIdentity(ctx context.Context, tenantID uuid.UUID) (name, replyTo string, err error) {
	if r.gate != nil {
		allowed, gateErr := r.gate.FeatureAllowed(ctx, tenantID, "custom_branding")
		if gateErr != nil || !allowed {
			return "", "", gateErr
		}
	}
	brand, err := r.Get(ctx, tenantID)
	if err != nil {
		return "", "", err
	}
	if brand.EmailFromName != nil {
		name = *brand.EmailFromName
	}
	replyTo, _ = brand.Settings["email_reply_to"].(string)
	return name, replyTo, nil
}

// Send implements notifier.Sender: an email for a tenant takes its sender
// name and reply-to address, then goes to Next.
func (s Sender) Send(ctx context.Context, message notifier.Message) error {
	if message.Channel == "email" || message.Channel == "" {
		if tenantID, err := uuid.Parse(message.TenantID); err == nil && tenantID != uuid.Nil {
			if name, replyTo, lookupErr := s.Source.EmailIdentity(ctx, tenantID); lookupErr == nil {
				message.FromName = name
				message.ReplyTo = replyTo
			}
		}
	}
	return s.Next.Send(ctx, message)
}
