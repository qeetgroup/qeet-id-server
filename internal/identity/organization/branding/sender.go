package branding

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// EmailIdentitySource returns the name and reply-to address an organization's email
// is sent with.
type EmailIdentitySource interface {
	EmailIdentity(context.Context, uuid.UUID) (name, replyTo string, err error)
}

// Sender is a notifier.Sender that sends an organization's email from its own name
// and reply-to address.
type Sender struct {
	Source EmailIdentitySource
	Next   notifier.Sender
}

// EmailAppearance returns the name, logo and primary colour of the organization's
// email, all empty (the default look) when its plan lacks custom branding.
func (r *Repository) EmailAppearance(ctx context.Context, organizationID uuid.UUID) (name, logo, primary string, err error) {
	if !r.brandingAllowed(ctx, organizationID) {
		return "", "", "", nil
	}
	brand, err := r.Get(ctx, organizationID)
	if err != nil {
		return "", "", "", err
	}
	if brand.EmailFromName != nil {
		name = *brand.EmailFromName
	}
	if brand.LogoURL != nil {
		logo = r.publicLogo(organizationID, *brand.LogoURL)
	}
	if brand.PrimaryColor != nil {
		primary = *brand.PrimaryColor
	}
	return name, logo, primary, nil
}

// EmailIdentity returns the name and reply-to address of the organization's email.
func (r *Repository) EmailIdentity(ctx context.Context, organizationID uuid.UUID) (name, replyTo string, err error) {
	allowed, gateErr := r.gate.FeatureAllowed(ctx, organizationID, "custom_branding")
	if gateErr != nil || !allowed {
		return "", "", gateErr
	}
	brand, err := r.Get(ctx, organizationID)
	if err != nil {
		return "", "", err
	}
	if brand.EmailFromName != nil {
		name = *brand.EmailFromName
	}
	replyTo, _ = brand.Settings["email_reply_to"].(string)
	return name, replyTo, nil
}

// Send implements notifier.Sender: an email for an organization takes its sender
// name and reply-to address, then goes to Next.
func (s Sender) Send(ctx context.Context, message notifier.Message) error {
	if message.Channel == "email" || message.Channel == "" {
		if organizationID, err := uuid.Parse(message.OrganizationID); err == nil && organizationID != uuid.Nil {
			if name, replyTo, lookupErr := s.Source.EmailIdentity(ctx, organizationID); lookupErr == nil {
				message.FromName = name
				message.ReplyTo = replyTo
			}
		}
	}
	return s.Next.Send(ctx, message)
}
