package branding

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

type EmailIdentitySource interface {
	EmailIdentity(context.Context, uuid.UUID) (name, replyTo string, err error)
}

type Sender struct {
	Source EmailIdentitySource
	Next   notifier.Sender
}

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
