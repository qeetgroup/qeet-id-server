package bootstrap

import (
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/branding"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// mailer is the outbound message chain: templating, branding, then the
// suppression check and delivery record, in front of the configured transport.
type mailer struct {
	sender      notifier.Sender
	transport   notifier.Router // the transport, when routed
	routed      bool
	testEnabled bool // a test email can be sent: an email transport is configured
	deliveries  *delivery.Store
}

// newMailer builds the message chain from cfg.
func newMailer(cfg *config.Config, pool *pgxpool.Pool, brandingRepo *branding.Repository, emailTemplateService *email.Service) mailer {
	sender := notifier.New(notifier.Config{
		EmailProvider:       cfg.EmailProvider,
		AWSRegion:           cfg.AWSRegion,
		SMTPHost:            cfg.SMTPHost,
		SMTPPort:            cfg.SMTPPort,
		SMTPUsername:        cfg.SMTPUsername,
		SMTPPassword:        cfg.SMTPPassword,
		SMTPFrom:            cfg.SMTPFrom,
		SESConfigurationSet: cfg.SESConfigurationSet,
		TwilioAccountSID:    cfg.TwilioAccountSID,
		TwilioAuthToken:     cfg.TwilioAuthToken,
		TwilioFrom:          cfg.TwilioFrom,
		Dev:                 cfg.IsDev(),
	})
	emailTransport, emailRouter := sender.(notifier.Router)
	emailTestEnabled := emailRouter && emailTransport.Email != nil
	// Every email is checked against the suppression list and recorded, right
	// in front of the transport (after templating and branding).
	deliveryStore := delivery.NewStore(pool)
	emailProvider := "none"
	if emailRouter {
		emailProvider = emailTransport.EmailProvider()
	}
	sender = delivery.Tracker{Next: sender, Store: deliveryStore, Provider: emailProvider}
	sender = branding.Sender{Source: brandingRepo, Next: sender}
	sender = email.TemplateSender{Templates: emailTemplateService, Appearance: brandingRepo, Next: sender}
	// PNG fallback for the email logo (served at the app root): shown in clients
	// that strip the inline SVG mark (Gmail/Outlook/Yahoo).
	emailtmpl.SetLogoPNGURL(strings.TrimRight(cfg.AppBaseURL, "/") + "/logo192.png")
	return mailer{sender: sender, transport: emailTransport, routed: emailRouter, testEnabled: emailTestEnabled, deliveries: deliveryStore}
}
