package notifier

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// SESv2Sender sends email through the Amazon SES v2 API, for regions with no SES
// SMTP endpoint (e.g. ap-south-2). Credentials come from the default AWS chain.
// A non-empty configurationSet routes delivery, bounce and complaint events.
type SESv2Sender struct {
	client           sesSendEmailAPI
	from             string
	configurationSet string
}

// sesSendEmailAPI is the slice of the SES client SESv2Sender needs — narrowed
// to an interface so it can be unit-tested with a fake (no AWS calls).
type sesSendEmailAPI interface {
	SendEmail(ctx context.Context, in *sesv2.SendEmailInput, optFns ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

// NewSESv2Sender builds a sender using the default AWS credential chain. region
// may be empty to fall back to AWS_REGION; from is the RFC 5322 From header
// (display name allowed, e.g. `Qeet ID <support@qeet.in>`).
func NewSESv2Sender(ctx context.Context, region, from, configurationSet string) (*SESv2Sender, error) {
	if from == "" {
		return nil, fmt.Errorf("ses: From address is required")
	}
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("ses: load aws config: %w", err)
	}
	return &SESv2Sender{client: sesv2.NewFromConfig(cfg), from: from, configurationSet: configurationSet}, nil
}

func (s *SESv2Sender) Send(ctx context.Context, m Message) error {
	_, err := s.SendID(ctx, m)
	return err
}

// SendID sends m and returns the id SES gave it, which its later delivery,
// bounce and complaint events name.
func (s *SESv2Sender) SendID(ctx context.Context, m Message) (string, error) {
	if m.Channel != "" && m.Channel != "email" {
		return "", fmt.Errorf("ses sender: unsupported channel %q", m.Channel)
	}
	if m.To == "" {
		return "", fmt.Errorf("ses sender: empty recipient")
	}
	body := &types.Body{
		Text: &types.Content{Data: aws.String(m.Body), Charset: aws.String("UTF-8")},
	}
	if m.HTML != "" {
		body.Html = &types.Content{Data: aws.String(m.HTML), Charset: aws.String("UTF-8")}
	}
	var replyTo []string
	if address := replyAddress(m.ReplyTo); address != "" {
		replyTo = []string{address}
	}
	var configurationSet *string
	if s.configurationSet != "" {
		configurationSet = aws.String(s.configurationSet)
	}
	out, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		ConfigurationSetName: configurationSet,
		FromEmailAddress:     aws.String(messageFrom(s.from, m.FromName)),
		ReplyToAddresses:     replyTo,
		Destination:          &types.Destination{ToAddresses: []string{m.To}},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{Data: aws.String(m.Subject), Charset: aws.String("UTF-8")},
				Body:    body,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ses send: %w", err)
	}
	return aws.ToString(out.MessageId), nil
}
