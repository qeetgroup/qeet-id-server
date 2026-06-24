# platform/events/publisher

`Publisher` interface and implementations (outbox, Kafka, NATS, in-memory).

The `platform/events/outbox` package implements durable at-least-once publishing using the
transactional outbox pattern. This package provides the unified `Publisher` interface
that hides the delivery mechanism.
