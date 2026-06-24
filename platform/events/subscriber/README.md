# platform/events/subscriber

`Subscriber` interface and fan-out router for consuming internal events.

Planned: in-process event bus for same-process consumers (e.g., audit log → SIEM stream),
and durable subscribers backed by Kafka/NATS for cross-service delivery.
