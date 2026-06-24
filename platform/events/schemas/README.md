# platform/events/schemas

Canonical event schema definitions (Go structs + JSON schemas).

All events published by Qeet ID (user.created, session.started, webhook.delivered, etc.)
should have their schema registered here so producers and consumers share the same type.
