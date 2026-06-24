# platform/testing

Test helpers shared across platform package tests.

Planned: `NewTestDB`, `NewTestConfig`, `FixedClock`, JWT test key generation.

Integration test helpers (testcontainer setup, HTTP test harness) live in `tests/fixtures/`.
This package is for lightweight unit-test helpers that have no external dependencies.
