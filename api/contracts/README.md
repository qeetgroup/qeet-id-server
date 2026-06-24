# api/contracts/

Reserved for **consumer-driven contract tests** between the Qeet ID API and its
clients (the JS/Go/Python SDKs, the three frontend apps).

Where the OpenAPI specs in [`../openapi/`](../openapi/) describe the *full* surface,
contracts pin the *subset each consumer actually depends on* — so a backend change
that breaks a real consumer fails fast, independently of full-spec coverage.

Planned layout (Pact-style):

```
api/contracts/
├── consumers/
│   ├── qeetid-admin.json     # @qeetid/admin → API
│   ├── qeetid-login.json     # @qeetid/login → API
│   └── sdk-js.json           # @qeetid/sdk → API
└── README.md
```

Conventions (when populated):
- Each consumer publishes the interactions it relies on.
- A provider-verification step runs the contracts against a running backend
  (alongside `make test-api`), failing CI on a broken expectation.
