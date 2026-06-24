# api/protobuf/

Reserved for gRPC service definitions (`.proto` files).

Qeet ID is REST-first (see [`../openapi/`](../openapi/)). This directory will hold
`.proto` schemas if/when a gRPC surface is added — pairing with the server-side
scaffolding under [`platform/api/grpc/`](../../platform/api/grpc/).

Planned layout:

```
api/protobuf/
├── qeetid/
│   ├── auth/v1/auth.proto
│   ├── identity/v1/users.proto
│   └── ...
└── buf.yaml          # buf lint + breaking-change config
```

Conventions (when populated):
- Version every package (`qeetid.auth.v1`).
- Lint + breaking-change checks via [buf](https://buf.build).
- Generated Go lands under `platform/api/grpc/gen/`; generated TS under `sdk/js`.
