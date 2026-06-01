# easy-psql-rbac

Role-based access control (RBAC) layer for [easy-psql](https://github.com/Dimitris-Tzilopoylos/easy-psql). Intercepts queries and enforces fine-grained permissions — column filtering, ownership rules, and server-side pre-conditions — based on the authenticated user's role.

## Installation

```bash
npm install easy-psql-rbac
```

`easy-psql` is a peer dependency and must be installed separately:

```bash
npm install easy-psql
```

## Quick Start

```typescript
import { EasyPSQLRBAC } from "easy-psql-rbac";

const rbac = new EasyPSQLRBAC();

// Define roles
rbac.withRole("viewer", (role) =>
  role
    .findMany("public", "posts", { columns: ["id", "title", "body"] })
    .findOne("public", "posts", { columns: ["id", "title", "body"] }),
);

rbac.withRole("author", (role) =>
  role
    .findMany("public", "posts", {
      columns: ["id", "title", "body", "author_id"],
      ownership: { enabled: true, columns: ["author_id"] },
    })
    .createOne("public", "posts", {
      columns: ["title", "body", "author_id"],
      preConditions: { input: { author_id: null } }, // auto-set to user identity
    })
    .updateOne("public", "posts", {
      columns: ["title", "body"],
      ownership: { enabled: true, columns: ["author_id"] },
    })
    .deleteOne("public", "posts", {
      ownership: { enabled: true, columns: ["author_id"] },
    }),
);

// Use with a request
const user = { id: "user-123", role_id: "author" };

const model = rbac.findManyModel({
  schema: "public",
  table: "posts",
  user,
  query: { select: { id: true, title: true }, where: {} },
});
// Executes with ownership filter: WHERE author_id = 'user-123'
```

## Core Concepts

### Roles and Permissions

Permissions are defined per **schema + table + operation**. Each permission entry controls:

- **`columns`** — whitelist of columns the role may read or write
- **`ownership`** — automatically scopes queries to the current user's rows
- **`preConditions`** — server-side conditions injected at query time

### Ownership Filtering

When `ownership.enabled` is `true`, the library automatically appends a `WHERE` condition matching the specified columns to the current user's identity:

```typescript
ownership: {
  enabled: true,
  columns: ["author_id"],                       // column(s) to filter on
  columnToUserFieldMapper: { author_id: "id" }, // which user field to match (default: userIdentityKey)
}
```

For inserts, ownership columns are automatically set to the current user's identity value.

### Pre-conditions

Pre-conditions are server-side rules that cannot be overridden by clients:

```typescript
preConditions: {
  where: { is_published: { _eq: true } },  // appended to every query's WHERE
  input:  { tenant_id: "acme" },           // merged into every INSERT/UPDATE body
}
```

## API Reference

### `new EasyPSQLRBAC(options?)`

| Option            | Type     | Default | Description                                          |
| ----------------- | -------- | ------- | ---------------------------------------------------- |
| `userIdentityKey` | `string` | `"id"`  | Field on the user object used for ownership matching |

```typescript
const rbac = new EasyPSQLRBAC({ userIdentityKey: "userId" });
```

---

### Role Definition

#### `rbac.withRole(id, callback)`

Registers or replaces a role. The callback receives a `RoleConfig` builder and must return it.

```typescript
rbac.withRole("admin", (role) =>
  role
    .findMany("public", "users", { columns: ["id", "email", "name"] })
    .updateOne("public", "users", { columns: ["email", "name"] }),
);
```

#### `rbac.upsertRole(roleConfig)`

Upserts a pre-built `RoleConfig` instance.

#### `rbac.deleteRole(id)`

Removes a role from the registry.

---

### `RoleConfig` Builder Methods

Each method takes `(schema: string, table: string, permissions: EntityPermissions)` and returns the builder for chaining.

| Method                                    | Operation            |
| ----------------------------------------- | -------------------- |
| `.findMany(schema, table, permissions)`   | SELECT multiple rows |
| `.findOne(schema, table, permissions)`    | SELECT single row    |
| `.aggregate(schema, table, permissions)`  | Aggregate queries    |
| `.createOne(schema, table, permissions)`  | INSERT single row    |
| `.createMany(schema, table, permissions)` | INSERT multiple rows |
| `.updateOne(schema, table, permissions)`  | UPDATE single row    |
| `.updateMany(schema, table, permissions)` | UPDATE multiple rows |
| `.deleteOne(schema, table, permissions)`  | DELETE single row    |
| `.deleteMany(schema, table, permissions)` | DELETE multiple rows |

---

### Query Model Methods

Each model method sanitizes the incoming query/body against the role's permissions and returns an object ready to pass to the `easy-psql` engine.

```typescript
rbac.findManyModel({ schema, table, user, query?, connection?, bypass? })
rbac.findOneModel({ schema, table, user, query?, connection?, bypass? })
rbac.aggregateModel({ schema, table, user, query?, connection?, bypass? })
rbac.createOneModel({ schema, table, user, body?, connection?, bypass? })
rbac.createManyModel({ schema, table, user, body?, connection?, bypass? })
rbac.updateOneModel({ schema, table, user, input?, connection?, bypass? })
rbac.updateManyModel({ schema, table, user, input?, connection?, bypass? })
rbac.deleteOneModel({ schema, table, user, query?, connection?, bypass? })
rbac.deleteManyModel({ schema, table, user, query?, connection?, bypass? })
```

| Parameter    | Type      | Description                                              |
| ------------ | --------- | -------------------------------------------------------- |
| `schema`     | `string`  | PostgreSQL schema name                                   |
| `table`      | `string`  | Table name                                               |
| `user`       | `User`    | Authenticated user object with a `role_id` field         |
| `bypass`     | `boolean` | Skip all RBAC checks (use for internal/admin operations) |
| `connection` | any       | Optional database connection override                    |

---

### `EntityPermissions` Shape

```typescript
interface EntityPermissions {
  columns?: string[];

  ownership?: {
    enabled?: boolean;
    columns?: string[];
    columnToUserFieldMapper?: Record<string, string>;
  };

  preConditions?: {
    where?: Record<string, any>;
    input?: Record<string, any>;
  };
}
```

---

### Errors

| Class            | HTTP Status | Thrown When                                                                      |
| ---------------- | ----------- | -------------------------------------------------------------------------------- |
| `ForbiddenError` | 403         | User has no role, role doesn't exist, or role lacks permission for the operation |
| `BadRequest`     | 400         | Query contains columns or conditions the role is not allowed to use              |

```typescript
import { ForbiddenError, BadRequest } from "easy-psql-rbac";

try {
  const model = rbac.findManyModel({ schema: "public", table: "users", user });
} catch (err) {
  if (err instanceof ForbiddenError) {
    // respond 403
  }
  if (err instanceof BadRequest) {
    // respond 400
  }
}
```

---

## Advanced Usage

### Multi-column Ownership

```typescript
rbac.withRole("member", (role) =>
  role.findMany("public", "documents", {
    columns: ["id", "title", "org_id", "owner_id"],
    ownership: {
      enabled: true,
      columns: ["owner_id"],
      columnToUserFieldMapper: { owner_id: "userId" },
    },
  }),
);
```

### Forced Server-side Values on Insert

```typescript
rbac.withRole("tenant-user", (role) =>
  role.createOne("public", "records", {
    columns: ["name", "data", "tenant_id"],
    preConditions: {
      input: { tenant_id: "fixed-tenant-id" }, // client cannot override this
    },
  }),
);
```

### Scoped Read with Pre-condition WHERE

```typescript
rbac.withRole("moderator", (role) =>
  role.findMany("public", "reports", {
    columns: ["id", "content", "status"],
    preConditions: {
      where: { status: { _eq: "pending" } },
    },
  }),
);
```

### Bypass for Internal Operations

```typescript
const model = rbac.deleteOneModel({
  schema: "public",
  table: "sessions",
  user: adminUser,
  bypass: true,
  query: { where: { expired: { _eq: true } } },
});
```

---

## TypeScript

The package ships with full TypeScript declarations. All types are exported from the main entry point:

```typescript
import {
  EasyPSQLRBAC,
  RoleRegistry,
  RoleConfig,
  ForbiddenError,
  BadRequest,
  AllowedEngineApiAccessTypes,
  type EntityPermissions,
  type RolePermissions,
  type User,
} from "easy-psql-rbac";
```

---

## License

ISC
