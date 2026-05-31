# easy-psql-rbac

Role-based access control layer for [easy-psql](https://www.npmjs.com/package/easy-psql). Sits between your route handlers and the database: given a `user` object carrying role permissions, it sanitizes queries before they reach the model — enforcing allowed columns, where-clause constraints, ownership filters, and pre-conditions — without a dedicated policy engine or a second database round-trip.

## Requirements

- `easy-psql >= 1.0.0` (peer dependency — you install it in your project)

## Installation

```bash
npm install easy-psql-rbac
# peer dependency — install separately if you haven't already
npm install easy-psql
```

## Setup

Register your models with `easy-psql` as you normally would. Because `easy-psql` uses a static module-level registry, `easy-psql-rbac` automatically shares the same registry without any extra wiring.

```ts
import { DB, Model } from "easy-psql";
import { EasyPSQLRBAC } from "easy-psql-rbac";

class UserModel extends Model {
  schema = "public";
  table = "users";
  columns = { id: {}, name: {}, email: {}, user_id: {} };
  relations = {};
}

DB.register(UserModel);

const rbac = new EasyPSQLRBAC({ userIdentityKey: "id" });
```

## Core concept

Every call to `rbac.*Model(...)` does two things:

1. **Gate** — checks that the user's role has a permission entry for the requested schema + table + operation. Throws `ForbiddenError` immediately if not.
2. **Sanitize** — mutates the `query` / `body` in-place to strip anything the role does not allow (columns, where fields, orderBy, groupBy, distinct, nested includes) and injects any pre-conditions or ownership filters. Returns the ready-to-use model instance.

The caller can then invoke the model's query methods directly:

```ts
const model = rbac.findManyModel({ schema, table, user, query });
const rows = await model.find(query);
```

## Permission structure

Permissions live on the `user` object under `role.permissions.entities`:

```ts
const user = {
  id: "u1",
  role: {
    permissions: {
      entities: {
        "<schema>": {
          "<table>": {
            findMany:   { columns: [...], ownership?: {...}, preConditions?: {...} },
            findOne:    { columns: [...] },
            createOne:  { columns: [...] },
            createMany: { columns: [...] },
            updateOne:  { columns: [...] },
            updateMany: { columns: [...] },
            deleteOne:  { columns: [...] },
            deleteMany: { columns: [...] },
            aggregate:  { columns: [...] },
          },
        },
      },
    },
  },
};
```

You only need to declare the operations you want to allow. Any operation with no entry throws `ForbiddenError`.

### Entity permissions

Each operation entry is an `EntityPermissions` object:

| Field           | Type       | Description                                                              |
| --------------- | ---------- | ------------------------------------------------------------------------ |
| `columns`       | `string[]` | Required. The only columns the role may read or write in this operation. |
| `ownership`     | `object`   | Optional. Enforces that rows belong to the requesting user.              |
| `preConditions` | `object`   | Optional. Conditions injected automatically into every query / mutation. |

#### `ownership`

```ts
ownership: {
  enabled: true,
  columns: ["user_id"],   // columns compared against user.id
}
```

- **Read operations** (`findMany`, `findOne`, `aggregate`): appends `{ _and: [{ user_id: { _eq: user.id } }] }` to the where clause.
- **Write operations** (`createOne`, `createMany`): forces `entry.user_id = user.id` on every row.
- **Update / Delete**: appends the same ownership filter to the where clause.

All `columns` listed in `ownership.columns` must also appear in `columns` — otherwise `ForbiddenError` is thrown.

#### `preConditions`

```ts
preConditions: {
  where: { active: true },          // merged into every where clause
  input: { tenant_id: "acme" },     // merged into every insert / update body
}
```

- `where` fields are merged into the query's where clause. `_and` / `_or` arrays are **concatenated** (not overwritten) with any user-supplied conditions.
- `input` fields are injected into insert/update bodies. Any injected key that is not in `columns` is silently removed (it cannot persist a value the role is not allowed to write).

## API

### Constructor

```ts
new EasyPSQLRBAC(options?: { userIdentityKey?: string })
```

`userIdentityKey` defaults to `"id"` — the property on the `user` object used to identify the requester (e.g. for ownership checks).

### Read methods

```ts
rbac.findManyModel ({ schema, table, user, query,   bypass?, connection? }) → Model
rbac.findOneModel  ({ schema, table, user, query,   bypass?, connection? }) → Model
rbac.aggregateModel({ schema, table, user, query,   bypass?, connection? }) → Model
```

`query` is mutated in-place. After the call, pass `query` directly to the model:

```ts
const model = rbac.findManyModel({
  schema: "public",
  table: "users",
  user,
  query,
});
const rows = await model.find(query);
```

### Write methods

```ts
rbac.createOneModel ({ schema, table, user, body,          bypass?, connection? }) → Model
rbac.createManyModel({ schema, table, user, body,          bypass?, connection? }) → Model
rbac.updateOneModel ({ schema, table, user, body, query?,  bypass?, connection? }) → Model
rbac.updateManyModel({ schema, table, user, body, query?,  bypass?, connection? }) → Model
rbac.deleteOneModel ({ schema, table, user, query?,        bypass?, connection? }) → Model
rbac.deleteManyModel({ schema, table, user, query?,        bypass?, connection? }) → Model
```

### `bypass`

Pass `bypass: true` to skip all permission checks and return the raw model. Useful for admin routes or internal background jobs.

```ts
const model = rbac.findManyModel({ schema, table, bypass: true, query: {} });
```

## Errors

| Class            | Status | Thrown when                                                                  |
| ---------------- | ------ | ---------------------------------------------------------------------------- |
| `ForbiddenError` | 403    | No role, no permission entry, disallowed column/relation, ownership mismatch |
| `BadRequest`     | 400    | Malformed `_and` / `_or` values, invalid aggregation config                  |

Both are exported from the package:

```ts
import { ForbiddenError, BadRequest } from "easy-psql-rbac";
```

## Full example

```ts
import { DB } from "easy-psql";
import { EasyPSQLRBAC, ForbiddenError } from "easy-psql-rbac";

// --- Model registration (done once at startup) ---

class PostModel extends DB {
  schema = "public";
  table = "posts";
  columns = { id: {}, title: {}, body: {}, user_id: {}, published: {} };
  relations = {
    author: {
      from_column: "user_id",
      to_table: "users",
      schema: "public",
      type: "object",
    },
  };
}
DB.register(PostModel);

// --- RBAC instance ---

const rbac = new EasyPSQLRBAC();

// --- Permission-aware route handler ---

async function listPosts(req, res) {
  const user = req.user; // carries role.permissions set by your auth middleware

  const query = {
    where: req.body.where ?? {},
    select: req.body.select ?? {},
    orderBy: req.body.orderBy ?? {},
    include: req.body.include ?? {},
  };

  try {
    const model = rbac.findManyModel({
      schema: "public",
      table: "posts",
      user,
      query,
    });
    // query.select, query.where, etc. are already sanitized
    const posts = await model.find(query);
    res.json(posts);
  } catch (err) {
    if (err instanceof ForbiddenError) {
      res.status(403).json({ message: err.message });
    } else {
      res.status(500).json({ message: "Internal error" });
    }
  }
}

// --- Example user with editor role ---

const editorUser = {
  id: "u42",
  role: {
    permissions: {
      entities: {
        public: {
          posts: {
            findMany: {
              columns: ["id", "title", "user_id"],
              preConditions: { where: { published: true } },
            },
            createOne: {
              columns: ["title", "body", "user_id"],
              ownership: { enabled: true, columns: ["user_id"] },
            },
            updateOne: {
              columns: ["title", "body"],
              ownership: { enabled: true, columns: ["user_id"] },
              preConditions: { where: { published: false } },
            },
          },
        },
      },
    },
  },
};
```

With the editor role above:

- `findMany` — only `id`, `title`, `user_id` are ever returned; `published: true` is always appended to the where clause.
- `createOne` — only `title`, `body`, `user_id` can be set; `user_id` is forced to `user.id` regardless of what the client sends.
- `updateOne` — only `title` and `body` can be changed; the update is silently restricted to rows where `user_id = user.id` and `published = false`.

## How the shared registry works

`easy-psql-rbac` does not bundle its own copy of `easy-psql`. It declares it as a `peerDependency`, so both your application code and this library resolve to the **same module instance** in Node's module cache — and therefore the same static `DB.models` / `DB.modelFactory` registry. Models you register at startup are immediately visible inside `easy-psql-rbac` without any extra configuration.

If two different versions of `easy-psql` end up installed (e.g. via a mismatched transitive dependency), they would produce two separate registries and RBAC would not be able to look up your models. Keep your `easy-psql` version within the `>=1.0.0` peer range to avoid this.
