/// <reference types="node" />
import { performance } from "perf_hooks";
import { DB } from "easy-psql";
import { EasyPSQLRBAC } from "../rbac";
import { AllowedEngineApiAccessTypes } from "../types";

// ── Mock DB setup (mirrors the unit-test harness) ────────────────────────────

class MockUserModel {
  schema = "public";
  table = "users";
  columns: Record<string, any> = { id: {}, name: {}, email: {}, user_id: {} };
  relations: Record<string, any> = {};
  constructor(_connection?: any) {}
}

class MockPostModel {
  schema = "public";
  table = "posts";
  columns: Record<string, any> = { id: {}, title: {}, user_id: {} };
  relations: Record<string, any> = {
    user: { from_column: "user_id", to_table: "users", schema: "public", type: "object" },
  };
  constructor(_connection?: any) {}
}

(DB as any).models = {
  public: { users: new MockUserModel(), posts: new MockPostModel() },
};
(DB as any).modelFactory = {
  public: { users: MockUserModel, posts: MockPostModel },
};

// ── Benchmark runner ─────────────────────────────────────────────────────────

interface BenchResult {
  name: string;
  ops: number;
  meanUs: number;
  minUs: number;
  p99Us: number;
  maxUs: number;
  iters: number;
}

function bench(name: string, fn: () => void, durationMs = 2000): BenchResult {
  for (let i = 0; i < 1000; i++) fn();

  const samples: number[] = [];
  const end = Date.now() + durationMs;
  while (Date.now() < end) {
    const t0 = performance.now();
    fn();
    samples.push(performance.now() - t0);
  }

  samples.sort((a, b) => a - b);
  const iters = samples.length;
  const total = samples.reduce((a, b) => a + b, 0);
  const meanUs = (total / iters) * 1_000;
  const minUs = samples[0] * 1_000;
  const p99Us = samples[Math.floor(iters * 0.99)] * 1_000;
  const maxUs = samples[iters - 1] * 1_000;
  const ops = Math.round(1_000_000 / meanUs);

  return { name, ops, meanUs, minUs, p99Us, maxUs, iters };
}

function printGroup(title: string, results: BenchResult[]) {
  const nameW = Math.max(...results.map((r) => r.name.length)) + 2;
  const sep = "─";
  console.log(`\n── ${title} ${sep.repeat(Math.max(1, 64 - title.length))}`);
  const hdr = [
    "Benchmark".padEnd(nameW),
    "ops/sec".padStart(11),
    "mean (µs)".padStart(11),
    "min (µs)".padStart(10),
    "p99 (µs)".padStart(10),
    "iters".padStart(8),
  ].join("  ");
  console.log(hdr);
  console.log(sep.repeat(hdr.length));
  for (const r of results) {
    console.log(
      [
        r.name.padEnd(nameW),
        r.ops.toLocaleString("en").padStart(11),
        r.meanUs.toFixed(3).padStart(11),
        r.minUs.toFixed(3).padStart(10),
        r.p99Us.toFixed(3).padStart(10),
        r.iters.toLocaleString("en").padStart(8),
      ].join("  "),
    );
  }
}

// ── RBAC + role setup ────────────────────────────────────────────────────────

const rbac = new EasyPSQLRBAC();

rbac
  .withRole("viewer", (r) =>
    r
      .findMany("public", "users", { columns: ["id", "name", "email", "user_id"] })
      .findOne("public", "users", { columns: ["id", "name", "email", "user_id"] }),
  )
  .withRole("author", (r) =>
    r
      .findMany("public", "users", {
        columns: ["id", "name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
        preConditions: { where: { name: { _neq: null } } },
      })
      .findOne("public", "users", {
        columns: ["id", "name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
      })
      .createOne("public", "users", {
        columns: ["name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
        preConditions: { input: { user_id: null } },
      })
      .createMany("public", "users", {
        columns: ["name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
      })
      .updateOne("public", "users", {
        columns: ["name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
        preConditions: { input: { user_id: null } },
      })
      .updateMany("public", "users", {
        columns: ["name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
      })
      .deleteOne("public", "users", {
        columns: ["id", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
      })
      .deleteMany("public", "users", {
        columns: ["id", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
      }),
  );

const viewer = { id: "u1", roleId: "viewer" };
const author = { id: "u2", roleId: "author" };
const userModel = new MockUserModel() as any;

// Pre-built inputs for non-mutating benchmarks
const simpleWhere = { id: { _eq: "x" }, name: { _eq: "y" } };
const nestedAndOrWhere = {
  _and: [
    { id: { _eq: "x" } },
    { _or: [{ name: { _eq: "a" } }, { email: { _eq: "b@example.com" } }] },
  ],
};
const smallObj = { a: 1, b: "hello", c: true, d: null };
const deepObj = {
  level1: {
    items: [
      { id: 1, name: "alpha", meta: { active: true, score: 95 } },
      { id: 2, name: "beta", meta: { active: false, score: 40 } },
      { id: 3, name: "gamma", meta: { active: true, score: 77 } },
    ],
    nested: { level2: { level3: { value: 42, tags: ["x", "y", "z"] } } },
  },
};

// ── Run ──────────────────────────────────────────────────────────────────────

console.log(
  `\neasy-psql-rbac benchmark  —  Node ${process.version}  —  ${new Date().toISOString()}`,
);

printGroup("Permission lookup", [
  bench("getRolePermissions", () => {
    rbac.getRolePermissions("viewer");
  }),
  bench("permission traversal (schema → table → op)", () => {
    rbac.getRolePermissions("viewer").schema("public").table("users").findMany();
  }),
  bench("getUserRolePermissionsForEntity", () => {
    rbac.getUserRolePermissionsForEntity({
      schema: "public",
      table: "users",
      user: viewer,
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
    });
  }),
]);

printGroup("Select sanitization", [
  bench("explicit select — no ownership", () => {
    rbac.roleBasedSelectSanitization({
      model: userModel,
      input: { select: { id: true, name: true, email: true }, where: {} },
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      user: viewer,
      entityPermissions: { columns: ["id", "name", "email", "user_id"] },
    });
  }),
  bench("auto-fill select (empty → all columns)", () => {
    rbac.roleBasedSelectSanitization({
      model: userModel,
      input: { select: {}, where: {} },
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      user: viewer,
      entityPermissions: { columns: ["id", "name", "email", "user_id"] },
    });
  }),
  bench("with ownership + preConditions", () => {
    rbac.roleBasedSelectSanitization({
      model: userModel,
      input: { select: { id: true, name: true }, where: {} },
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      user: author,
      entityPermissions: {
        columns: ["id", "name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
        preConditions: { where: { name: { _neq: null } } },
      },
    });
  }),
]);

printGroup("Insert sanitization", [
  bench("single row — no ownership", () => {
    rbac.roleBasedInsertSanitization({
      model: userModel,
      input: { name: "Alice", email: "alice@example.com", user_id: "u1" },
      apiAccessType: AllowedEngineApiAccessTypes.createOne,
      user: viewer,
      entityPermissions: { columns: ["name", "email", "user_id"] },
    });
  }),
  bench("single row — ownership + preConditions", () => {
    rbac.roleBasedInsertSanitization({
      model: userModel,
      input: { name: "Bob", email: "bob@example.com" },
      apiAccessType: AllowedEngineApiAccessTypes.createOne,
      user: author,
      entityPermissions: {
        columns: ["name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
        preConditions: { input: { user_id: null } },
      },
    });
  }),
  bench("batch 10 rows — ownership", () => {
    rbac.roleBasedInsertSanitization({
      model: userModel,
      input: Array.from({ length: 10 }, (_, i) => ({
        name: `User ${i}`,
        email: `u${i}@example.com`,
      })),
      apiAccessType: AllowedEngineApiAccessTypes.createMany,
      user: author,
      entityPermissions: {
        columns: ["name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
      },
    });
  }),
]);

printGroup("Update sanitization", [
  bench("no ownership", () => {
    rbac.roleBasedUpdateSanitization({
      model: userModel,
      input: { update: { name: "Charlie" }, where: { user_id: { _eq: "u1" } } },
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: viewer,
      entityPermissions: { columns: ["id", "name", "email", "user_id"] },
    });
  }),
  bench("ownership + preConditions", () => {
    rbac.roleBasedUpdateSanitization({
      model: userModel,
      input: { update: { name: "Dana", email: "dana@example.com" }, where: { id: { _eq: "u2" } } },
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: author,
      entityPermissions: {
        columns: ["id", "name", "email", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
        preConditions: { input: { user_id: null } },
      },
    });
  }),
]);

printGroup("Delete sanitization", [
  bench("no ownership", () => {
    rbac.roleBasedDeleteSanitization({
      model: userModel,
      input: { where: { id: { _eq: "u1" } } },
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user: viewer,
      entityPermissions: { columns: ["id", "user_id"] },
    });
  }),
  bench("with ownership", () => {
    rbac.roleBasedDeleteSanitization({
      model: userModel,
      input: { where: { id: { _eq: "u2" } } },
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user: author,
      entityPermissions: {
        columns: ["id", "user_id"],
        ownership: { enabled: true, columns: ["user_id"] },
      },
    });
  }),
]);

printGroup("Where sanitization", [
  bench("simple — two columns", () => {
    rbac.roleBasedWhereSanitization({
      model: userModel,
      where: simpleWhere,
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      user: viewer,
      entityPermissions: { columns: ["id", "name", "email", "user_id"] },
    });
  }),
  bench("nested _and / _or (4 conditions)", () => {
    rbac.roleBasedWhereSanitization({
      model: userModel,
      where: nestedAndOrWhere,
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      user: viewer,
      entityPermissions: { columns: ["id", "name", "email", "user_id"] },
    });
  }),
]);

printGroup("mergeWhereWithPreConditions", [
  bench("simple scalar merge", () => {
    rbac.mergeWhereWithPreConditions({
      where: { id: { _eq: "x" } },
      preConditions: { where: { name: { _eq: "y" } } },
    });
  }),
  bench("merge with _and / _or propagation", () => {
    rbac.mergeWhereWithPreConditions({
      where: { id: { _eq: "x" }, _and: [{ name: { _eq: "a" } }] },
      preConditions: {
        where: {
          status: { _eq: "active" },
          _and: [{ email: { _eq: "b" } }, { user_id: { _eq: "c" } }],
          _or: [{ id: { _eq: "d" } }],
        },
      },
    });
  }),
]);

printGroup("Utilities", [
  bench("fastDeepClone — small flat object (4 keys)", () => {
    rbac.fastDeepClone(smallObj);
  }),
  bench("fastDeepClone — deep nested object", () => {
    rbac.fastDeepClone(deepObj);
  }),
  bench("withRole — 9 permissions", () => {
    new EasyPSQLRBAC().withRole("tmp", (r) =>
      r
        .findMany("public", "users", { columns: ["id", "name"] })
        .findOne("public", "users", { columns: ["id", "name"] })
        .createOne("public", "users", { columns: ["name"] })
        .createMany("public", "users", { columns: ["name"] })
        .updateOne("public", "users", { columns: ["name"] })
        .updateMany("public", "users", { columns: ["name"] })
        .deleteOne("public", "users", { columns: ["id"] })
        .deleteMany("public", "users", { columns: ["id"] })
        .aggregate("public", "users", { columns: ["id", "name"] }),
    );
  }),
]);

console.log("\nDone.\n");
