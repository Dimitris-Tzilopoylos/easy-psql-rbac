import { DB } from "easy-psql";
import { EasyPSQLRBAC } from "../rbac";
import { ForbiddenError } from "../forbidden";
import { BadRequest } from "../badrequest";
import { AllowedEngineApiAccessTypes, EntityPermissions } from "../types";

// ---------------------------------------------------------------------------
// Mock model classes
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// DB registry setup
// ---------------------------------------------------------------------------

const origModels = (DB as any).models;
const origFactory = (DB as any).modelFactory;

function resetRegistry() {
  (DB as any).models = {
    public: {
      users: new MockUserModel(),
      posts: new MockPostModel(),
      users_aggregate: Object.assign(new MockUserModel(), { isAggregate: true }),
      posts_aggregate: Object.assign(new MockPostModel(), { isAggregate: true }),
    },
  };
  (DB as any).modelFactory = {
    public: { users: MockUserModel, posts: MockPostModel },
  };
}

beforeAll(resetRegistry);
afterAll(() => {
  (DB as any).models = origModels;
  (DB as any).modelFactory = origFactory;
});

// ---------------------------------------------------------------------------
// Role / user helpers
// ---------------------------------------------------------------------------

const ROLE = {
  BASE: "base",
} as const;

const BASE_USER = { id: "user-123", roleId: ROLE.BASE };

// Full-permissions role used by most tests
function setupBaseRole(rbac: EasyPSQLRBAC) {
  rbac.withRole(ROLE.BASE, (r) =>
    r
      .findMany("public", "users", { columns: ["id", "name", "email", "user_id"] })
      .findOne("public", "users", { columns: ["id", "name", "email", "user_id"] })
      .aggregate("public", "users", { columns: ["id", "name", "email", "user_id"] })
      .createOne("public", "users", { columns: ["name", "email", "user_id"] })
      .createMany("public", "users", { columns: ["name", "email", "user_id"] })
      .updateOne("public", "users", { columns: ["name", "email", "user_id"] })
      .updateMany("public", "users", { columns: ["name", "email", "user_id"] })
      .deleteOne("public", "users", { columns: ["id", "user_id"] })
      .deleteMany("public", "users", { columns: ["id", "user_id"] })
      .findMany("public", "posts", { columns: ["id", "title", "user_id"] })
      .findOne("public", "posts", { columns: ["id", "title", "user_id"] })
  );
}

// Convenience: entity permissions for the users table at a given access type
const EP = {
  usersFull: { columns: ["id", "name", "email", "user_id"] } as EntityPermissions,
  usersRestricted: { columns: ["id", "name"] } as EntityPermissions,
  usersInsert: { columns: ["name", "email", "user_id"] } as EntityPermissions,
  usersUpdate: { columns: ["name", "email", "user_id"] } as EntityPermissions,
  usersDelete: { columns: ["id", "user_id"] } as EntityPermissions,
  postsFull: { columns: ["id", "title", "user_id"] } as EntityPermissions,
};

// ---------------------------------------------------------------------------
// 1. Module registry sharing
// ---------------------------------------------------------------------------

describe("module registry sharing", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("DB.models set in consumer code is immediately visible to EasyPSQLRBAC", () => {
    const sentinel = new MockUserModel();
    sentinel.table = "sentinel";
    (DB as any).models["public"]["sentinel"] = sentinel;

    const resolved = DB.getRelatedModel({
      from_column: "id", to_table: "sentinel", schema: "public", type: "object",
    } as any);
    expect(resolved).toBe(sentinel);

    delete (DB as any).models["public"]["sentinel"];
  });

  it("modelFactory registered before instantiation is used when creating models", () => {
    const model = rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query: {} });
    expect(model).toBeInstanceOf(MockUserModel);
  });

  it("DB imported in test and in rbac.ts resolve to the same class reference", () => {
    const { DB: DBfromRequire } = require("easy-psql");
    expect(DBfromRequire).toBe(DB);
    expect(DBfromRequire.models).toBe(DB.models);
  });
});

// ---------------------------------------------------------------------------
// 2. Access control gates
// ---------------------------------------------------------------------------

describe("access control gates", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("throws ForbiddenError when user has no roleId", () => {
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: {}, query: {} }))
      .toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when roleId is not registered", () => {
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "unknown" }, query: {} }))
      .toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when role has no permissions for the requested schema", () => {
    rbac.withRole("no-schema", (r) => r); // empty role, no schemas
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "no-schema" }, query: {} }))
      .toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when role has no permissions for the requested table", () => {
    rbac.withRole("no-table", (r) => r.findMany("public", "other", { columns: ["id"] }));
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "no-table" }, query: {} }))
      .toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when entity permissions have an empty columns array", () => {
    rbac.withRole("empty-cols", (r) => r.findMany("public", "users", { columns: [] }));
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "empty-cols" }, query: {} }))
      .toThrow(ForbiddenError);
  });

  it("bypass skips all checks and returns a model directly", () => {
    const model = rbac.findManyModel({ schema: "public", table: "users", bypass: true, query: {} });
    expect(model).toBeInstanceOf(MockUserModel);
  });
});

// ---------------------------------------------------------------------------
// 3. Select sanitization
// ---------------------------------------------------------------------------

describe("select sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("sets all allowed columns when no select is provided", () => {
    const query: any = {};
    rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query });
    expect(query.select).toEqual({ id: true, name: true, email: true, user_id: true });
  });

  it("filters an explicit select down to only allowed columns", () => {
    const query: any = { select: { id: true, name: true, secret: true } };
    rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query });
    expect(query.select).toEqual({ id: true, name: true });
    expect(query.select).not.toHaveProperty("secret");
  });

  it("removes a column from select when its value is false", () => {
    const query: any = { select: { id: false, name: true } };
    rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query });
    expect(query.select).toEqual({ name: true });
  });

  it("throws ForbiddenError when orderBy references an allowed model column not in permission list", () => {
    rbac.withRole("r", (r) => r.findMany("public", "users", { columns: ["id", "name"] }));
    const user = { id: "user-123", roleId: "r" };
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user, query: { orderBy: { email: "asc" } } }))
      .toThrow(ForbiddenError);
  });

  it("does not throw when orderBy references an allowed column", () => {
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query: { orderBy: { name: "asc" } } }))
      .not.toThrow();
  });

  it("merges preConditions.where into input.where", () => {
    rbac.withRole("pc", (r) =>
      r.findMany("public", "users", { columns: ["id", "name", "email", "user_id"], preConditions: { where: { name: { _eq: "active" } } } })
    );
    const query: any = {};
    rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "pc" }, query });
    expect(query.where).toMatchObject({ name: { _eq: "active" } });
  });

  it("appends ownership where condition with user.id", () => {
    rbac.withRole("own", (r) =>
      r.findMany("public", "users", { columns: ["id", "name", "email", "user_id"], ownership: { enabled: true, columns: ["user_id"] } })
    );
    const query: any = {};
    rbac.findManyModel({ schema: "public", table: "users", user: { id: "user-123", roleId: "own" }, query });
    expect(query.where._and).toContainEqual({ user_id: { _eq: "user-123" } });
  });

  it("throws when ONE of multiple select-ownership columns is missing — every not some", () => {
    const query: any = {};
    expect(() =>
      rbac.roleBasedSelectSanitization({
        model: (DB as any).models["public"]["users"],
        input: query,
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: BASE_USER,
        entityPermissions: {
          columns: ["id", "name", "user_id"], // tenant_id absent
          ownership: { enabled: true, columns: ["user_id", "tenant_id"] },
        },
      })
    ).toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when groupBy contains a column not in the allowed list", () => {
    rbac.withRole("r", (r) => r.findMany("public", "users", { columns: ["id", "name"] }));
    const user = { id: "u1", roleId: "r" };
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user, query: { groupBy: ["email"] } }))
      .toThrow(ForbiddenError);
  });

  it("does not throw when groupBy columns are all allowed", () => {
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query: { groupBy: ["id", "name"] } }))
      .not.toThrow();
  });

  it("throws ForbiddenError when distinct contains a column not in the allowed list", () => {
    rbac.withRole("r", (r) => r.findMany("public", "users", { columns: ["id", "name"] }));
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "r" }, query: { distinct: ["email"] } }))
      .toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when include relation's from_column is not in the allowed select", () => {
    // posts.findMany with no user_id → can't join 'user' relation
    rbac.withRole("r", (r) =>
      r
        .findMany("public", "posts", { columns: ["id", "title"] })
        .findMany("public", "users", { columns: ["id", "name"] })
    );
    expect(() => rbac.findManyModel({ schema: "public", table: "posts", user: { id: "u1", roleId: "r" }, query: { include: { user: {} } } }))
      .toThrow(ForbiddenError);
  });

  it("does not throw when include relation's from_column is in the allowed select", () => {
    expect(() => rbac.findManyModel({ schema: "public", table: "posts", user: BASE_USER, query: { include: { user: {} } } }))
      .not.toThrow();
  });

  // ---- Edge cases ----

  it("empty select {} falls back to all allowed columns", () => {
    const query: any = { select: {} };
    rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query });
    expect(query.select).toEqual({ id: true, name: true, email: true, user_id: true });
  });

  it("a select where every value is false results in an empty select object", () => {
    const query: any = { select: { id: false, name: false, email: false } };
    rbac.findManyModel({ schema: "public", table: "users", user: BASE_USER, query });
    expect(query.select).toEqual({});
  });

  it("only columns that are both requested (true) and allowed are kept", () => {
    rbac.withRole("r", (r) => r.findMany("public", "users", { columns: ["id", "name"] }));
    const query: any = { select: { id: true, name: true, email: true } };
    rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "r" }, query });
    expect(query.select).toEqual({ id: true, name: true });
  });
});

// ---------------------------------------------------------------------------
// 4. Insert sanitization
// ---------------------------------------------------------------------------

describe("insert sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("throws ForbiddenError when insert body contains a disallowed column", () => {
    const body: any = { name: "Alice", email: "a@b.com", secret: "x" };
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user: BASE_USER, body }))
      .toThrow(ForbiddenError);
  });

  it("succeeds when insert body contains only allowed columns", () => {
    const body: any = { name: "Alice", email: "a@b.com" };
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user: BASE_USER, body }))
      .not.toThrow();
  });

  it("applies preConditions.input values to every row", () => {
    rbac.withRole("pc", (r) =>
      r.createOne("public", "users", { columns: ["name", "email", "user_id"], preConditions: { input: { user_id: "forced" } } })
    );
    const body: any = { name: "Alice", email: "a@b.com" };
    rbac.createOneModel({ schema: "public", table: "users", user: { id: "u1", roleId: "pc" }, body });
    expect(body.user_id).toBe("forced");
  });

  it("sets ownership columns to user.id on insert", () => {
    rbac.withRole("own", (r) =>
      r.createOne("public", "users", { columns: ["name", "email", "user_id"], ownership: { enabled: true, columns: ["user_id"] } })
    );
    const body: any = { name: "Alice", email: "a@b.com" };
    rbac.createOneModel({ schema: "public", table: "users", user: { id: "user-123", roleId: "own" }, body });
    expect(body.user_id).toBe("user-123");
  });

  it("throws ForbiddenError when any row in createMany contains a disallowed column", () => {
    const body: any = [
      { name: "Alice", email: "a@b.com" },
      { name: "Bob", email: "b@b.com", secret: "y" },
    ];
    expect(() => rbac.createManyModel({ schema: "public", table: "users", user: BASE_USER, body }))
      .toThrow(ForbiddenError);
  });

  it("createMany succeeds when all rows contain only allowed columns", () => {
    const body: any = [
      { name: "Alice", email: "a@b.com" },
      { name: "Bob", email: "b@b.com" },
    ];
    expect(() => rbac.createManyModel({ schema: "public", table: "users", user: BASE_USER, body }))
      .not.toThrow();
  });

  it("throws ForbiddenError when user has no insert permissions", () => {
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user: {}, body: { name: "A" } }))
      .toThrow(ForbiddenError);
  });

  // ---- Edge cases ----

  it("throws ForbiddenError when preConditions.input injects a key not in allowed columns", () => {
    // user_id is injected server-side but not in columns — now throws instead of silently dropping
    rbac.withRole("pc", (r) =>
      r.createOne("public", "users", { columns: ["name", "email"], preConditions: { input: { user_id: "forced" } } })
    );
    const body: any = { name: "Alice", email: "a@b.com" };
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user: { id: "u1", roleId: "pc" }, body }))
      .toThrow(ForbiddenError);
  });

  it("preConditions.input key that IS in allowed columns is applied correctly", () => {
    rbac.withRole("pc", (r) =>
      r.createOne("public", "users", { columns: ["name", "email", "user_id"], preConditions: { input: { user_id: "forced" } } })
    );
    const body: any = { name: "Alice", email: "a@b.com" };
    rbac.createOneModel({ schema: "public", table: "users", user: { id: "u1", roleId: "pc" }, body });
    expect(body.user_id).toBe("forced");
  });

  it("onConflict key is preserved and never stripped", () => {
    const body: any = { name: "Alice", email: "a@b.com", onConflict: { target: ["email"], action: "nothing" } };
    rbac.createOneModel({ schema: "public", table: "users", user: BASE_USER, body });
    expect(body).toHaveProperty("onConflict");
    expect(body.onConflict).toEqual({ target: ["email"], action: "nothing" });
  });

  it("relation key in body recurses and throws when nested body has a disallowed column", () => {
    rbac.withRole("nested", (r) =>
      r
        .createOne("public", "posts", { columns: ["title", "user_id"] })
        .createOne("public", "users", { columns: ["name", "email"] })
    );
    const body: any = { title: "Hello", user_id: 1, user: { name: "Alice", email: "a@b.com", secret: "x" } };
    expect(() => rbac.createOneModel({ schema: "public", table: "posts", user: { id: "u1", roleId: "nested" }, body }))
      .toThrow(ForbiddenError);
  });

  it("relation key in body recurses and succeeds when nested body is clean", () => {
    rbac.withRole("nested", (r) =>
      r
        .createOne("public", "posts", { columns: ["title", "user_id"] })
        .createOne("public", "users", { columns: ["name", "email"] })
    );
    const body: any = { title: "Hello", user_id: 1, user: { name: "Alice", email: "a@b.com" } };
    expect(() => rbac.createOneModel({ schema: "public", table: "posts", user: { id: "u1", roleId: "nested" }, body }))
      .not.toThrow();
  });

  it("multiple ownership columns in createMany — each row gets user.id", () => {
    rbac.withRole("own", (r) =>
      r.createMany("public", "users", { columns: ["name", "email", "user_id"], ownership: { enabled: true, columns: ["user_id"] } })
    );
    const body: any = [{ name: "Alice", email: "a@b.com" }, { name: "Bob", email: "b@b.com" }];
    rbac.createManyModel({ schema: "public", table: "users", user: { id: "user-123", roleId: "own" }, body });
    expect(body[0].user_id).toBe("user-123");
    expect(body[1].user_id).toBe("user-123");
  });

  it("throws ForbiddenError when ownership.columns are not in the allowed columns list", () => {
    rbac.withRole("bad-own", (r) =>
      r.createOne("public", "users", { columns: ["name", "email"], ownership: { enabled: true, columns: ["user_id"] } })
    );
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user: { id: "u1", roleId: "bad-own" }, body: { name: "A" } }))
      .toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 5. Update sanitization
// ---------------------------------------------------------------------------

describe("update sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("throws ForbiddenError when update body contains a disallowed column", () => {
    const input: any = { update: { name: "Bob", secret: "x" }, where: {} };
    expect(() =>
      rbac.roleBasedUpdateSanitization({
        model: (DB as any).models["public"]["users"],
        input,
        apiAccessType: AllowedEngineApiAccessTypes.updateOne,
        user: BASE_USER,
        entityPermissions: EP.usersUpdate,
      })
    ).toThrow(ForbiddenError);
  });

  it("succeeds when update body contains only allowed columns", () => {
    const input: any = { update: { name: "Bob", email: "b@b.com" }, where: {} };
    expect(() =>
      rbac.roleBasedUpdateSanitization({
        model: (DB as any).models["public"]["users"],
        input,
        apiAccessType: AllowedEngineApiAccessTypes.updateOne,
        user: BASE_USER,
        entityPermissions: EP.usersUpdate,
      })
    ).not.toThrow();
  });

  it("throws ForbiddenError when update body contains a disallowed column", () => {
    expect(() =>
      rbac.updateOneModel({ schema: "public", table: "users", user: BASE_USER, body: { id: 99, name: "Bob" }, query: { where: {} } })
    ).toThrow(ForbiddenError);
  });

  it("applies preConditions.input to input.update", () => {
    const input: any = { update: { name: "Bob" }, where: {} };
    rbac.roleBasedUpdateSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: BASE_USER,
      entityPermissions: { columns: ["name", "email", "user_id"], preConditions: { input: { user_id: "forced" } } },
    });
    expect(input.update.user_id).toBe("forced");
  });

  it("appends ownership where condition with user.id", () => {
    const input: any = { update: { name: "Bob" }, where: {} };
    rbac.roleBasedUpdateSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: BASE_USER,
      entityPermissions: { columns: ["name", "email", "user_id"], ownership: { enabled: true, columns: ["user_id"] } },
    });
    expect(input.where._and).toContainEqual({ user_id: { _eq: "user-123" } });
  });

  it("initialises input.where to {} when not provided", () => {
    const input: any = { update: { name: "Bob" } };
    rbac.roleBasedUpdateSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: BASE_USER,
      entityPermissions: EP.usersUpdate,
    });
    expect(input.where).toBeDefined();
    expect(typeof input.where).toBe("object");
  });

  it("throws when ONE of multiple update-ownership columns is missing — every not some", () => {
    const input: any = { update: { name: "Bob" }, where: {} };
    expect(() =>
      rbac.roleBasedUpdateSanitization({
        model: (DB as any).models["public"]["users"],
        input,
        apiAccessType: AllowedEngineApiAccessTypes.updateOne,
        user: BASE_USER,
        entityPermissions: {
          columns: ["name", "email", "user_id"], // tenant_id absent
          ownership: { enabled: true, columns: ["user_id", "tenant_id"] },
        },
      })
    ).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 6. Delete sanitization
// ---------------------------------------------------------------------------

describe("delete sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("merges preConditions.where into input.where", () => {
    const input: any = { where: { id: { _eq: 1 } } };
    rbac.roleBasedDeleteSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user: BASE_USER,
      entityPermissions: { columns: ["id", "user_id"], preConditions: { where: { deleted: false } } },
    });
    expect(input.where).toMatchObject({ deleted: false });
  });

  it("appends ownership where condition with user.id", () => {
    const input: any = { where: {} };
    rbac.roleBasedDeleteSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user: BASE_USER,
      entityPermissions: { columns: ["id", "user_id"], ownership: { enabled: true, columns: ["user_id"] } },
    });
    expect(input.where._and).toContainEqual({ user_id: { _eq: "user-123" } });
  });

  it("throws ForbiddenError when ownership.columns are not in the allowed columns list", () => {
    const input: any = { where: {} };
    expect(() =>
      rbac.roleBasedDeleteSanitization({
        model: (DB as any).models["public"]["users"],
        input,
        apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
        user: BASE_USER,
        entityPermissions: { columns: ["id"], ownership: { enabled: true, columns: ["user_id"] } },
      })
    ).toThrow(ForbiddenError);
  });

  it("throws when ONE of multiple ownership columns is missing — every not some", () => {
    // With 'some', this would pass because user_id IS in allowed columns.
    // With 'every', it throws because tenant_id is NOT in allowed columns.
    const input: any = { where: {} };
    expect(() =>
      rbac.roleBasedDeleteSanitization({
        model: (DB as any).models["public"]["users"],
        input,
        apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
        user: BASE_USER,
        entityPermissions: {
          columns: ["id", "user_id"], // tenant_id is intentionally absent
          ownership: { enabled: true, columns: ["user_id", "tenant_id"] },
        },
      })
    ).toThrow(ForbiddenError);
  });

  it("does not throw when ALL ownership columns are in the allowed list", () => {
    const input: any = { where: {} };
    expect(() =>
      rbac.roleBasedDeleteSanitization({
        model: (DB as any).models["public"]["users"],
        input,
        apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
        user: BASE_USER,
        entityPermissions: {
          columns: ["id", "user_id"],
          ownership: { enabled: true, columns: ["user_id"] },
        },
      })
    ).not.toThrow();
  });

  it("initialises input.where to {} when not provided", () => {
    const input: any = {};
    rbac.roleBasedDeleteSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user: BASE_USER,
      entityPermissions: EP.usersDelete,
    });
    expect(input.where).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// 7. Where sanitization
// ---------------------------------------------------------------------------

describe("where sanitization", () => {
  let rbac: EasyPSQLRBAC;
  const usersModel = () => (DB as any).models["public"]["users"] as MockUserModel;
  const fullPerms = EP.usersFull;

  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("passes when where contains a model column that is allowed", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: { name: { _eq: "Alice" } }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: fullPerms })
    ).not.toThrow();
  });

  it("throws ForbiddenError when where contains a model column not in the allowed list", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: { email: { _eq: "x@x.com" } }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: EP.usersRestricted })
    ).toThrow(ForbiddenError);
  });

  it("recurses into _and arrays", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: { _and: [{ name: { _eq: "A" } }, { id: { _eq: 1 } }] }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: fullPerms })
    ).not.toThrow();
  });

  it("recurses into _or arrays", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: { _or: [{ name: { _eq: "A" } }, { id: { _eq: 2 } }] }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: fullPerms })
    ).not.toThrow();
  });

  it("throws BadRequest when _and value is not an array", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: { _and: "not-an-array" }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: fullPerms })
    ).toThrow(BadRequest);
  });

  it("traverses a relation in where and checks related entity permissions", () => {
    const postsModel = (DB as any).models["public"]["posts"] as MockPostModel;
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: postsModel as any, where: { user: { name: { _eq: "Alice" } } }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: EP.postsFull })
    ).not.toThrow();
  });

  it("throws ForbiddenError when relation where references a disallowed column on the related entity", () => {
    rbac.withRole("r", (r) =>
      r
        .findMany("public", "posts", { columns: ["id", "title", "user_id"] })
        .findMany("public", "users", { columns: ["id", "name"] }) // no email
    );
    const postsModel = (DB as any).models["public"]["posts"] as MockPostModel;
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: postsModel as any, where: { user: { email: { _eq: "x" } } }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: { id: "u1", roleId: "r" }, entityPermissions: EP.postsFull })
    ).toThrow(ForbiddenError);
  });

  // ---- Edge cases ----

  it("returns early without throwing when where is null", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: null, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: fullPerms })
    ).not.toThrow();
  });

  it("returns early without throwing when where is a number", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: 42, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: fullPerms })
    ).not.toThrow();
  });

  it("processes an array where by checking each element individually", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: [{ name: { _eq: "Alice" } }, { id: { _eq: 1 } }], apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: fullPerms })
    ).not.toThrow();
  });

  it("throws ForbiddenError for a disallowed column inside a nested _and", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: { _and: [{ email: { _eq: "x" } }] }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: EP.usersRestricted })
    ).toThrow(ForbiddenError);
  });

  it("throws ForbiddenError for a disallowed column inside a nested _or", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({ model: usersModel() as any, where: { _or: [{ name: { _eq: "Alice" } }] }, apiAccessType: AllowedEngineApiAccessTypes.findMany, user: BASE_USER, entityPermissions: { columns: ["id"] } })
    ).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 8. mergeWhereWithPreConditions
// ---------------------------------------------------------------------------

describe("mergeWhereWithPreConditions", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); });

  it("returns where unchanged when preConditions has no where", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { id: 1 }, preConditions: {} });
    expect(result).toMatchObject({ id: 1 });
  });

  it("merges scalar fields from preConditions.where", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { id: 1 }, preConditions: { where: { active: true } } });
    expect(result).toMatchObject({ id: 1, active: true });
  });

  it("concatenates _and from preConditions.where with existing _and", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { _and: [{ id: 1 }] }, preConditions: { where: { _and: [{ active: true }] } } });
    expect(result._and).toContainEqual({ id: 1 });
    expect(result._and).toContainEqual({ active: true });
    expect(result._and).toHaveLength(2);
  });

  it("concatenates _or from preConditions.where with existing _or", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { _or: [{ id: 1 }] }, preConditions: { where: { _or: [{ id: 2 }] } } });
    expect(result._or).toContainEqual({ id: 1 });
    expect(result._or).toContainEqual({ id: 2 });
  });

  it("handles non-object where by treating it as empty", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: null, preConditions: { where: { active: true } } });
    expect(result).toMatchObject({ active: true });
  });

  it("does not crash when preConditions.where has _and but where has none yet", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { id: 1 }, preConditions: { where: { _and: [{ active: true }] } } });
    expect(result._and).toEqual([{ active: true }]);
  });

  it("does not crash when preConditions.where has _or but where has none yet", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { id: 1 }, preConditions: { where: { _or: [{ status: "a" }] } } });
    expect(result._or).toEqual([{ status: "a" }]);
  });

  it("concatenated _and is not overwritten by the final return", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { _and: [{ id: 1 }] }, preConditions: { where: { _and: [{ active: true }] } } });
    expect(result._and).toHaveLength(2);
  });

  it("does not bleed preConditions.input into the result object", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { id: 1 }, preConditions: { where: { active: true }, input: { user_id: "x" } } });
    expect(result).not.toHaveProperty("input");
    expect(result).toMatchObject({ id: 1, active: true });
  });

  it("returns where unchanged when preConditions has only input (no where)", () => {
    const result = rbac.mergeWhereWithPreConditions({ where: { id: 99 }, preConditions: { input: { user_id: "x" } } });
    expect(result).toEqual({ id: 99 });
  });
});

// ---------------------------------------------------------------------------
// 9. preConditions end-to-end
// ---------------------------------------------------------------------------

describe("preConditions end-to-end", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); setupBaseRole(rbac); });

  it("select: preConditions.where._and concatenated with existing where._and", () => {
    rbac.withRole("pc", (r) =>
      r.findMany("public", "users", { columns: ["id", "name", "email", "user_id"], preConditions: { where: { _and: [{ active: true }] } } })
    );
    const query: any = { where: { _and: [{ id: { _gt: 0 } }] } };
    rbac.findManyModel({ schema: "public", table: "users", user: { id: "u1", roleId: "pc" }, query });
    expect(query.where._and).toContainEqual({ active: true });
    expect(query.where._and).toContainEqual({ id: { _gt: 0 } });
    expect(query.where._and).toHaveLength(2);
  });

  it("update: preConditions.where._and concatenated with existing where._and", () => {
    const input: any = { update: { name: "Bob" }, where: { _and: [{ name: { _eq: "Alice" } }] } };
    rbac.roleBasedUpdateSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: BASE_USER,
      entityPermissions: { columns: ["name", "email", "user_id"], preConditions: { where: { _and: [{ active: true }] } } },
    });
    expect(input.where._and).toContainEqual({ active: true });
    expect(input.where._and).toContainEqual({ name: { _eq: "Alice" } });
  });

  it("relation where traversal: related entity preConditions.where is merged", () => {
    rbac.withRole("pc", (r) =>
      r
        .findMany("public", "posts", { columns: ["id", "title", "user_id"] })
        .findMany("public", "users", { columns: ["id", "name", "email", "user_id"], preConditions: { where: { active: true } } })
    );
    const postsModel = (DB as any).models["public"]["posts"];
    const where: any = { user: { name: { _eq: "Alice" } } };
    rbac.roleBasedWhereSanitization({
      model: postsModel as any,
      where,
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      user: { id: "u1", roleId: "pc" },
      entityPermissions: EP.postsFull,
    });
    expect(where.user).toMatchObject({ active: true });
  });
});

// ---------------------------------------------------------------------------
// 10. Access type enforcement — each convenience method routes to correct type
// ---------------------------------------------------------------------------

describe("access type enforcement", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => { rbac = new EasyPSQLRBAC(); });

  function userWith(accessType: string, columns = ["id", "name", "email", "user_id"]) {
    const roleId = `only-${accessType}`;
    rbac.withRole(roleId, (r) => r.addPermission("public", "users", accessType as any, { columns }));
    return { id: "user-123", roleId };
  }

  it("findOneModel uses findOne — not findMany", () => {
    const user = userWith("findOne");
    expect(() => rbac.findOneModel({ schema: "public", table: "users", user, query: {} })).not.toThrow();
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user, query: {} })).toThrow(ForbiddenError);
  });

  it("aggregateModel uses aggregate — not findMany", () => {
    const user = userWith("aggregate");
    expect(() => rbac.aggregateModel({ schema: "public", table: "users", user, query: {} })).not.toThrow();
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user, query: {} })).toThrow(ForbiddenError);
  });

  it("createOneModel uses createOne — not createMany", () => {
    const user = userWith("createOne", ["name", "email"]);
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user, body: { name: "A" } })).not.toThrow();
    expect(() => rbac.createManyModel({ schema: "public", table: "users", user, body: [{ name: "A" }] })).toThrow(ForbiddenError);
  });

  it("createManyModel uses createMany — not createOne", () => {
    const user = userWith("createMany", ["name", "email"]);
    expect(() => rbac.createManyModel({ schema: "public", table: "users", user, body: [{ name: "A" }] })).not.toThrow();
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user, body: { name: "A" } })).toThrow(ForbiddenError);
  });

  it("updateOneModel uses updateOne — not updateMany", () => {
    const user = userWith("updateOne", ["name"]);
    expect(() => rbac.updateOneModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })).not.toThrow();
    expect(() => rbac.updateManyModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })).toThrow(ForbiddenError);
  });

  it("updateManyModel uses updateMany — not updateOne", () => {
    const user = userWith("updateMany", ["name"]);
    expect(() => rbac.updateManyModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })).not.toThrow();
    expect(() => rbac.updateOneModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })).toThrow(ForbiddenError);
  });

  it("deleteOneModel uses deleteOne — not deleteMany", () => {
    const user = userWith("deleteOne", ["id"]);
    expect(() => rbac.deleteOneModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).not.toThrow();
    expect(() => rbac.deleteManyModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).toThrow(ForbiddenError);
  });

  it("deleteManyModel uses deleteMany — not deleteOne", () => {
    const user = userWith("deleteMany", ["id"]);
    expect(() => rbac.deleteManyModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).not.toThrow();
    expect(() => rbac.deleteOneModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 11. RoleRegistry
// ---------------------------------------------------------------------------

describe("RoleRegistry", () => {
  it("upsertRole / findRoleById roundtrip", () => {
    const rbac = new EasyPSQLRBAC();
    rbac.withRole("editor", (r) => r.findMany("public", "users", { columns: ["id"] }));
    expect(rbac.findRoleById("editor")).toBeDefined();
    expect(rbac.findRoleById("unknown")).toBeUndefined();
  });

  it("deleteRole removes the role", () => {
    const rbac = new EasyPSQLRBAC();
    rbac.withRole("tmp", (r) => r);
    rbac.deleteRole("tmp");
    expect(rbac.findRoleById("tmp")).toBeUndefined();
  });

  it("getRolePermissions throws ForbiddenError for unknown roleId", () => {
    const rbac = new EasyPSQLRBAC();
    expect(() => rbac.getRolePermissions("ghost")).toThrow(ForbiddenError);
  });

  it("addPermission initialises missing schema and table entries", () => {
    const rbac = new EasyPSQLRBAC();
    rbac.withRole("r", (r) =>
      r
        .findMany("public", "users", { columns: ["id"] })
        .findMany("app", "orders", { columns: ["order_id"] })
    );
    const role = rbac.findRoleById("r")!;
    expect(role.options.permissions!.entities!["public"]["users"]["findMany"]).toEqual({ columns: ["id"] });
    expect(role.options.permissions!.entities!["app"]["orders"]["findMany"]).toEqual({ columns: ["order_id"] });
  });
});
