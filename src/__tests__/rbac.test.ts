import { DB } from "easy-psql";
import { EasyPSQLRBAC } from "../rbac";
import { ForbiddenError } from "../forbidden";
import { BadRequest } from "../badrequest";
import { AllowedEngineApiAccessTypes } from "../types";

// ---------------------------------------------------------------------------
// Mock model classes — plain classes that satisfy the Model duck-type.
// No real DB connection is needed; only schema/table/columns/relations matter.
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
    user: {
      from_column: "user_id",
      to_table: "users",
      schema: "public",
      type: "object",
    },
  };
  constructor(_connection?: any) {}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUser(entityOverrides: Record<string, any> = {}) {
  return {
    id: "user-123",
    role: {
      permissions: {
        entities: {
          public: {
            users: {
              findMany: { columns: ["id", "name", "email", "user_id"] },
              findOne: { columns: ["id", "name", "email", "user_id"] },
              aggregate: { columns: ["id", "name", "email", "user_id"] },
              createOne: { columns: ["name", "email", "user_id"] },
              createMany: { columns: ["name", "email", "user_id"] },
              updateOne: { columns: ["name", "email", "user_id"] },
              updateMany: { columns: ["name", "email", "user_id"] },
              deleteOne: { columns: ["id", "user_id"] },
              deleteMany: { columns: ["id", "user_id"] },
              ...entityOverrides.users,
            },
            posts: {
              findMany: { columns: ["id", "title", "user_id"] },
              ...entityOverrides.posts,
            },
          },
        },
      },
    },
  };
}

function makeUserWithFindMany(columns: string[], extra: Record<string, any> = {}) {
  return makeUser({ users: { findMany: { columns, ...extra } } });
}

// ---------------------------------------------------------------------------
// DB registry setup — simulates what the consumer project does.
// We bypass DB.register() to avoid spinning up a real DB instance.
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
    public: {
      users: MockUserModel,
      posts: MockPostModel,
    },
  };
}

beforeAll(resetRegistry);
afterAll(() => {
  (DB as any).models = origModels;
  (DB as any).modelFactory = origFactory;
});

// ---------------------------------------------------------------------------
// 1. Registry sharing
// ---------------------------------------------------------------------------

describe("module registry sharing", () => {
  it("DB.models set in consumer code is immediately visible to EasyPSQLRBAC", () => {
    // Simulate consumer registering a new model at runtime
    const sentinel = new MockUserModel();
    sentinel.table = "sentinel";
    (DB as any).models["public"]["sentinel"] = sentinel;

    // DB.getRelatedModel is how rbac.ts resolves relations — uses the same static
    const resolved = DB.getRelatedModel({
      from_column: "id",
      to_table: "sentinel",
      schema: "public",
      type: "object",
    } as any);

    expect(resolved).toBe(sentinel);

    // clean up
    delete (DB as any).models["public"]["sentinel"];
  });

  it("modelFactory registered before instantiation is used when creating models", () => {
    const rbac = new EasyPSQLRBAC({});
    const user = makeUser();
    const model = rbac.findManyModel({
      schema: "public",
      table: "users",
      user,
      query: {},
    });
    expect(model).toBeInstanceOf(MockUserModel);
  });

  it("DB imported in test and in rbac.ts resolve to the same class reference", () => {
    // Because both live in the same Node.js module cache, the constructor is identical
    const { DB: DBfromRequire } = require("easy-psql");
    expect(DBfromRequire).toBe(DB);
    expect(DBfromRequire.models).toBe(DB.models);
  });
});

// ---------------------------------------------------------------------------
// 2. Access control — ForbiddenError gates
// ---------------------------------------------------------------------------

describe("access control gates", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("throws ForbiddenError when user has no role", () => {
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user: {}, query: {} })
    ).toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when entity has no permissions for the operation", () => {
    const user = { role: { permissions: { entities: {} } } };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user, query: {} })
    ).toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when entity permissions have an empty columns array", () => {
    const user = makeUser({ users: { findMany: { columns: [] } } });
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user, query: {} })
    ).toThrow(ForbiddenError);
  });

  it("bypass skips all checks and returns a model directly", () => {
    const model = rbac.findManyModel({
      schema: "public",
      table: "users",
      bypass: true,
      query: {},
    });
    expect(model).toBeInstanceOf(MockUserModel);
  });
});

// ---------------------------------------------------------------------------
// 3. Select sanitization
// ---------------------------------------------------------------------------

describe("select sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("sets all allowed columns when no select is provided", () => {
    const query: any = {};
    rbac.findManyModel({ schema: "public", table: "users", user: makeUser(), query });
    expect(query.select).toEqual({
      id: true,
      name: true,
      email: true,
      user_id: true,
    });
  });

  it("filters an explicit select down to only allowed columns", () => {
    const query: any = { select: { id: true, name: true, secret: true } };
    rbac.findManyModel({ schema: "public", table: "users", user: makeUser(), query });
    expect(query.select).toEqual({ id: true, name: true });
    expect(query.select).not.toHaveProperty("secret");
  });

  it("removes a column from select when its value is false", () => {
    const query: any = { select: { id: false, name: true } };
    rbac.findManyModel({ schema: "public", table: "users", user: makeUser(), query });
    expect(query.select).toEqual({ name: true });
    expect(query.select).not.toHaveProperty("id");
  });

  it("throws ForbiddenError when orderBy references an allowed model column that is NOT in permission list", () => {
    const user = makeUserWithFindMany(["id", "name"]); // email excluded
    const query: any = { orderBy: { email: "asc" } };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user, query })
    ).toThrow(ForbiddenError);
  });

  it("does not throw when orderBy references an allowed column", () => {
    const query: any = { orderBy: { name: "asc" } };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user: makeUser(), query })
    ).not.toThrow();
  });

  it("merges preConditions.where into input.where", () => {
    const user = makeUser({
      users: {
        findMany: {
          columns: ["id", "name", "email", "user_id"],
          preConditions: { where: { name: { _eq: "active" } } },
        },
      },
    });
    const query: any = {};
    rbac.findManyModel({ schema: "public", table: "users", user, query });
    expect(query.where).toMatchObject({ name: { _eq: "active" } });
  });

  it("appends ownership where condition with user.id", () => {
    const user = makeUser({
      users: {
        findMany: {
          columns: ["id", "name", "email", "user_id"],
          ownership: { enabled: true, columns: ["user_id"] },
        },
      },
    });
    const query: any = {};
    rbac.findManyModel({ schema: "public", table: "users", user, query });
    expect(query.where._and).toContainEqual({ user_id: { _eq: "user-123" } });
  });

  it("throws ForbiddenError when groupBy contains a column not in the allowed list", () => {
    const user = makeUserWithFindMany(["id", "name"]);
    const query: any = { groupBy: ["email"] };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user, query })
    ).toThrow(ForbiddenError);
  });

  it("does not throw when groupBy columns are all allowed", () => {
    const user = makeUserWithFindMany(["id", "name", "email", "user_id"]);
    const query: any = { groupBy: ["id", "name"] };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user, query })
    ).not.toThrow();
  });

  it("throws ForbiddenError when distinct contains a column not in the allowed list", () => {
    const user = makeUserWithFindMany(["id", "name"]);
    const query: any = { distinct: ["email"] };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "users", user, query })
    ).toThrow(ForbiddenError);
  });

  it("throws ForbiddenError when include references a relation whose from_column is not selected", () => {
    // posts.findMany allows ['id', 'title'] — no user_id, so the 'user' relation can't be joined
    const user = makeUser({ posts: { findMany: { columns: ["id", "title"] } } });
    const query: any = { include: { user: {} } };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "posts", user, query })
    ).toThrow(ForbiddenError);
  });

  it("does not throw when include relation's from_column is in the allowed select", () => {
    // posts.findMany allows user_id, so the 'user' join is fine
    const user = makeUser();
    const query: any = { include: { user: {} } };
    expect(() =>
      rbac.findManyModel({ schema: "public", table: "posts", user, query })
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 4. Insert sanitization
// ---------------------------------------------------------------------------

describe("insert sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("removes columns that are not in the permission list", () => {
    const body: any = { name: "Alice", email: "alice@test.com", secret: "x", id: 99 };
    // createOne allows: ['name', 'email', 'user_id']
    rbac.createOneModel({ schema: "public", table: "users", user: makeUser(), body });
    expect(body).not.toHaveProperty("secret");
    expect(body).not.toHaveProperty("id");
    expect(body).toHaveProperty("name", "Alice");
    expect(body).toHaveProperty("email", "alice@test.com");
  });

  it("applies preConditions.input values to every row", () => {
    const user = makeUser({
      users: {
        createOne: {
          columns: ["name", "email", "user_id"],
          preConditions: { input: { user_id: "forced" } },
        },
      },
    });
    const body: any = { name: "Alice", email: "a@b.com" };
    rbac.createOneModel({ schema: "public", table: "users", user, body });
    expect(body.user_id).toBe("forced");
  });

  it("sets ownership columns to user.id on insert", () => {
    const user = makeUser({
      users: {
        createOne: {
          columns: ["name", "email", "user_id"],
          ownership: { enabled: true, columns: ["user_id"] },
        },
      },
    });
    const body: any = { name: "Alice", email: "a@b.com" };
    rbac.createOneModel({ schema: "public", table: "users", user, body });
    expect(body.user_id).toBe("user-123");
  });

  it("handles array body for createMany", () => {
    const body: any = [
      { name: "Alice", email: "a@b.com", secret: "x" },
      { name: "Bob", email: "b@b.com", secret: "y" },
    ];
    rbac.createManyModel({ schema: "public", table: "users", user: makeUser(), body });
    for (const entry of body) {
      expect(entry).not.toHaveProperty("secret");
      expect(entry).toHaveProperty("name");
    }
  });

  it("throws ForbiddenError when user has no insert permissions", () => {
    expect(() =>
      rbac.createOneModel({
        schema: "public",
        table: "users",
        user: {},
        body: { name: "Alice" },
      })
    ).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 5. Update sanitization
// ---------------------------------------------------------------------------

describe("update sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("strips columns not in the permission list from input.update", () => {
    const input: any = { update: { name: "Bob", email: "b@b.com", id: 99, secret: "x" }, where: {} };
    const model = (DB as any).models["public"]["users"];
    rbac.roleBasedUpdateSanitization({
      model,
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: makeUser(),
    });
    expect(input.update).toHaveProperty("name");
    expect(input.update).toHaveProperty("email");
    expect(input.update).not.toHaveProperty("id");
    expect(input.update).not.toHaveProperty("secret");
  });

  it("throws ForbiddenError when all update columns are disallowed", () => {
    // updateOne allows ['name', 'email', 'user_id'] — but body only has 'id' and 'secret'
    expect(() =>
      rbac.updateOneModel({
        schema: "public",
        table: "users",
        user: makeUser(),
        body: { id: 99, secret: "x" },
        query: { where: {} },
      })
    ).toThrow(ForbiddenError);
  });

  it("applies preConditions.input to input.update", () => {
    const user = makeUser({
      users: {
        updateOne: {
          columns: ["name", "email", "user_id"],
          preConditions: { input: { user_id: "forced" } },
        },
      },
    });
    const input: any = { update: { name: "Bob" }, where: {} };
    const model = (DB as any).models["public"]["users"];
    rbac.roleBasedUpdateSanitization({
      model,
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user,
    });
    expect(input.update.user_id).toBe("forced");
  });

  it("appends ownership where condition with user.id", () => {
    const user = makeUser({
      users: {
        updateOne: {
          columns: ["name", "email", "user_id"],
          ownership: { enabled: true, columns: ["user_id"] },
        },
      },
    });
    const input: any = { update: { name: "Bob" }, where: {} };
    const model = (DB as any).models["public"]["users"];
    rbac.roleBasedUpdateSanitization({
      model,
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user,
    });
    expect(input.where._and).toContainEqual({ user_id: { _eq: "user-123" } });
  });
});

// ---------------------------------------------------------------------------
// 6. Delete sanitization
// ---------------------------------------------------------------------------

describe("delete sanitization", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("merges preConditions.where into input.where", () => {
    const user = makeUser({
      users: {
        deleteOne: {
          columns: ["id", "user_id"],
          preConditions: { where: { deleted: false } },
        },
      },
    });
    const input: any = { where: { id: { _eq: 1 } } };
    const model = (DB as any).models["public"]["users"];
    rbac.roleBasedDeleteSanitization({
      model,
      input,
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user,
    });
    expect(input.where).toMatchObject({ deleted: false });
  });

  it("appends ownership where condition with user.id", () => {
    const user = makeUser({
      users: {
        deleteOne: {
          columns: ["id", "user_id"],
          ownership: { enabled: true, columns: ["user_id"] },
        },
      },
    });
    const input: any = { where: {} };
    const model = (DB as any).models["public"]["users"];
    rbac.roleBasedDeleteSanitization({
      model,
      input,
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user,
    });
    expect(input.where._and).toContainEqual({ user_id: { _eq: "user-123" } });
  });

  it("throws ForbiddenError when ownership.columns are not in the allowed columns list", () => {
    const user = makeUser({
      users: {
        deleteOne: {
          columns: ["id"],
          ownership: { enabled: true, columns: ["user_id"] }, // user_id not in ['id']
        },
      },
    });
    const input: any = { where: {} };
    const model = (DB as any).models["public"]["users"];
    expect(() =>
      rbac.roleBasedDeleteSanitization({
        model,
        input,
        apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
        user,
      })
    ).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 7. Where sanitization
// ---------------------------------------------------------------------------

describe("where sanitization", () => {
  let rbac: EasyPSQLRBAC;
  const usersModel = () => (DB as any).models["public"]["users"] as MockUserModel;
  const fullPermissions = { columns: ["id", "name", "email", "user_id"] };

  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("passes when where contains a model column that is allowed", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: usersModel() as any,
        where: { name: { _eq: "Alice" } },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: fullPermissions,
      })
    ).not.toThrow();
  });

  it("throws ForbiddenError when where contains a model column that is NOT allowed", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: usersModel() as any,
        where: { email: { _eq: "x@x.com" } },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: { columns: ["id", "name"] }, // email excluded
      })
    ).toThrow(ForbiddenError);
  });

  it("recurses into _and arrays", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: usersModel() as any,
        where: { _and: [{ name: { _eq: "Alice" } }, { id: { _eq: 1 } }] },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: fullPermissions,
      })
    ).not.toThrow();
  });

  it("recurses into _or arrays", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: usersModel() as any,
        where: { _or: [{ name: { _eq: "Alice" } }, { id: { _eq: 2 } }] },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: fullPermissions,
      })
    ).not.toThrow();
  });

  it("throws BadRequest when _and value is not an array", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: usersModel() as any,
        where: { _and: "not-an-array" },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: fullPermissions,
      })
    ).toThrow(BadRequest);
  });

  it("traverses a relation in where and checks related entity permissions", () => {
    const postsModel = (DB as any).models["public"]["posts"] as MockPostModel;
    // 'user' relation: from_column = 'user_id', to_table = 'users'
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: postsModel as any,
        where: { user: { name: { _eq: "Alice" } } },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: { columns: ["id", "title", "user_id"] },
      })
    ).not.toThrow();
  });

  it("throws ForbiddenError when relation where references a column that is not allowed on the related entity", () => {
    // makeUser gives users.findMany only ['id', 'name'] — email is excluded
    const user = makeUser({ users: { findMany: { columns: ["id", "name"] } } });
    const postsModel = (DB as any).models["public"]["posts"] as MockPostModel;
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: postsModel as any,
        where: { user: { email: { _eq: "x@x.com" } } },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user,
        entityPermissions: { columns: ["id", "title", "user_id"] },
      })
    ).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 8. mergeWhereWithPreConditions
// ---------------------------------------------------------------------------

describe("mergeWhereWithPreConditions", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("returns where unchanged when preConditions has no where", () => {
    const result = rbac.mergeWhereWithPreConditions({
      where: { id: 1 },
      preConditions: {},
    });
    expect(result).toMatchObject({ id: 1 });
  });

  it("merges scalar fields from preConditions.where into where", () => {
    const result = rbac.mergeWhereWithPreConditions({
      where: { id: 1 },
      preConditions: { where: { active: true } },
    });
    expect(result).toMatchObject({ id: 1, active: true });
  });

  it("concatenates _and arrays from both where and preConditions.where", () => {
    const result = rbac.mergeWhereWithPreConditions({
      where: { _and: [{ id: 1 }] },
      preConditions: { where: { _and: [{ active: true }] } },
    });
    expect(result._and).toContainEqual({ id: 1 });
    expect(result._and).toContainEqual({ active: true });
  });

  it("concatenates _or arrays from both where and preConditions.where", () => {
    const result = rbac.mergeWhereWithPreConditions({
      where: { _or: [{ id: 1 }] },
      preConditions: { where: { _or: [{ id: 2 }] } },
    });
    expect(result._or).toContainEqual({ id: 1 });
    expect(result._or).toContainEqual({ id: 2 });
  });

  it("handles non-object where by treating it as empty", () => {
    const result = rbac.mergeWhereWithPreConditions({
      where: null,
      preConditions: { where: { active: true } },
    });
    expect(result).toMatchObject({ active: true });
  });

  // ---- Bug proofs ----

  it("does not crash when preConditions.where has _and but where has none yet", () => {
    // Previously: [...where._and, ..._and] → TypeError (undefined is not iterable)
    expect(() =>
      rbac.mergeWhereWithPreConditions({
        where: { id: 1 },
        preConditions: { where: { _and: [{ active: true }] } },
      })
    ).not.toThrow();

    const result = rbac.mergeWhereWithPreConditions({
      where: { id: 1 },
      preConditions: { where: { _and: [{ active: true }] } },
    });
    expect(result._and).toEqual([{ active: true }]);
  });

  it("does not crash when preConditions.where has _or but where has none yet", () => {
    const result = rbac.mergeWhereWithPreConditions({
      where: { id: 1 },
      preConditions: { where: { _or: [{ status: "a" }, { status: "b" }] } },
    });
    expect(result._or).toEqual([{ status: "a" }, { status: "b" }]);
  });

  it("concatenated _and is preserved — not overwritten by the final return", () => {
    // Previously: { ...where, ...preConditions?.where } re-spread preConditions._and,
    // silently overwriting the concatenated array built above.
    const result = rbac.mergeWhereWithPreConditions({
      where: { _and: [{ id: 1 }] },
      preConditions: { where: { _and: [{ active: true }] } },
    });
    // Both entries must survive — overwrite would leave only [{ active: true }]
    expect(result._and).toContainEqual({ id: 1 });
    expect(result._and).toContainEqual({ active: true });
    expect(result._and).toHaveLength(2);
  });

  it("does not bleed preConditions.input or preConditions.where into the result object", () => {
    // Previously: { ...where, ...preConditions } added 'input' and 'where' as literal keys
    const result = rbac.mergeWhereWithPreConditions({
      where: { id: 1 },
      preConditions: { where: { active: true }, input: { user_id: "x" } },
    });
    expect(result).not.toHaveProperty("input");
    expect(result).not.toHaveProperty("where"); // 'where' as a key name, not the clause
    expect(result).toMatchObject({ id: 1, active: true });
  });

  it("preConditions.where passed as full preConditions object (relation traversal shape)", () => {
    // roleBasedWhereSanitization passes relatedEntityPermissions?.preConditions (full object)
    // The function must read .where from it correctly
    const result = rbac.mergeWhereWithPreConditions({
      where: { title: "hello" },
      preConditions: { where: { published: true }, input: { user_id: "forced" } },
    });
    expect(result).toMatchObject({ title: "hello", published: true });
    expect(result).not.toHaveProperty("input");
  });

  it("returns where unchanged when preConditions has no .where property", () => {
    const result = rbac.mergeWhereWithPreConditions({
      where: { id: 99 },
      preConditions: { input: { user_id: "x" } }, // only input, no where
    });
    expect(result).toEqual({ id: 99 });
  });
});

// ---------------------------------------------------------------------------
// 9. mergeWhereWithPreConditions — applied end-to-end through select/update/delete
// ---------------------------------------------------------------------------

describe("preConditions end-to-end", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("select: preConditions.where._and concatenated with existing where._and", () => {
    const user = makeUser({
      users: {
        findMany: {
          columns: ["id", "name", "email", "user_id"],
          preConditions: { where: { _and: [{ active: true }] } },
        },
      },
    });
    const query: any = { where: { _and: [{ id: { _gt: 0 } }] } };
    rbac.findManyModel({ schema: "public", table: "users", user, query });
    expect(query.where._and).toContainEqual({ active: true });
    expect(query.where._and).toContainEqual({ id: { _gt: 0 } });
    expect(query.where._and).toHaveLength(2);
  });

  it("update: preConditions.where._and concatenated with existing where._and", () => {
    const user = makeUser({
      users: {
        updateOne: {
          columns: ["name", "email", "user_id"],
          preConditions: { where: { _and: [{ active: true }] } },
        },
      },
    });
    // where uses 'name' — must be a column in the updateOne permissions
    const input: any = {
      update: { name: "Bob" },
      where: { _and: [{ name: { _eq: "Alice" } }] },
    };
    rbac.roleBasedUpdateSanitization({
      model: (DB as any).models["public"]["users"],
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user,
    });
    expect(input.where._and).toContainEqual({ active: true });
    expect(input.where._and).toContainEqual({ name: { _eq: "Alice" } });
  });

  it("relation where traversal: related entity preConditions.where is merged", () => {
    // posts → user (users table) — users have a preCondition requiring active: true
    const user = makeUser({
      users: {
        findMany: {
          columns: ["id", "name", "email", "user_id"],
          preConditions: { where: { active: true } },
        },
      },
    });
    const postsModel = (DB as any).models["public"]["posts"];
    const entityPermissions = { columns: ["id", "title", "user_id"] };
    const where: any = { user: { name: { _eq: "Alice" } } };

    rbac.roleBasedWhereSanitization({
      model: postsModel as any,
      where,
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      user,
      entityPermissions,
    });

    // The related entity's preConditions.where should be merged into where.user
    expect(where.user).toMatchObject({ active: true });
  });
});

// ---------------------------------------------------------------------------
// 10. Insert sanitization — edge cases
// ---------------------------------------------------------------------------

describe("insert sanitization — edge cases", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("preConditions.input key NOT in allowed columns is injected then stripped", () => {
    const user = makeUser({
      users: {
        createOne: {
          columns: ["name", "email"], // user_id NOT allowed
          preConditions: { input: { user_id: "forced", name: "forced-name" } },
        },
      },
    });
    const body: any = { name: "Alice", email: "a@b.com" };
    rbac.createOneModel({ schema: "public", table: "users", user, body });
    // user_id was injected by preConditions but stripped because not in columns
    expect(body).not.toHaveProperty("user_id");
    // name IS in columns so the forced value survives
    expect(body.name).toBe("forced-name");
  });

  it("onConflict key is preserved and never stripped", () => {
    const body: any = {
      name: "Alice",
      email: "a@b.com",
      onConflict: { target: ["email"], action: "nothing" },
    };
    rbac.createOneModel({ schema: "public", table: "users", user: makeUser(), body });
    expect(body).toHaveProperty("onConflict");
    expect(body.onConflict).toEqual({ target: ["email"], action: "nothing" });
  });

  it("relation key in body recurses into the related model's permissions", () => {
    const user = {
      id: "user-123",
      role: {
        permissions: {
          entities: {
            public: {
              posts: { createOne: { columns: ["title", "user_id"] } },
              users: { createOne: { columns: ["name", "email"] } },
            },
          },
        },
      },
    };
    const body: any = {
      title: "Hello",
      user_id: 1,
      user: { name: "Alice", email: "a@b.com", secret: "forbidden" },
    };
    rbac.createOneModel({ schema: "public", table: "posts", user, body });
    // Nested object is sanitized against the related model's permissions
    expect(body.user).toBeDefined();
    expect(body.user).not.toHaveProperty("secret");
    expect(body.user).toHaveProperty("name", "Alice");
  });

  it("multiple ownership columns are all set to user.id", () => {
    const user = makeUser({
      users: {
        createMany: {
          columns: ["name", "email", "user_id"],
          ownership: { enabled: true, columns: ["user_id"] },
        },
      },
    });
    // Multiple rows — each must get user.id on the ownership column
    const body: any = [
      { name: "Alice", email: "a@b.com" },
      { name: "Bob", email: "b@b.com" },
    ];
    rbac.createManyModel({ schema: "public", table: "users", user, body });
    expect(body[0].user_id).toBe("user-123");
    expect(body[1].user_id).toBe("user-123");
  });

  it("throws ForbiddenError when ownership.columns are not in the allowed columns list", () => {
    const user = makeUser({
      users: {
        createOne: {
          columns: ["name", "email"], // no user_id
          ownership: { enabled: true, columns: ["user_id"] },
        },
      },
    });
    expect(() =>
      rbac.createOneModel({ schema: "public", table: "users", user, body: { name: "Alice" } })
    ).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 11. Select sanitization — edge cases
// ---------------------------------------------------------------------------

describe("select sanitization — edge cases", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("empty select {} is treated the same as no select — falls back to all allowed columns", () => {
    const query: any = { select: {} };
    rbac.findManyModel({ schema: "public", table: "users", user: makeUser(), query });
    expect(query.select).toEqual({
      id: true,
      name: true,
      email: true,
      user_id: true,
    });
  });

  it("a select where every value is false results in an empty select object", () => {
    // All entries are filtered out; RBAC does not throw — the caller gets an empty select
    const query: any = { select: { id: false, name: false, email: false } };
    rbac.findManyModel({ schema: "public", table: "users", user: makeUser(), query });
    expect(query.select).toEqual({});
  });

  it("only columns that are both requested (true) and allowed are kept", () => {
    const user = makeUserWithFindMany(["id", "name"]); // email not allowed
    const query: any = { select: { id: true, name: true, email: true } };
    rbac.findManyModel({ schema: "public", table: "users", user, query });
    expect(query.select).toEqual({ id: true, name: true });
  });
});

// ---------------------------------------------------------------------------
// 12. Update / Delete — where initialisation edge cases
// ---------------------------------------------------------------------------

describe("where initialisation", () => {
  let rbac: EasyPSQLRBAC;
  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("update: initialises input.where to {} when not provided", () => {
    const input: any = { update: { name: "Bob" } }; // no where key at all
    const model = (DB as any).models["public"]["users"];
    rbac.roleBasedUpdateSanitization({
      model,
      input,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      user: makeUser(),
    });
    expect(input.where).toBeDefined();
    expect(typeof input.where).toBe("object");
  });

  it("delete: initialises input.where to {} when not provided", () => {
    const input: any = {}; // no where key
    const model = (DB as any).models["public"]["users"];
    rbac.roleBasedDeleteSanitization({
      model,
      input,
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      user: makeUser(),
    });
    expect(input.where).toBeDefined();
    expect(typeof input.where).toBe("object");
  });
});

// ---------------------------------------------------------------------------
// 13. Where sanitization — edge cases
// ---------------------------------------------------------------------------

describe("where sanitization — edge cases", () => {
  let rbac: EasyPSQLRBAC;
  const model = () => (DB as any).models["public"]["users"] as MockUserModel;
  const permissions = { columns: ["id", "name", "email", "user_id"] };

  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("returns early without throwing when where is null", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: model() as any,
        where: null,
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: permissions,
      })
    ).not.toThrow();
  });

  it("returns early without throwing when where is a number", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: model() as any,
        where: 42,
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: permissions,
      })
    ).not.toThrow();
  });

  it("returns early without throwing when where is a string", () => {
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: model() as any,
        where: "invalid",
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: permissions,
      })
    ).not.toThrow();
  });

  it("processes an array where by checking each element individually", () => {
    // Array where is used internally when _and/_or values are passed recursively
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: model() as any,
        where: [{ name: { _eq: "Alice" } }, { id: { _eq: 1 } }],
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: permissions,
      })
    ).not.toThrow();
  });

  it("throws ForbiddenError for a disallowed column inside a nested _and", () => {
    const restrictedPermissions = { columns: ["id", "name"] }; // no email
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: model() as any,
        where: { _and: [{ email: { _eq: "x@x.com" } }] },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: restrictedPermissions,
      })
    ).toThrow(ForbiddenError);
  });

  it("throws ForbiddenError for a disallowed column inside a nested _or", () => {
    const restrictedPermissions = { columns: ["id"] };
    expect(() =>
      rbac.roleBasedWhereSanitization({
        model: model() as any,
        where: { _or: [{ name: { _eq: "Alice" } }] },
        apiAccessType: AllowedEngineApiAccessTypes.findMany,
        user: makeUser(),
        entityPermissions: restrictedPermissions,
      })
    ).toThrow(ForbiddenError);
  });
});

// ---------------------------------------------------------------------------
// 14. Access-type enforcement — each convenience method routes to the right type
// ---------------------------------------------------------------------------

describe("access type enforcement", () => {
  let rbac: EasyPSQLRBAC;

  function userWithOnly(accessType: string, columns = ["id", "name", "email", "user_id"]) {
    return {
      id: "user-123",
      role: {
        permissions: {
          entities: {
            public: {
              users: { [accessType]: { columns } },
            },
          },
        },
      },
    } as any;
  }

  beforeEach(() => {
    rbac = new EasyPSQLRBAC({});
  });

  it("findOneModel uses findOne — not findMany", () => {
    const user = userWithOnly("findOne");
    expect(() => rbac.findOneModel({ schema: "public", table: "users", user, query: {} })).not.toThrow();
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user, query: {} })).toThrow(ForbiddenError);
  });

  it("aggregateModel uses aggregate — not findMany", () => {
    const user = userWithOnly("aggregate");
    expect(() => rbac.aggregateModel({ schema: "public", table: "users", user, query: {} })).not.toThrow();
    expect(() => rbac.findManyModel({ schema: "public", table: "users", user, query: {} })).toThrow(ForbiddenError);
  });

  it("createOneModel uses createOne — not createMany", () => {
    const user = userWithOnly("createOne", ["name", "email"]);
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user, body: { name: "A" } })).not.toThrow();
    expect(() => rbac.createManyModel({ schema: "public", table: "users", user, body: [{ name: "A" }] })).toThrow(ForbiddenError);
  });

  it("createManyModel uses createMany — not createOne", () => {
    const user = userWithOnly("createMany", ["name", "email"]);
    expect(() => rbac.createManyModel({ schema: "public", table: "users", user, body: [{ name: "A" }] })).not.toThrow();
    expect(() => rbac.createOneModel({ schema: "public", table: "users", user, body: { name: "A" } })).toThrow(ForbiddenError);
  });

  it("updateOneModel uses updateOne — not updateMany", () => {
    const user = userWithOnly("updateOne", ["name"]);
    expect(() =>
      rbac.updateOneModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })
    ).not.toThrow();
    expect(() =>
      rbac.updateManyModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })
    ).toThrow(ForbiddenError);
  });

  it("updateManyModel uses updateMany — not updateOne", () => {
    const user = userWithOnly("updateMany", ["name"]);
    expect(() =>
      rbac.updateManyModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })
    ).not.toThrow();
    expect(() =>
      rbac.updateOneModel({ schema: "public", table: "users", user, body: { name: "Bob" }, query: { where: {} } })
    ).toThrow(ForbiddenError);
  });

  it("deleteOneModel uses deleteOne — not deleteMany", () => {
    const user = userWithOnly("deleteOne", ["id"]);
    expect(() => rbac.deleteOneModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).not.toThrow();
    expect(() => rbac.deleteManyModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).toThrow(ForbiddenError);
  });

  it("deleteManyModel uses deleteMany — not deleteOne", () => {
    const user = userWithOnly("deleteMany", ["id"]);
    expect(() => rbac.deleteManyModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).not.toThrow();
    expect(() => rbac.deleteOneModel({ schema: "public", table: "users", user, query: { where: { id: { _eq: 1 } } } })).toThrow(ForbiddenError);
  });
});
