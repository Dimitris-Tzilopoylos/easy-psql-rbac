import ValidationService from "easy-validation-service";
import {
  AllowedEngineApiAccessTypes,
  EntityPermissions,
  RoleConfigConstructor,
} from "./types";
import { ForbiddenError } from "./forbidden";

export class RoleConfig {
  options: RoleConfigConstructor;
  constructor(options: RoleConfigConstructor) {
    this.options = options;
    this.preparOptions();
  }

  private preparOptions() {
    if (
      !ValidationService.isObject(this.options.permissions) ||
      !ValidationService.isObject(this.options.permissions?.entities)
    ) {
      this.options.permissions = { entities: {} };
    }
  }

  addPermission(
    schema: string,
    table: string,
    accessType: AllowedEngineApiAccessTypes,
    input: EntityPermissions,
  ) {
    if (!this.options.permissions) {
      this.options.permissions = { entities: {} };
    }
    if (!this.options.permissions.entities) {
      this.options.permissions.entities = {};
    }
    if (!this.options.permissions.entities[schema]) {
      this.options.permissions.entities[schema] = {};
    }
    if (!this.options.permissions.entities[schema][table]) {
      this.options.permissions.entities[schema][table] = {} as any;
    }
    this.options.permissions.entities[schema][table][accessType] = input;
    return this;
  }

  findMany(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.findMany,
      input,
    );
  }

  findOne(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.findOne,
      input,
    );
  }

  createMany(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.createMany,
      input,
    );
  }

  createOne(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.createOne,
      input,
    );
  }

  updateMany(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.updateMany,
      input,
    );
  }

  updateOne(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.updateOne,
      input,
    );
  }

  deleteMany(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.deleteMany,
      input,
    );
  }

  deleteOne(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.deleteOne,
      input,
    );
  }

  aggregate(schema: string, table: string, input: EntityPermissions) {
    return this.addPermission(
      schema,
      table,
      AllowedEngineApiAccessTypes.aggregate,
      input,
    );
  }

  assertPermissionEntities() {
    if (!this.options?.permissions?.entities) {
      throw new ForbiddenError();
    }
  }

  schema(s: string) {
    this.assertPermissionEntities();
    const _schema = this.options.permissions!.entities![s];
    if (!_schema) {
      throw new ForbiddenError();
    }
    return {
      table: (t: string) => {
        if (!(t in _schema)) {
          throw new ForbiddenError();
        }
        const _table = _schema[t];
        return {
          [AllowedEngineApiAccessTypes.findMany]: () => {
            const config = _table[AllowedEngineApiAccessTypes.findMany];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.findOne]: () => {
            const config = _table[AllowedEngineApiAccessTypes.findOne];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.aggregate]: () => {
            const config = _table[AllowedEngineApiAccessTypes.aggregate];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.createMany]: () => {
            const config = _table[AllowedEngineApiAccessTypes.createMany];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.createOne]: () => {
            const config = _table[AllowedEngineApiAccessTypes.createOne];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.updateMany]: () => {
            const config = _table[AllowedEngineApiAccessTypes.updateMany];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.updateOne]: () => {
            const config = _table[AllowedEngineApiAccessTypes.updateOne];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.deleteMany]: () => {
            const config = _table[AllowedEngineApiAccessTypes.deleteMany];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
          [AllowedEngineApiAccessTypes.deleteOne]: () => {
            const config = _table[AllowedEngineApiAccessTypes.deleteOne];
            if (
              !ValidationService.isObject(config) ||
              Object.keys(config || {}).length === 0
            ) {
              throw new ForbiddenError();
            }
            return config!;
          },
        };
      },
    };
  }
}

export const roleFactory = (id: any) =>
  new RoleConfig({ id, permissions: { entities: {} } });

export class RoleRegistry {
  private _registry: Map<string, RoleConfig> = new Map();
  constructor() {}

  upsertRole(role: RoleConfig) {
    this._registry.set(role.options.id, role);
    return this;
  }

  deleteRole(id: any) {
    this._registry.delete(id);
    return this;
  }

  withRole(id: any, callback: (role: RoleConfig) => RoleConfig) {
    const role = roleFactory(id);
    this.upsertRole(callback(role));
    return this;
  }

  findRoleById(id: any) {
    return this._registry.get(id);
  }

  getRolePermissions(roleId: any) {
    const role = this.findRoleById(roleId);
    if (!role) {
      throw new ForbiddenError();
    }
    return role;
  }
}

export const roleRegistryFactory = () => new RoleRegistry();