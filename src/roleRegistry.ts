import ValidationService from "easy-validation-service";
import {
  AllowedEngineApiAccessTypes,
  EntityPermissions,
  RoleConfigConstructor,
} from "./types";

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
    if (!("permissions" in this.options)) {
      this.options.permissions = {};
      if (!("entities" in this.options.permissions)) {
        this.options.permissions.entities = {};
      }
    }
    this.options.permissions!.entities![schema][table][accessType] = input;
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
}

export const roleRegistryFactory = () => new RoleRegistry();
