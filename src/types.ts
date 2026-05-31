import type { Model, Relation } from "easy-psql";

export type { Model, Relation };

export enum AllowedEngineApiAccessTypes {
  "findMany" = "findMany",
  "findOne" = "findOne",
  "createOne" = "createOne",
  "createMany" = "createMany",
  "updateOne" = "updateOne",
  "updateMany" = "updateMany",
  "deleteOne" = "deleteOne",
  "deleteMany" = "deleteMany",
  "aggregate" = "aggregate",
}

export type AtLeastOne<T extends object> = {
  [K in keyof T]: Pick<T, K>;
}[keyof T] &
  Partial<T>;

export interface EntityPermissions {
  columns?: string[];
  ownership?: {
    enabled?: boolean;
    columns?: string[];
    columnToUserFieldMapper?: Record<string, string>;
  };
  preConditions?: { where?: Record<string, any>; input?: any };
}

export interface RolePermissions {
  entities?: Record<
    string,
    Record<
      string,
      AtLeastOne<Record<AllowedEngineApiAccessTypes, EntityPermissions>>
    >
  >;
}

export interface Role extends Record<string, any> {
  permissions?: RolePermissions;
}

export interface User extends Record<string, any> {
  role?: Role;
}

export interface RBACOptions {
  userIdentityKey?: string;
}

export interface RoleConfigConstructor extends Role {
  id: any;
}
