import { BadRequest } from "./badrequest";
import { ForbiddenError } from "./forbidden";
import {
  AllowedEngineApiAccessTypes,
  AtLeastOne,
  EntityPermissions,
  Model,
  RBACOptions,
  Relation,
  User,
} from "./types";
import ValidationService from "easy-validation-service";
import { DB } from "easy-psql";
import { RoleRegistry } from "./roleRegistry";

export class EasyPSQLRBAC extends RoleRegistry {
  options: RBACOptions;
  constructor(options?: RBACOptions) {
    super();
    this.options = options || {};
    if (!this.options.userIdentityKey) {
      this.options.userIdentityKey = "id";
    }
    this.assertUserIdentityKey();
  }

  private assertUserIdentityKey() {
    if (
      typeof this.options.userIdentityKey !== "string" ||
      !this.options.userIdentityKey.trim().length
    ) {
      throw new Error(`Please provide a userIdentityKey in options`);
    }
  }

  private model({
    schema,
    table,
    connection,
  }: {
    schema: string;
    table: string;
    connection?: any;
  }) {
    return new DB.modelFactory[schema][table](connection);
  }

  roleBasedModel({
    table,
    schema,
    connection,
    apiAccessType,
    bypass,
    input,
    user,
  }: {
    table: string;
    schema: string;
    connection?: any;
    apiAccessType: AllowedEngineApiAccessTypes;
    bypass?: boolean;
    input?: any;
    user?: User;
  }) {
    if (bypass) {
      return this.model({ schema, table, connection });
    }
    const role = user?.role;
    if (!role) {
      throw new ForbiddenError("Access to this resource is forbidden");
    }

    const entityPermissions = this.getRolePermissions(user?.roleId)
      .schema(schema)
      .table(table)
      [apiAccessType]();

    if (!entityPermissions) {
      throw new ForbiddenError(
        `${schema}.${table}: operation ${apiAccessType}  is not allowed`,
      );
    }

    const { columns = [] } = entityPermissions || {};

    if (!columns?.length) {
      throw new ForbiddenError(
        `${schema}.${table}: operation ${apiAccessType} is not allowed`,
      );
    }

    const model = this.model({ table, schema, connection });

    switch (apiAccessType) {
      case AllowedEngineApiAccessTypes.findMany:
      case AllowedEngineApiAccessTypes.findOne:
      case AllowedEngineApiAccessTypes.aggregate:
        this.roleBasedSelectSanitization({
          user,
          model,
          input,
          entityPermissions,
          apiAccessType,
        });
        break;
      case AllowedEngineApiAccessTypes.createOne:
      case AllowedEngineApiAccessTypes.createMany:
        this.roleBasedInsertSanitization({
          user,
          model,
          input,
          apiAccessType,
          entityPermissions,
        });
        break;
      case AllowedEngineApiAccessTypes.updateOne:
      case AllowedEngineApiAccessTypes.updateMany:
        this.roleBasedUpdateSanitization({
          user,
          model,
          input,
          apiAccessType,
          entityPermissions,
        });
        break;
      case AllowedEngineApiAccessTypes.deleteOne:
      case AllowedEngineApiAccessTypes.deleteMany:
        this.roleBasedDeleteSanitization({
          user,
          model,
          input,
          apiAccessType,
          entityPermissions,
        });
        break;
      default:
        throw new ForbiddenError(
          `${schema}.${table}: operation ${apiAccessType}  is not allowed`,
        );
    }

    return model;
  }

  getUserRolePermissionsForEntity({
    schema,
    table,
    user,
    apiAccessType,
  }: {
    schema: string;
    table: string;
    user: User;
    apiAccessType: AllowedEngineApiAccessTypes;
  }): EntityPermissions {
    return this.getRolePermissions(user?.roleId)
      .schema(schema)
      .table(table)
      [apiAccessType]();
  }

  roleBasedSelectSanitization({
    model,
    input,
    apiAccessType,
    user,
    entityPermissions,
  }: {
    model: Model;
    input: any;
    apiAccessType: AllowedEngineApiAccessTypes;
    user: User;
    entityPermissions: EntityPermissions;
  }) {
    const role = user?.role;
    if (!role) {
      throw new ForbiddenError("Access to this resource is forbidden");
    }

    if (!entityPermissions) {
      throw new ForbiddenError(
        `${model.schema}.${model.table}: operation ${apiAccessType}  is not allowed`,
      );
    }

    const { columns, ownership, preConditions } = entityPermissions;

    if (!Array.isArray(columns) || !columns.length) {
      throw new ForbiddenError(
        `${model.schema}.${model.table}: operation ${apiAccessType}   is not allowed`,
      );
    }

    if (
      ValidationService.isObject(input.select) &&
      Object.keys(input.select).length > 0
    ) {
      input.select = Object.entries(input.select).reduce(
        (acc: any, [key, value]: any) => {
          if (!value || !columns.some((col) => col === key)) {
            return acc;
          }
          acc[key] = true;
          return acc;
        },
        {},
      );
    } else {
      input.select = (columns || []).reduce((acc: any, col: any) => {
        acc[col] = true;
        return acc;
      }, {});
    }

    //sanitize order by
    if (ValidationService.isObject(input.orderBy)) {
      const iter: any = Object.entries(input.orderBy);
      for (const [key, value] of iter) {
        if (model.columns[key] && !columns.includes(key)) {
          throw new ForbiddenError(`Operation orderBy.${key} is not allowed`);
        } else if (DB.getIsAggregate(key)) {
          const relation =
            model.relations[DB.getRelationNameWithoutAggregate(key)];
          if (
            !relation ||
            !columns.some((col) =>
              this.isColumnInRelationColumns({ relation, column: col }),
            )
          ) {
            throw new ForbiddenError(`operation orderBy.${key} is not allowed`);
          }
          const relatedModel = DB.getRelatedModel(relation);
          if (!relatedModel) {
            throw new ForbiddenError(
              `operation ${apiAccessType} is not allowed`,
            );
          }
          const relatedEntityPermissions = this.getUserRolePermissionsForEntity(
            {
              schema: relatedModel.schema ?? "",
              table: relatedModel.table,
              user: { role },
              apiAccessType,
            },
          );

          if (
            !relatedEntityPermissions ||
            !relatedEntityPermissions?.columns?.length
          ) {
            throw new ForbiddenError(
              `${relatedModel.schema}.${relatedModel.table}: operation ${apiAccessType} is not allowed`,
            );
          }
          for (const [aggregationKey, config] of Object.entries(value) as any) {
            if (aggregationKey === "_count") {
              continue;
            }

            if (!ValidationService.isObject(config)) {
              throw new BadRequest(
                `invalid aggregation at orderBy.${key}.${aggregationKey}`,
              );
            }

            let column;
            if (
              !Object.keys(config).every((col: string) => {
                const exists =
                  relatedEntityPermissions.columns?.includes?.(col);
                if (!exists) {
                  column = col;
                }

                return exists;
              })
            ) {
              throw new ForbiddenError(
                `invalid aggregation at orderBy.${key}.${aggregationKey}.${column}`,
              );
            }
          }
        }
      }
    }
    if (!input.where) {
      input.where = {};
    }
    input.where = this.mergeWhereWithPreConditions({
      where: input.where || {},
      preConditions: preConditions || {},
    });
    // sanitize where
    this.roleBasedWhereSanitization({
      model,
      where: input.where,
      user,
      apiAccessType,
      entityPermissions,
    });

    if (
      ownership?.enabled &&
      Array.isArray(ownership?.columns) &&
      ownership.columns.length
    ) {
      if (!user) {
        throw new ForbiddenError(
          `${model.schema}.${model.table}: operation ${apiAccessType} is not allowed`,
        );
      }
      if (!ownership?.columns.some((x: string) => columns.includes(x))) {
        throw new ForbiddenError(
          `${model.schema}.${model.table}: operation ${apiAccessType} is not allowed`,
        );
      }
      if (!ValidationService.isObject(input.where)) {
        input.where = {};
      }

      input.where = {
        _and: Object.entries(input.where)
          .map(([key, value]: any) => ({
            [key]: value,
          }))
          .concat(
            ownership?.columns.map((col: string) => {
              return { [col]: { _eq: this.toUserOwnershipColumn(user) } };
            }, {}),
          ),
      };
    }

    //sanitize relations
    const include = input.include || {};
    const iter: any = Object.entries(include);
    for (let [alias, relationConfig] of iter) {
      if (
        ValidationService.isBoolean(relationConfig) ||
        ValidationService.isString(relationConfig)
      ) {
        include[alias] = {};
        relationConfig = include[alias];
      }
      if (DB.getIsAggregate(alias)) {
        const relation =
          model.relations[DB.getRelationNameWithoutAggregate(alias)];
        if (
          !relation ||
          (!Array.isArray(relation.from_column) &&
            !input.select[relation.from_column as any]) ||
          (Array.isArray(relation.from_column) &&
            !relation.from_column.some(
              (col: string) => input.select[col as any],
            ))
        ) {
          throw new ForbiddenError(
            `operation ${model.schema}.${model.table}.${alias} is not allowed`,
          );
        }
        const relatedModel = DB.getRelatedModel(relation);
        if (!relatedModel) {
          throw new ForbiddenError(
            `aggregate operation ${apiAccessType} is not allowed`,
          );
        }
        const relatedEntityPermissions = this.getUserRolePermissionsForEntity({
          schema: relatedModel.schema ?? "",
          table: relatedModel.table,
          user,
          apiAccessType,
        });

        if (
          !relatedEntityPermissions ||
          !relatedEntityPermissions?.columns?.length
        ) {
          throw new ForbiddenError(
            `${relatedModel.schema}.${relatedModel.table}: aggregate operation ${apiAccessType} is not allowed`,
          );
        }

        const { where, limit, offset, orderBy, groupBy, distinct, ...rest } =
          relationConfig;
        for (const [aggregationKey, config] of Object.entries(rest) as any) {
          if (aggregationKey === "_count") {
            continue;
          }

          if (!ValidationService.isObject(config)) {
            throw new BadRequest(
              `invalid aggregation at ${relatedModel.schema}.${relatedModel.table}.${alias}.${aggregationKey}`,
            );
          }

          let column;
          if (
            !Object.keys(config).every((col: string) => {
              const exists = relatedEntityPermissions.columns?.includes?.(col);
              if (!exists) {
                column = col;
              }

              return exists;
            })
          ) {
            throw new ForbiddenError(
              `aggregation at ${relatedModel.schema}.${relatedModel.table}.${alias}.${aggregationKey}.${column} is not allowed`,
            );
          }
        }
        continue;
      }
      const relation = model.relations?.[alias];
      // e.g relation is from id -> product_id. If id is excluded from the current model the join will fail, so force it to fail...
      if (
        !relation ||
        (!Array.isArray(relation.from_column) &&
          !input.select[relation.from_column as any]) ||
        (Array.isArray(relation.from_column) &&
          !relation.from_column.some((col: string) => input.select[col as any]))
      ) {
        throw new ForbiddenError(
          `${model.schema}.${model.table}.${alias}: operation ${apiAccessType} is not allowed`,
        );
      }
      const relatedModel = DB.getRelatedModel(relation);
      if (!relatedModel) {
        throw new ForbiddenError(`operation ${apiAccessType} is not allowed`);
      }
      const relatedEntityPermissions = this.getUserRolePermissionsForEntity({
        schema: relatedModel.schema ?? "",
        table: relatedModel.table,
        user,
        apiAccessType,
      });

      if (!relatedEntityPermissions) {
        throw new ForbiddenError(
          `${relatedModel.schema}.${relatedModel.table}: operation ${apiAccessType} is not allowed`,
        );
      }

      this.roleBasedSelectSanitization({
        user,
        model: relatedModel,
        input: relationConfig,
        apiAccessType,
        entityPermissions: relatedEntityPermissions,
      });
    }

    // sanitize group by
    if (Array.isArray(input.groupBy) && input.groupBy.length > 0) {
      let column;
      if (
        !input.groupBy.every((col: string) => {
          const exists = columns.some((x: string) => x === col);
          if (!exists) {
            column = col;
          }
          return exists;
        })
      ) {
        throw new ForbiddenError(
          `${model.schema}.${model.table}.groupBy.${column}: operation ${apiAccessType} is not allowed`,
        );
      }
    }

    // sanitize distinct
    if (Array.isArray(input.distinct) && input.distinct.length > 0) {
      let column;
      if (
        !input.distinct.every((col: string) => {
          const exists = columns.some((x: string) => x === col);
          if (!exists) {
            column = col;
          }
          return exists;
        })
      ) {
        throw new ForbiddenError(
          `${model.schema}.${model.table}.distinct.${column}: operation ${apiAccessType} is not allowed`,
        );
      }
    }
  }

  roleBasedInsertSanitization({
    model,
    input,
    apiAccessType,
    user,
    entityPermissions,
  }: {
    model: Model;
    input: any;
    apiAccessType: AllowedEngineApiAccessTypes;
    user: User;
    entityPermissions: EntityPermissions;
  }) {
    if (!entityPermissions) {
      throw new ForbiddenError();
    }

    const { columns, ownership, preConditions } = entityPermissions;

    if (!Array.isArray(columns) || !columns.length) {
      throw new ForbiddenError();
    }

    const allowedColumnsMap = columns.reduce((acc: any, col: string) => {
      acc[col] = true;
      return acc;
    }, {});

    const iter = Array.isArray(input) ? input : [input];

    for (let i = 0; i < iter.length; i++) {
      Object.assign(iter[i], preConditions?.input);
      let entry = iter[i];
      const entryPropsIter = Object.keys(entry);
      for (const key of entryPropsIter) {
        if (key === "onConflict") {
          continue;
        } else if (model.relations?.[key]) {
          const relatedModel = DB.getRelatedModel(model.relations[key]);
          const relatedModelEntityPermissions =
            this.getUserRolePermissionsForEntity({
              schema: relatedModel.schema,
              table: relatedModel.table,
              user,
              apiAccessType,
            });
          this.roleBasedInsertSanitization({
            model: relatedModel,
            input: entry[key],
            apiAccessType,
            user,
            entityPermissions: relatedModelEntityPermissions,
          });
        } else {
          if (!allowedColumnsMap[key]) {
            delete entry[key];
          }
        }
      }

      if (
        ownership?.enabled &&
        Array.isArray(ownership.columns) &&
        ownership.columns.length
      ) {
        if (!user) {
          throw new ForbiddenError();
        }
        if (!ownership?.columns.some((x: string) => allowedColumnsMap[x])) {
          throw new ForbiddenError();
        }
        for (const col of ownership.columns) {
          entry[col] = this.toUserOwnershipColumn(user);
        }
      }
    }
  }

  roleBasedUpdateSanitization({
    model,
    input,
    apiAccessType,
    user,
    entityPermissions,
  }: {
    model: Model;
    input: any;
    apiAccessType: AllowedEngineApiAccessTypes;
    user: User;
    entityPermissions: EntityPermissions;
  }) {
    if (!entityPermissions) {
      throw new ForbiddenError();
    }

    const { columns, ownership, preConditions } = entityPermissions;

    if (!Array.isArray(columns) || !columns.length) {
      throw new ForbiddenError();
    }

    input.update = { ...input.update, ...preConditions?.input };

    const iter = Object.keys(input.update);
    for (const column of iter) {
      if (!columns.some((x: string) => x === column)) {
        delete input.update[column];
      }
    }

    if (!Object.keys(input.update).length) {
      throw new ForbiddenError();
    }
    if (!input.where) {
      input.where = {};
    }
    input.where = this.mergeWhereWithPreConditions({
      where: input.where || {},
      preConditions: preConditions || {},
    });
    // sanitize where
    this.roleBasedWhereSanitization({
      model,
      where: input.where,
      user,
      apiAccessType,
      entityPermissions,
    });

    if (
      ownership?.enabled &&
      Array.isArray(ownership?.columns) &&
      ownership.columns.length
    ) {
      if (!user) {
        throw new ForbiddenError();
      }
      if (!ownership?.columns.some((x: string) => columns.includes(x))) {
        throw new ForbiddenError();
      }
      if (!ValidationService.isObject(input.where)) {
        input.where = {};
      }

      input.where = {
        _and: Object.entries(input.where)
          .map(([key, value]: any) => ({
            [key]: value,
          }))
          .concat(
            ownership?.columns.map((col: string) => {
              return { [col]: { _eq: this.toUserOwnershipColumn(user) } };
            }, {}),
          ),
      };
    }
  }

  roleBasedWhereSanitization({
    model,
    where,
    apiAccessType,
    user,
    entityPermissions,
  }: {
    model: Model;
    where: any;
    apiAccessType: AllowedEngineApiAccessTypes;
    user: User;
    entityPermissions: EntityPermissions;
  }) {
    if (
      !Array.isArray(entityPermissions?.columns) ||
      !entityPermissions?.columns?.length
    ) {
      throw new ForbiddenError();
    }
    if (!ValidationService.isObject(where) && !Array.isArray(where)) {
      return;
    }
    if (Array.isArray(where)) {
      for (const operation of where) {
        this.roleBasedWhereSanitization({
          model,
          where: operation,
          apiAccessType,
          user,
          entityPermissions,
        });
      }
      return;
    }
    const iter: any = Object.entries(where);
    for (const [key, value] of iter) {
      if (key === "_and" || key === "_or") {
        if (!Array.isArray(value)) {
          throw new BadRequest(`invalid value for operation ${key}`);
        }
        this.roleBasedWhereSanitization({
          model,
          where: value,
          apiAccessType,
          user,
          entityPermissions,
        });
      } else if (model.columns[key]) {
        if (!entityPermissions.columns.some((c: string) => c === key)) {
          throw new ForbiddenError();
        }
      } else if (DB.getIsAggregate(key)) {
        const relationKey = DB.getRelationNameWithoutAggregate(key);
        const relation = model.relations[relationKey];

        if (
          !relation ||
          !entityPermissions.columns.some(
            (col: string) => col === relation.from_column,
          )
        ) {
          throw new ForbiddenError();
        }
        const relatedModel = DB.getRelatedModel(relation);
        if (!relatedModel) {
          throw new ForbiddenError();
        }
        const relatedEntityPermissions = this.getUserRolePermissionsForEntity({
          schema: relatedModel.schema!,
          table: relatedModel.table,
          user,
          apiAccessType,
        });

        if (
          !relatedEntityPermissions ||
          !relatedEntityPermissions?.columns?.length
        ) {
          throw new ForbiddenError();
        }
        const [_, config]: any = Object.entries(value)?.[0] || [null, {}];

        const [aggregationKey, aggregationConfig]: any = Object.entries(
          config,
        )?.[0] || ["", {}];

        if (!aggregationKey) {
          throw new BadRequest();
        }
        if (aggregationKey === "_count") {
          continue;
        } else {
          const aggregationColumns = Object.keys(aggregationConfig);
          if (
            !aggregationColumns.every((aggColumn: string) =>
              relatedEntityPermissions?.columns?.includes?.(aggColumn),
            )
          ) {
            throw new ForbiddenError();
          }
        }
      } else if (model.relations[key]) {
        const relation = model.relations[key];
        if (
          !relation ||
          !entityPermissions.columns.some(
            (col: string) => col === relation.from_column,
          )
        ) {
          throw new ForbiddenError();
        }
        const relatedModel = DB.getRelatedModel(relation);
        if (!relatedModel) {
          throw new ForbiddenError();
        }
        const relatedEntityPermissions = this.getUserRolePermissionsForEntity({
          schema: relatedModel.schema!,
          table: relatedModel.table,
          user,
          apiAccessType,
        });

        if (!relatedEntityPermissions) {
          throw new ForbiddenError();
        }

        where[key] = this.mergeWhereWithPreConditions({
          where: value || {},
          preConditions: relatedEntityPermissions?.preConditions,
        });

        this.roleBasedWhereSanitization({
          user,
          model: relatedModel,
          entityPermissions: relatedEntityPermissions,
          where: where[key],
          apiAccessType,
        });
      }
    }
  }

  roleBasedDeleteSanitization({
    model,
    input,
    apiAccessType,
    user,
    entityPermissions,
  }: {
    model: Model;
    input: any;
    role?: any;
    apiAccessType: AllowedEngineApiAccessTypes;
    user: User;
    entityPermissions: EntityPermissions;
  }) {
    if (!entityPermissions) {
      throw new ForbiddenError();
    }

    const { columns, ownership, preConditions } = entityPermissions;

    if (!Array.isArray(columns) || !columns.length) {
      throw new ForbiddenError();
    }
    if (!input.where) {
      input.where = {};
    }
    input.where = this.mergeWhereWithPreConditions({
      where: input.where || {},
      preConditions: preConditions || {},
    });
    // sanitize where
    this.roleBasedWhereSanitization({
      model,
      where: input.where,
      user,
      apiAccessType,
      entityPermissions,
    });

    if (
      ValidationService.isObject(ownership) &&
      ownership?.enabled &&
      Array.isArray(ownership?.columns) &&
      ownership?.columns.length
    ) {
      if (!user) {
        throw new ForbiddenError();
      }
      if (!ownership.columns.every((x: string) => columns.includes(x))) {
        throw new ForbiddenError();
      }
      if (!ValidationService.isObject(input.where)) {
        input.where = {};
      }

      input.where = {
        _and: Object.entries(input.where)
          .map(([key, value]: any) => ({
            [key]: value,
          }))
          .concat(
            ownership.columns.map((col: string) => {
              return { [col]: { _eq: this.toUserOwnershipColumn(user) } };
            }, {}),
          ),
      };
    }
  }

  isColumnInRelationColumns({
    relation,
    column,
  }: {
    relation: Relation;
    column: string;
  }) {
    if (Array.isArray(relation.from_column)) {
      return relation.from_column.includes(column);
    } else {
      return relation.from_column === column;
    }
  }

  mergeWhereWithPreConditions({
    where,
    preConditions,
  }: {
    where: any;
    preConditions: any;
  }) {
    if (!ValidationService.isObject(where)) {
      where = {};
    }

    const conditionsToMerge = preConditions?.where;

    if (ValidationService.isObject(conditionsToMerge)) {
      const { _and, _or, ...rest } = conditionsToMerge;
      where = { ...where, ...rest };
      if (Array.isArray(_and)) {
        where._and = [...(where._and || []), ..._and];
      }
      if (Array.isArray(_or)) {
        where._or = [...(where._or || []), ..._or];
      }
    }
    return where;
  }

  findManyModel({
    schema,
    table,
    connection,
    bypass,
    query,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    query?: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.findMany,
      bypass,
      input: query,
      user,
    });

    return model;
  }

  findOneModel({
    schema,
    table,
    connection,
    bypass,
    query,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    query?: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.findOne,
      bypass,
      input: query,
      user,
    });
    return model;
  }

  aggregateModel({
    schema,
    table,
    connection,
    bypass,
    query,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    query?: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.aggregate,
      bypass,
      input: query,
      user,
    });
    return model;
  }

  createManyModel({
    schema,
    table,
    connection,
    bypass,
    body,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    body: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.createMany,
      bypass,
      input: body,
      user,
    });
    return model;
  }

  createOneModel({
    schema,
    table,
    connection,
    bypass,
    body,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    body: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.createOne,
      bypass,
      input: body,
      user,
    });
    return model;
  }

  updateManyModel({
    schema,
    table,
    connection,
    bypass,
    body,
    query,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    body: any;
    query?: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.updateMany,
      bypass,
      //might needs only query not
      input: { update: body, where: query?.where },
      user,
    });
    return model;
  }

  updateOneModel({
    schema,
    table,
    connection,
    bypass,
    body,
    query,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    body: any;
    query?: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.updateOne,
      bypass,
      input: { update: body, where: query?.where },
      user,
    });
    return model;
  }

  deleteManyModel({
    schema,
    table,
    connection,
    bypass,
    query,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    query?: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.deleteMany,
      bypass,
      input: { where: query?.where },
      user,
    });
    return model;
  }

  deleteOneModel({
    schema,
    table,
    connection,
    bypass,
    query,
    user,
  }: {
    schema: string;
    table: string;
    connection?: any;
    bypass?: boolean;
    query?: any;
    user?: User;
  }) {
    const model = this.roleBasedModel({
      schema,
      table,
      connection,
      apiAccessType: AllowedEngineApiAccessTypes.deleteOne,
      bypass,
      input: { where: query?.where },
      user,
    });
    return model;
  }

  private toUserOwnershipColumn(user: User) {
    return user?.[this.options.userIdentityKey || "id"];
  }

  allowedApiAccessTypeToWebhookEvent(
    apiAccessType: AllowedEngineApiAccessTypes,
  ) {
    return {
      [AllowedEngineApiAccessTypes.findMany]:
        AllowedEngineApiAccessTypes.findMany,
      [AllowedEngineApiAccessTypes.findOne]:
        AllowedEngineApiAccessTypes.findOne,
      [AllowedEngineApiAccessTypes.aggregate]:
        AllowedEngineApiAccessTypes.aggregate,
      [AllowedEngineApiAccessTypes.createMany]:
        AllowedEngineApiAccessTypes.createMany,
      [AllowedEngineApiAccessTypes.createOne]:
        AllowedEngineApiAccessTypes.createOne,
      [AllowedEngineApiAccessTypes.updateMany]:
        AllowedEngineApiAccessTypes.updateMany,
      [AllowedEngineApiAccessTypes.updateOne]:
        AllowedEngineApiAccessTypes.updateOne,
      [AllowedEngineApiAccessTypes.deleteMany]:
        AllowedEngineApiAccessTypes.deleteMany,
      [AllowedEngineApiAccessTypes.deleteOne]:
        AllowedEngineApiAccessTypes.deleteOne,
    }[apiAccessType];
  }
}
