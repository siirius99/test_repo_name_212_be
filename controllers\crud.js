const _ = require('lodash');
const Joi = require('@hapi/joi');
const { Collection, Item, Request } = require('postman-collection');
const { Readable } = require('stream');
const bcrypt = require('bcrypt');

const BASE_URL = `http://localhost:3000`;

module.exports = function (app) {
  const controller = {};

  controller.get = async function (req, res, next) {
    try {
      const __res = await app.libs.crud.get_crud({ params: req.params, query: req.query, user_info: req.user_info });
      return res.jsonp(__res);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.post = async function (req, res, next) {
    try {
      const __res = await app.libs.crud.post_crud({ params: req.params, body: req.body, user_info: req.user_info });
      return res.jsonp(__res);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'post',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.get_schema = async function (req, res, next) {
    try {
      const __tables = _.cloneDeep(_.get(app.mysql_schema, 'tables', []));
      const __user_id = _.get(req.user_info, 'user.id');
      const __user_role = _.get(req.user_info, 'user.role');
      if (__user_id !== '-1') {
        for (const __t of __tables) {
          if (__t.tenant) {
            __t.crud_get_enabled = __user_role === _.get(app.constants, ['roles', 'OWNER']);
            __t.crud_post_enabled = false;
            __t.crud_delete_enabled = false;
            __t.crud_soft_delete_enabled = false;
            __t.crud_put_enabled = __user_role === _.get(app.constants, ['roles', 'OWNER']);
          }
          if (__t.member) {
            __t.crud_get_enabled = __user_role === _.get(app.constants, ['roles', 'OWNER']);
            __t.crud_post_enabled = __user_role === _.get(app.constants, ['roles', 'OWNER']);
            __t.crud_delete_enabled = __user_role === _.get(app.constants, ['roles', 'OWNER']);
            __t.crud_soft_delete_enabled = __user_role === _.get(app.constants, ['roles', 'OWNER']);
            __t.crud_put_enabled = __user_role === _.get(app.constants, ['roles', 'OWNER']);
          }
        }
      }
      return res.jsonp({ tables: __tables });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get_schema',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.login = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          email: Joi.string()
            .email({
              minDomainSegments: 2,
            })
            .required(),
          password: Joi.string().required(),
        }),
        data: req.body,
      });

      const __email = _.get(req, 'body.email');
      const __password = _.get(req, 'body.password');
      const __root_email = _.get(app.config, ['superadmin', 'username']);
      if (__email === __root_email) {
        if (__password !== _.get(app.config, ['superadmin', 'password'])) {
          throw new app.libs.customError('Incorrect username or password', 403);
        }
        const authDetails = await app.libs.auth.generate_token({ id: '-1' });
        return res.jsonp(
          _.merge(authDetails, {
            user: { email: __root_email, first_name: 'Root', last_name: 'User', is_admin: true },
            message: 'Login successful',
          })
        );
      }
      const tableDetails = _.find(_.get(app.mysql_schema, 'tables'), (item) => item.tenant);
      const memberTableDetails = _.find(_.get(app.mysql_schema, 'tables'), (item) => item.member);
      const fieldDetails = _.get(tableDetails, 'external_fields') || {};
      const primaryKey = _.findKey(fieldDetails, { primary: true });
      if (!primaryKey) {
        throw new app.libs.customError('Incorrect username or password', 403);
      }

      let table_name = tableDetails.name;
      let __tenant_column = null;
      if (memberTableDetails) {
        table_name = memberTableDetails.name;
        for (const __c in _.get(memberTableDetails, ['external_fields'], {})) {
          const __cr_meta = _.get(memberTableDetails, ['external_fields', __c, 'reference'], {});
          if (_.get(__cr_meta, ['table']) === tableDetails.name && _.get(__cr_meta, ['column']) === primaryKey) {
            __tenant_column = __c;
            break;
          }
        }
        if (!__tenant_column) {
          throw new app.libs.customError('Incorrect username or password', 403);
        }
      }
      const whereClause = { table_name, email: __email };
      const result = await app.db.records(whereClause);

      if (result.length === 0 || !result[0].password) {
        throw new app.libs.customError('Incorrect username or password', 403);
      }

      const isPasswordMatch = await bcrypt.compare(__password, result[0].password);

      if (isPasswordMatch) {
        const __user_id = memberTableDetails ? result[0][__tenant_column] : result[0][primaryKey];
        const authDetails = await app.libs.auth.generate_token({
          id: __user_id,
          role: _.get(result, [0, 'role'], _.get(app.constants, ['roles', 'OWNER'])),
        });
        return res.jsonp(
          _.merge(authDetails, {
            user: { ...result[0], is_admin: false },
            role: _.get(result, [0, 'role'], _.get(app.constants, ['roles', 'OWNER'])),
            message: 'Login successful',
          })
        );
      }
      throw new app.libs.customError('Incorrect username or password', 403);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'login',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.delete = async function (req, res, next) {
    try {
      const eligible_tables = app.libs.utils.pluck(
        _.filter(_.get(app.mysql_schema, ['tables']), (item) => item.crud_delete_enabled || item.crud_soft_delete_enabled),
        'name'
      );
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          table_name: Joi.string().valid(eligible_tables).required(),
          id: Joi.string().required(),
        }),
        data: req.params,
      });

      const __table_name = req.params.table_name;
      const __crud_details = _.find(_.get(app.mysql_schema, ['tables']), { name: __table_name });
      const __field_details = _.get(__crud_details, 'external_fields') || {};
      const __primary_key = _.findKey(__field_details, { primary: true });
      if (!__primary_key) {
        return res.status(404).jsonp({ message: 'Primary key not configured' });
      }
      const __q = { table_name: __table_name, [__primary_key]: req.params.id };
      const __record = await app.db.records(__q);
      if (_.size(__record) === 0) {
        return res.status(404).jsonp({ message: 'Record not found' });
      }
      const __is_soft_delete = __crud_details.crud_soft_delete_enabled;
      if (__is_soft_delete) {
        const __soft_delete_keys = Object.keys(__field_details).filter(
          (key) => __field_details[key].soft_delete && __field_details[key].soft_delete.configured
        );
        const __soft_delete_pairs = __soft_delete_keys.reduce((acc, key) => {
          const softDeleteValue = __field_details[key].soft_delete.value;
          acc[key] = softDeleteValue;
          return acc;
        }, {});
        if (!_.size(__soft_delete_pairs)) {
          return res.status(404).jsonp({ message: 'Archive data not found' });
        }
        await app.db.update_record_by_ID_or_UUID({
          table_name: __table_name,
          id: _.get(req, 'params.id', 'NA'),
          identifier: __primary_key,
          update: _.merge(
            __soft_delete_pairs,
            app.libs.utils.get_basic_insert_details({ meta: { update: true }, user_info: req.user_info })
          ),
        });
        return res.jsonp({ message: 'Archived successfully' });
      }
      // Check for the reference
      for (const __t of _.get(app.mysql_schema, ['tables'], [])) {
        for (const __i in _.get(__t, 'external_fields')) {
          if (_.get(__t, ['external_fields', __i, 'reference', 'table']) === req.params.table_name) {
            const __q1 = {
              table_name: __t.name,
              [__i]: _.get(__record, [0, _.get(__t, ['external_fields', __i, 'reference', 'column'])]),
            };
            const __record1 = await app.db.records(__q1);
            if (_.size(__record1)) {
              return res
                .status(403)
                .jsonp({ message: `This table is linked to others, so deleting from it isn't allowed directly` });
            }
          }
        }
      }
      await app.db.delete_record_by_ID_or_UUID({
        table_name: req.params.table_name,
        identifier: __primary_key,
        id: _.get(req, 'params.id', 'NA'),
      });
      return res.jsonp({ message: 'Deleted successfully' });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'delete',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.update = async function (req, res, next) {
    try {
      const __res = await app.libs.crud.put_crud({ params: req.params, body: req.body, user_info: req.user_info });
      return res.jsonp(__res);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'update',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.download_postman_collection = async function (req, res, next) {
    try {
      const postmanCollection = new Collection({
        info: {
          name: 'postman-collection',
          schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
        },
      });

      for (const table of _.get(app.mysql_schema, 'tables') || []) {
        if (table.crud_get_enabled) {
          const getItem = new Item({
            name: `Get ${table.name} data`,
            request: new Request({
              url: `${BASE_URL}/crud/${table.name}`,
              method: 'GET',
            }).toJSON(),
          });
          postmanCollection.items.add(getItem);
        }

        if (table.crud_post_enabled) {
          const postItem = new Item({
            name: `Insert ${table.name} data`,
            request: new Request({
              url: `${BASE_URL}/crud/${table.name}`,
              method: 'POST',
            }).toJSON(),
            body: {
              mode: 'raw',
              raw: JSON.stringify({}),
            },
          });
          postmanCollection.items.add(postItem);
        }

        if (table.crud_put_enabled) {
          const putItem = new Item({
            name: `Update ${table.name} data`,
            request: new Request({
              url: `${BASE_URL}/crud/${table.name}/:id`,
              method: 'PUT',
            }).toJSON(),
            body: {
              mode: 'raw',
              raw: JSON.stringify({}),
            },
          });
          postmanCollection.items.add(putItem);
        }

        if (table.crud_delete_enabled) {
          const deleteItem = new Item({
            name: `Delete ${table.name} data`,
            request: new Request({
              url: `${BASE_URL}/crud/${table.name}/:id`,
              method: 'DELETE',
            }).toJSON(),
          });
          postmanCollection.items.add(deleteItem);
        }

        if (table.crud_soft_delete_enabled) {
          const archiveItem = new Item({
            name: `Archive ${table.name} data`,
            request: new Request({
              url: `${BASE_URL}/crud/${table.name}/:id`,
              method: 'DELETE',
            }).toJSON(),
          });
          postmanCollection.items.add(archiveItem);
        }
      }
      res.setHeader('Content-disposition', 'attachment; filename=postman-collection.json');
      res.setHeader('Content-type', 'application/json');
      const stream = Readable.from(JSON.stringify(postmanCollection.toJSON(), null, 2));
      stream.pipe(res);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'download_postman_collection',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  return controller;
};
