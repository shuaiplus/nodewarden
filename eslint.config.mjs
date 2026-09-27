import { defineConfig } from 'eslint/config';
import ts from 'typescript';
import tseslint from 'typescript-eslint';

// String-SQL entry points on the Cloudflare bindings: D1 and Durable Object SQLite storage. Drizzle's
// database object (getOrm(db), drizzle-orm/durable-sqlite) is a different type, so its builders and its
// batch() stay allowed.
const RAW_SQL_METHODS = new Map([
  ['D1Database', new Set(['prepare', 'exec', 'batch', 'dump', 'withSession'])],
  ['D1DatabaseSession', new Set(['prepare', 'batch'])],
  ['SqlStorage', new Set(['exec'])],
]);
// Drizzle database methods that execute a whole hand-written statement: they take a sql`...` value or a
// plain string (SQLWrapper | string). Passing a query builder to them stays allowed.
const DRIZZLE_STATEMENT_EXECUTORS = new Set(['run', 'all', 'get', 'values']);
const DRIZZLE_DATABASES = new Set(['DrizzleD1Database', 'BaseSQLiteDatabase', 'DrizzleSqliteDODatabase']);

const noRawSql = {
  meta: {
    type: 'problem',
    docs: { description: 'Forbid string SQL against D1 and Durable Object storage; build queries with drizzle.' },
    messages: {
      binding: '{{type}}.{{method}}() runs hand-written SQL. Use the drizzle query builder through getOrm(db) (drizzle-orm/durable-sqlite in Durable Objects).',
      statement: '{{method}}() on the drizzle database runs a hand-written statement. Build it with the drizzle query builder instead.',
      sqlRaw: 'sql.raw() splices unescaped text into SQL. Use sql`...` parameters or the query builder.',
    },
    schema: [],
  },
  create(context) {
    const services = context.sourceCode.parserServices;
    const checker = services.program.getTypeChecker();
    // Type-aware, so RegExp#exec, Map#get('key') or an unrelated prepare() never trips the rule.
    const typeParts = (node) => {
      const flatten = (type) => (type.isUnion() || type.isIntersection() ? type.types.flatMap(flatten) : [type]);
      return flatten(checker.getNonNullableType(services.getTypeAtLocation(node)));
    };
    const typeNames = (node) => typeParts(node).map((part) => part.getSymbol()?.getName());
    const isHandWrittenStatement = (query, receiver) =>
      typeNames(query).includes('SQL') ||
      (typeParts(query).every((part) => part.flags & ts.TypeFlags.StringLike) && typeNames(receiver).some((name) => DRIZZLE_DATABASES.has(name)));
    return {
      CallExpression(node) {
        const { callee } = node;
        if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') return;
        const method = callee.property.name;
        if (method === 'raw' && callee.object.type === 'Identifier' && callee.object.name === 'sql') {
          context.report({ node, messageId: 'sqlRaw' });
        } else if (DRIZZLE_STATEMENT_EXECUTORS.has(method) && node.arguments[0] && isHandWrittenStatement(node.arguments[0], callee.object)) {
          context.report({ node, messageId: 'statement', data: { method } });
        } else {
          const type = typeNames(callee.object).find((name) => RAW_SQL_METHODS.get(name)?.has(method));
          if (type) context.report({ node, messageId: 'binding', data: { type, method } });
        }
      },
    };
  },
};

const FUNCTION_VALUES = new Set(['ArrowFunctionExpression', 'FunctionExpression']);

// A module-local function referenced from exactly one place is a named detour: inline it there.
// Exported functions are the module's API (routers, other modules and tests call them), so only their
// own callers decide whether they earn a name.
const noSingleUseFunction = {
  meta: {
    type: 'suggestion',
    docs: { description: 'Forbid module-local functions that are referenced only once; inline them at the call site.' },
    messages: { singleUse: '{{name}} is only used once. Inline it at its single call site.' },
    schema: [],
  },
  create(context) {
    const exportedNames = new Set();
    const functionBody = (definition) => {
      if (definition.type === 'FunctionName' && definition.node.type === 'FunctionDeclaration') return definition.node;
      if (definition.type === 'Variable' && definition.parent.kind === 'const' && FUNCTION_VALUES.has(definition.node.init?.type)) {
        return definition.node.init;
      }
      return null;
    };
    const isExported = (definition) => {
      const declaration = definition.type === 'FunctionName' ? definition.node : definition.parent;
      return ['ExportNamedDeclaration', 'ExportDefaultDeclaration'].includes(declaration.parent?.type);
    };
    return {
      ExportSpecifier(node) {
        exportedNames.add(node.local.name);
      },
      'Program:exit'() {
        for (const scope of context.sourceCode.scopeManager.scopes) {
          for (const variable of scope.variables) {
            const definition = variable.defs.find(functionBody);
            if (!definition || isExported(definition) || exportedNames.has(variable.name)) continue;
            const body = functionBody(definition);
            // A recursive call is not a second caller.
            const callers = variable.references.filter(({ identifier: { range: [start, end] } }) => start < body.range[0] || end > body.range[1]);
            if (callers.length === 1) context.report({ node: definition.name, messageId: 'singleUse', data: { name: variable.name } });
          }
        }
      },
    };
  },
};

export default defineConfig([
  {
    files: ['**/*.{ts,mts,js,mjs,cjs}'],
    languageOptions: { parser: tseslint.parser },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    plugins: {
      '@typescript-eslint': tseslint.plugin,
      nodewarden: { rules: { 'no-raw-sql': noRawSql, 'no-single-use-function': noSingleUseFunction } },
    },
    rules: {
      // Rest siblings are how a field is dropped from a copy ({ secret: _omitted, ...rest }).
      '@typescript-eslint/no-unused-vars': ['error', { ignoreRestSiblings: true }],
      '@typescript-eslint/no-unused-expressions': 'error',
      'nodewarden/no-single-use-function': 'error',
    },
  },
  {
    files: ['src/**/*.ts'],
    // Tests seed and inspect the database directly; the rule guards what ships in the Worker.
    ignores: ['src/**/*.test.ts', 'src/test/**'],
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
    rules: { 'nodewarden/no-raw-sql': 'error' },
  },
]);
