import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

// String-SQL entry points on the Cloudflare bindings: D1 and Durable Object SQLite storage. Drizzle's
// database object (getOrm(db), drizzle-orm/durable-sqlite) is a different type, so its builders and its
// batch() stay allowed.
const RAW_SQL_METHODS = new Map([
  ['D1Database', new Set(['prepare', 'exec', 'batch', 'dump', 'withSession'])],
  ['D1DatabaseSession', new Set(['prepare', 'batch'])],
  ['SqlStorage', new Set(['exec'])],
]);
// Drizzle methods that execute a whole hand-written statement when handed a sql`...` template.
const DRIZZLE_STATEMENT_EXECUTORS = new Set(['run', 'all', 'get', 'values']);

const isSqlTemplate = (node) => node?.type === 'TaggedTemplateExpression' && node.tag.type === 'Identifier' && node.tag.name === 'sql';

const noRawSql = {
  meta: {
    type: 'problem',
    docs: { description: 'Forbid string SQL against D1 and Durable Object storage; build queries with drizzle.' },
    messages: {
      binding: '{{type}}.{{method}}() runs hand-written SQL. Use the drizzle query builder through getOrm(db) (drizzle-orm/durable-sqlite in Durable Objects).',
      statement: '{{method}}(sql`...`) runs a hand-written statement. Build it with the drizzle query builder instead.',
      sqlRaw: 'sql.raw() splices unescaped text into SQL. Use sql`...` parameters or the query builder.',
    },
    schema: [],
  },
  create(context) {
    const services = context.sourceCode.parserServices;
    const checker = services.program.getTypeChecker();
    // Type-aware, so RegExp#exec or an unrelated prepare() never trips the rule.
    const receiverTypes = (node) => {
      const type = checker.getNonNullableType(services.getTypeAtLocation(node));
      return (type.isUnion() ? type.types : [type]).map((part) => part.getSymbol()?.getName());
    };
    return {
      CallExpression(node) {
        const { callee } = node;
        if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') return;
        const method = callee.property.name;
        if (method === 'raw' && callee.object.type === 'Identifier' && callee.object.name === 'sql') {
          context.report({ node, messageId: 'sqlRaw' });
        } else if (DRIZZLE_STATEMENT_EXECUTORS.has(method) && isSqlTemplate(node.arguments[0])) {
          context.report({ node, messageId: 'statement', data: { method } });
        } else {
          const type = receiverTypes(callee.object).find((name) => RAW_SQL_METHODS.get(name)?.has(method));
          if (type) context.report({ node, messageId: 'binding', data: { type, method } });
        }
      },
    };
  },
};

export default defineConfig({
  files: ['src/**/*.ts'],
  // Tests seed and inspect the database directly; the rule guards what ships in the Worker.
  ignores: ['src/**/*.test.ts', 'src/test/**'],
  languageOptions: {
    parser: tseslint.parser,
    parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
  },
  linterOptions: { reportUnusedDisableDirectives: 'error' },
  plugins: { nodewarden: { rules: { 'no-raw-sql': noRawSql } } },
  rules: { 'nodewarden/no-raw-sql': 'error' },
});
