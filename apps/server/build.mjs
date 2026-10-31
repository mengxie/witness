// Bundles the server and the workspace's core package into one ESM file;
// third-party dependencies stay external and are installed in the image.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { build } from 'esbuild';

const pkg = JSON.parse(await readFile(join(import.meta.dirname, 'package.json'), 'utf8'));
await build({
  entryPoints: ['src/main.ts'],
  outfile: 'dist/main.js',
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  sourcemap: true,
  external: Object.keys(pkg.dependencies).filter((name) => !name.startsWith('@witness/')),
  logLevel: 'info',
});
