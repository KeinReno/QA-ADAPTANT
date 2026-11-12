import { z } from 'zod';
import { mkdir, writeFile } from 'node:fs/promises';
import { schemas } from './index.mjs';
const dir = new URL('../../schemas/', import.meta.url);
await mkdir(dir, { recursive: true });
for (const [name, schema] of Object.entries(schemas)) {
  await writeFile(new URL(`${name}.schema.json`, dir), JSON.stringify(z.toJSONSchema(schema), null, 2) + '\n');
}
console.log('Экспортированы шесть структурных схем; межполевые правила: packages/contracts/index.mjs');
