import fs from 'node:fs';
import path from 'node:path';
import { observe } from '../apps/control/run.mjs';

const root = process.argv[2];
const runId = process.argv[3];
const count = Number(process.argv[4] || 100);
const runDir = path.join(root, 'runs', runId);
let done = 0;
const deadline = Date.now() + 60000;
while (done < count && Date.now() < deadline) {
  const journal = path.join(runDir, 'evidence.jsonl');
  if (fs.existsSync(journal)) fs.readFileSync(journal);
  const commits = path.join(runDir, 'evidence-commits');
  if (fs.existsSync(commits)) {
    for (const name of fs.readdirSync(commits)) {
      if (!/^\d{6}\.json$/.test(name)) continue;
      try { fs.readFileSync(path.join(commits, name)); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
  if (fs.existsSync(path.join(runDir, 'manifest.json'))) {
    try { await observe({ root, runId }); }
    catch (error) {
      const message = String(error.message || error);
      if (!/INCOMPLETE_RUN|неполон|недоступен/.test(message)) throw error;
    }
    done++;
  } else {
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}
if (done < count) throw new Error(`OBSERVE выполнен ${done} раз из ${count}`);
process.stdout.write(String(done));
