import path from 'node:path';
import { spawn } from 'node:child_process';

const fail = (code, message) => Object.assign(new Error(message), { code });

// Windows kernel releases FileShare.None when the helper exits, including when
// the Node owner crashes. The lock file is persistent; it is never unlinked or reclaimed.
export async function withFileMutex(file, action, { timeoutMs = 10000 } = {}) {
  const helperPath = path.join(process.env.SystemRoot || process.env.windir || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const escapedPath = path.resolve(file).replace(/'/g, "''");
  const script = `$f = $null; while (-not $f) { try { $f = [System.IO.File]::Open('${escapedPath}', [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) } catch [System.IO.IOException] { Start-Sleep -Milliseconds 25 } }; [Console]::Out.WriteLine('LOCKED'); [Console]::In.ReadLine() | Out-Null; $f.Dispose()`;
  const helper = spawn(helperPath, ['-NoProfile', '-NonInteractive', '-Command', script], {
    stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true
  });
  const exited = new Promise(resolve => helper.once('exit', (code, signal) => resolve({ code, signal })));
  let buffer = '';
  const stopHelper = async () => {
    const result = await Promise.race([exited, new Promise(resolve => setTimeout(() => resolve(null), 5000))]);
    if (!result && helper.exitCode === null && helper.signalCode === null) {
      helper.kill();
      await exited;
    }
  };
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(fail('PUBLICATION_PENDING', 'Таймаут ожидания mutex публикации')), timeoutMs);
      const finish = callback => value => { clearTimeout(timer); callback(value); };
      helper.stdout.setEncoding('utf8');
      helper.stdout.on('data', chunk => {
        buffer += chunk;
        if (buffer.includes('LOCKED')) finish(resolve)();
      });
      helper.once('error', error => finish(reject)(fail('PUBLICATION_PENDING', 'Не запущен Windows mutex публикации: ' + error.message)));
      helper.once('exit', code => {
        if (!buffer.includes('LOCKED')) finish(reject)(fail('PUBLICATION_PENDING', `Windows mutex публикации завершился: exit=${code}`));
      });
    });
    return await action();
  } finally {
    if (helper.exitCode === null && helper.signalCode === null) helper.stdin.end('\n');
    await stopHelper();
  }
}
