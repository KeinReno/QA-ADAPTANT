import { spawn } from 'node:child_process';

function powershell(script, path) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
      windowsHide: true,
      env: { ...process.env, QA_ACL_PATH: path }
    });
    const out = [];
    const err = [];
    child.stdout.on('data', chunk => out.push(chunk));
    child.stderr.on('data', chunk => err.push(chunk));
    child.on('error', reject);
    child.on('close', code => {
      const failure = Buffer.concat(err).toString('utf8').trim();
      if (code !== 0) reject(Object.assign(new Error(failure || 'ACL каталога ключей не установлен'), { code: 'TRUST_STORE_UNAVAILABLE' }));
      else resolve(Buffer.concat(out).toString('utf8').trim());
    });
    child.stdin.end();
  });
}

const restrictScript = `
$ErrorActionPreference = 'Stop'
$path = $env:QA_ACL_PATH
$acl = Get-Acl -LiteralPath $path
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$item = Get-Item -LiteralPath $path
$inherit = $(if ($item.PSIsContainer) { 'ContainerInherit, ObjectInherit' } else { 'None' })
$rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $path -AclObject $acl
`;

const readScript = `
$ErrorActionPreference = 'Stop'
$path = $env:QA_ACL_PATH
$acl = Get-Acl -LiteralPath $path
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$aces = foreach ($rule in $acl.Access) {
  $id = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  '{0}|{1}' -f $id, $rule.AccessControlType
}
@{ protected = [bool]$acl.AreAccessRulesProtected; current = $current; aces = @($aces) } | ConvertTo-Json -Compress
`;

export async function restrictToCurrentUser(path) {
  if (process.platform !== 'win32') throw Object.assign(new Error('ACL ключей задаётся только на Windows'), { code: 'UNSUPPORTED' });
  await powershell(restrictScript, path);
}

export async function readAcl(path) {
  const text = await powershell(readScript, path);
  return JSON.parse(text);
}
