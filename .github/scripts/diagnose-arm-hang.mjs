import { spawn, spawnSync } from 'node:child_process';
import {
  appendFileSync, closeSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

const [command, ...args] = process.argv.slice(2);
if (!command) throw new Error('Usage: node diagnose-arm-hang.mjs COMMAND [ARGS...]');

const directory = process.env.CORUS_DIAGNOSTIC_DIR ?? 'target/arm-hang-diagnostics';
const timeoutMs = Number(process.env.CORUS_DIAGNOSTIC_TIMEOUT_MS ?? 60_000);
const snapshotMs = Number(process.env.CORUS_DIAGNOSTIC_SNAPSHOT_MS ?? 10_000);
if (![timeoutMs, snapshotMs].every(value => Number.isSafeInteger(value) && value > 0)) {
  throw new Error('Diagnostic timer values must be positive integers');
}
mkdirSync(directory, { recursive: true });
const logPath = join(directory, 'test.log');
const snapshotsPath = join(directory, 'processes.log');
const descriptor = openSync(logPath, 'w');
const child = spawn(command, args, { detached: true, stdio: ['ignore', descriptor, descriptor] });
let forcedExit;

function readProcFile(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    if (error.code === 'EACCES' || error.code === 'EPERM') {
      const result = spawnSync('sudo', ['-n', 'cat', '--', path], {
        encoding: 'utf8', timeout: 1000,
      });
      if (result.status === 0) return result.stdout;
      return `unavailable: ${result.error?.message ?? result.stderr}\n`;
    }
    return `unavailable: ${error.code}\n`;
  }
}

function snapshot(reason) {
  appendFileSync(snapshotsPath, `\n${new Date().toISOString()} ${reason} root=${child.pid}\n`);
  const pending = [child.pid];
  const visited = new Set();
  while (pending.length) {
    const pid = pending.pop();
    if (!pid || visited.has(pid)) continue;
    visited.add(pid);
    let tids;
    try {
      tids = readdirSync(`/proc/${pid}/task`);
    } catch {
      continue;
    }
    for (const tid of tids) {
      const taskPath = `/proc/${pid}/task/${tid}`;
      const children = readProcFile(`${taskPath}/children`).trim().split(/\s+/);
      pending.push(...children.filter(value => /^\d+$/.test(value)).map(Number));
      for (const name of ['status', 'wchan', 'syscall', 'stack']) {
        appendFileSync(snapshotsPath, `\n${taskPath}/${name}\n${readProcFile(`${taskPath}/${name}`)}\n`);
      }
    }
  }
  return visited;
}

function killGroup(pids = []) {
  for (const pid of [...pids].reverse()) {
    if (pid === child.pid) continue;
    try {
      process.kill(pid, 'SIGKILL');
    } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
  }
  if (!child.pid) return;
  try {
    process.kill(-child.pid, 'SIGKILL');
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}

snapshot('started');
const interval = setInterval(() => snapshot('running'), snapshotMs);
const timer = setTimeout(() => {
  forcedExit = 124;
  killGroup(snapshot('timeout'));
}, timeoutMs);
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    forcedExit = signal === 'SIGINT' ? 130 : 143;
    killGroup(snapshot(signal));
  });
}

const exitCode = await new Promise(resolve => {
  function finish(code, signal, error) {
    clearInterval(interval);
    clearTimeout(timer);
    killGroup();
    if (error) appendFileSync(logPath, `${error.message}\n`);
    closeSync(descriptor);
    const exitCode = forcedExit ?? code ?? 1;
    writeFileSync(join(directory, 'result.json'), `${JSON.stringify({
      command, args, pid: child.pid, exitCode, signal, timedOut: forcedExit === 124,
    }, null, 2)}\n`);
    process.stdout.write(readFileSync(logPath, 'utf8'));
    console.log(`Diagnostic exit code: ${exitCode}; artifacts: ${directory}`);
    resolve(exitCode);
  }
  child.once('error', error => finish(null, null, error));
  child.once('exit', (code, signal) => finish(code, signal));
});
process.exitCode = exitCode;