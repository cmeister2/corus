import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./diagnose-arm-hang.mjs', import.meta.url));

function run(source, timeoutMs = 5000) {
  const directory = mkdtempSync(join(tmpdir(), 'corus-watchdog-'));
  try {
    const processResult = spawnSync(process.execPath, [script, process.execPath, '-e', source], {
      encoding: 'utf8', timeout: 15_000,
      env: {
        ...process.env,
        CORUS_DIAGNOSTIC_DIR: directory,
        CORUS_DIAGNOSTIC_TIMEOUT_MS: String(timeoutMs),
        CORUS_DIAGNOSTIC_SNAPSHOT_MS: '100',
      },
    });
    assert.equal(processResult.error, undefined);
    return {
      status: processResult.status,
      result: JSON.parse(readFileSync(join(directory, 'result.json'), 'utf8')),
      log: readFileSync(join(directory, 'test.log'), 'utf8'),
      snapshots: readFileSync(join(directory, 'processes.log'), 'utf8'),
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('preserves output and a successful exit', () => {
  const observed = run('console.log("completed")');
  assert.equal(observed.status, 0);
  assert.equal(observed.result.exitCode, 0);
  assert.equal(observed.result.timedOut, false);
  assert.match(observed.log, /completed/);
});

test('preserves a failing exit', () => {
  const observed = run('process.exitCode = 7');
  assert.equal(observed.status, 7);
  assert.equal(observed.result.exitCode, 7);
  assert.equal(observed.result.timedOut, false);
});

test('snapshots and kills a stopped process and its detached descendant', () => {
  const observed = run(`
    const { spawn } = require('node:child_process');
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { detached: true });
    console.log('descendant=' + child.pid);
    child.once('spawn', () => process.kill(process.pid, 'SIGSTOP'));
  `, 1000);
  assert.equal(observed.status, 124);
  assert.equal(observed.result.timedOut, true);
  assert.match(observed.snapshots, /timeout/);
  assert.match(observed.snapshots, /State:\s+T/);
  const descendant = observed.log.match(/descendant=(\d+)/)?.[1];
  assert.ok(descendant);
  assert.ok(observed.snapshots.includes(`/proc/${descendant}/task/`));
  for (const pid of [observed.result.pid, descendant]) {
    try {
      assert.match(readFileSync(`/proc/${pid}/status`, 'utf8'), /State:\s+Z/);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
});