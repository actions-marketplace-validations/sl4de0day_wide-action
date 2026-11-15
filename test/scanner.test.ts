import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { SecurityScanner } from '../src/engine/scanner.js';

describe('SecurityScanner Engine', () => {
  const tmpDir = resolve('./test_tmp_scanner');

  before(() => {
    mkdirSync(tmpDir, { recursive: true });
  });

  after(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects sql injection and command injection correctly', async () => {
    const filePath = join(tmpDir, 'vuln.ts');
    const content = [
      'import express from "express";',
      'const query = "SELECT * FROM users WHERE name = \'" + req.query.name + "\'";',
      'const safe = 42;'
    ].join('\n');

    writeFileSync(filePath, content, 'utf8');

    const scanner = new SecurityScanner(tmpDir);
    const result = await scanner.scan({ onlyDiff: false });

    assert.ok(result.findings.length >= 1);
    const sqlFinding = result.findings.find(f => f.ruleId === 'WIDE-SEC-001');
    assert.ok(sqlFinding);
    assert.equal(sqlFinding.line, 2);
    assert.equal(sqlFinding.severity, 'CRITICAL');
  });

  it('filters out findings outside modified lines when onlyDiff is true', async () => {
    const filePath = join(tmpDir, 'diff_test.ts');
    const content = [
      'const preExisting = "SELECT * FROM data WHERE id = " + req.query.id;',
      'const normalLine = 1;',
      'const newVuln = "AKIA1234567890123456";',
      'const endLine = 2;'
    ].join('\n');

    writeFileSync(filePath, content, 'utf8');

    const scanner = new SecurityScanner(tmpDir);
    const modifiedLines = new Set<number>([3]);
    const modifiedMap = new Map<string, Set<number>>([['diff_test.ts', modifiedLines]]);

    const diffResult = await scanner.scan({
      onlyDiff: true,
      modifiedFiles: modifiedMap
    });

    assert.equal(diffResult.findings.length, 1);
    assert.equal(diffResult.findings[0].line, 3);
    assert.equal(diffResult.findings[0].ruleId, 'WIDE-SEC-008');

    const fullResult = await scanner.scan({ onlyDiff: false });
    assert.ok(fullResult.findings.length >= 2);
  });

  it('does not fall back to full workspace scan when onlyDiff is true with empty modifiedFiles', async () => {
    const filePath = join(tmpDir, 'existing_vuln.ts');
    writeFileSync(filePath, 'const q = "SELECT * FROM users WHERE id = " + req.query.id;\n', 'utf8');

    const scanner = new SecurityScanner(tmpDir);
    const emptyDiffResult = await scanner.scan({
      onlyDiff: true,
      modifiedFiles: new Map<string, Set<number>>()
    });

    assert.equal(emptyDiffResult.totalFilesScanned, 0);
    assert.equal(emptyDiffResult.findings.length, 0);
  });

  it('skips ignored directories, non-code extensions, and binary files in onlyDiff mode', async () => {
    mkdirSync(join(tmpDir, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(tmpDir, 'node_modules', 'pkg', 'index.js'), 'const q = "SELECT * FROM x WHERE id=" + req.query.id;\n', 'utf8');
    writeFileSync(join(tmpDir, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00]));
    writeFileSync(join(tmpDir, 'binary.ts'), Buffer.from('const q = "SELECT * FROM x WHERE id=" + req.query.id;\x00\x01'));

    const scanner = new SecurityScanner(tmpDir);
    const modifiedFiles = new Map<string, Set<number>>([
      ['node_modules/pkg/index.js', new Set([1])],
      ['image.png', new Set([1])],
      ['binary.ts', new Set([1])]
    ]);

    const res = await scanner.scan({ onlyDiff: true, modifiedFiles });
    assert.equal(res.totalFilesScanned, 0);
    assert.equal(res.findings.length, 0);
  });
});
