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
    const sqlFinding = result.findings.find(f => f.cwe === 'CWE-89');
    assert.ok(sqlFinding);
    assert.equal(sqlFinding.ruleId, 'wide/sql-concatenation');
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
    assert.equal(diffResult.findings[0].ruleId, 'wide/hardcoded-secret');

    const fullResult = await scanner.scan({ onlyDiff: false });
    assert.ok(fullResult.findings.length >= 2);
  });

  it('scans vue, yaml, and kotlin extensions, suppresses comments and wide-ignore, and skips prompt behavior rules', async () => {
    const subDir = join(tmpDir, 'multi_lang');
    mkdirSync(subDir, { recursive: true });
    writeFileSync(
      join(subDir, 'App.vue'),
      [
        '<template>',
        '  <a :href="\'javascript:alert(1)\'">bad</a>',
        '  <a :href="\'javascript:alert(2)\'">suppressed</a> <!-- wide-ignore -->',
        '  <!-- wide-ignore-next-line -->',
        '  <a :href="\'javascript:alert(3)\'">ignored</a>',
        '</template>'
      ].join('\n'),
      'utf8'
    );
    writeFileSync(
      join(subDir, 'config.yml'),
      'db_url: "postgresql://prod_admin:S3cur3ProdPass99@db.internal:5432/app"\n',
      'utf8'
    );
    writeFileSync(
      join(subDir, 'notes.ts'),
      [
        '// const leaked = "AKIA1234567890123456";',
        'const label = "Follow my guidelines carefully";'
      ].join('\n'),
      'utf8'
    );

    const scanner = new SecurityScanner(subDir);
    const res = await scanner.scan({ onlyDiff: false });
    assert.ok(res.findings.some(f => f.file === 'App.vue' && f.line === 2 && f.ruleId === 'wide/cwe79-vue-href-javascript-uri'));
    assert.equal(res.findings.some(f => f.file === 'App.vue' && (f.line === 3 || f.line === 5)), false);
    assert.ok(res.findings.some(f => f.file === 'config.yml' && f.cwe === 'CWE-798'));
    assert.equal(res.findings.some(f => f.file === 'notes.ts'), false);
  });

  it('detects vulnerable dependencies via OSV SCA across manifests and honors onlyDiff', async () => {
    const scaDir = join(tmpDir, 'sca_test');
    mkdirSync(scaDir, { recursive: true });
    writeFileSync(
      join(scaDir, 'package.json'),
      JSON.stringify(
        {
          name: 'demo',
          dependencies: {
            lodash: '4.17.20',
            minimist: '1.2.5',
            react: '19.0.0'
          }
        },
        null,
        2
      ),
      'utf8'
    );
    writeFileSync(join(scaDir, 'requirements.txt'), 'pyyaml==5.3.1\nrequests==2.32.3\n', 'utf8');
    writeFileSync(join(scaDir, 'go.mod'), 'module demo\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)\n', 'utf8');

    const mockAdvisories = {
      npm: [
        { name: 'lodash', ge: '0.0.0', lt: '4.17.21', id: 'CVE-2021-23337', cwe: 'CWE-78', sev: 'HIGH', note: 'Command injection in lodash', kev: true, epss: 0.72 },
        { name: 'minimist', ge: '1.0.0', le: '1.2.5', id: 'CVE-2021-44906', cwe: 'CWE-1321', sev: 'CRITICAL', note: 'Prototype pollution inclusive upper bound' }
      ],
      pip: [
        { name: 'pyyaml', lt: '5.4', id: 'CVE-2020-14343', cwe: 'CWE-502', sev: 'CRITICAL', note: 'Arbitrary code execution in PyYAML' }
      ],
      go: [
        { name: 'github.com/gin-gonic/gin', lt: '1.7.0', id: 'CVE-2020-28483', cwe: 'CWE-20', sev: 'MEDIUM', note: 'ClientIP bypass' }
      ]
    };

    const scanner = new SecurityScanner(scaDir);
    const full = await scanner.scan({ onlyDiff: false, sca: true, advisories: mockAdvisories });
    const scaFull = full.findings.filter(f => f.source === 'sca');
    assert.equal(scaFull.length, 4);
    const minimistHit = scaFull.find(f => f.packageName === 'minimist');
    assert.ok(minimistHit?.remediation?.includes('newer than 1.2.5'));
    const lodashHit = scaFull.find(f => f.packageName === 'lodash');
    assert.ok(lodashHit);
    assert.equal(lodashHit.kev, true);
    assert.ok(lodashHit.description.includes('CISA KEV'));

    const modifiedFiles = new Map<string, Set<number>>([['requirements.txt', new Set([1])]]);
    const diffRes = await scanner.scan({ onlyDiff: true, modifiedFiles, sca: true, advisories: mockAdvisories });
    assert.equal(diffRes.findings.filter(f => f.source === 'sca').length, 1);
    assert.equal(diffRes.findings[0].packageName, 'pyyaml');
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

  it('detects multi-line and cross-file taint flows, filters placeholder secrets, and evaluates lockfile SCA reachability', async () => {
    const deepDir = join(tmpDir, 'deep_test');
    mkdirSync(join(deepDir, '.github', 'workflows'), { recursive: true });
    writeFileSync(
      join(deepDir, 'sink.ts'),
      'export function runLookup(db: any, userId: string) {\n  return db.query(\n    "SELECT * FROM users WHERE name = \'" +\n    userId\n  );\n}\n',
      'utf8'
    );
    writeFileSync(
      join(deepDir, 'routes.ts'),
      'import express from "express";\nimport { runLookup } from "./sink.js";\nexport function handler(req: any, db: any) {\n  const raw = req.query.q;\n  return runLookup(db, raw);\n}\nexport const SAFE_PLACEHOLDER = "EXAMPLE_YOUR_API_KEY_HERE";\nexport const LEAKED = "ghp_9xK2mP7qR4tV8wZ1aB3cD5eF6gH8jL0nM2q";\n',
      'utf8'
    );
    writeFileSync(
      join(deepDir, '.github', 'workflows', 'pr.yml'),
      'on: pull_request_target\nsteps:\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n',
      'utf8'
    );
    writeFileSync(
      join(deepDir, 'main.tf'),
      'resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n',
      'utf8'
    );
    writeFileSync(join(deepDir, 'yarn.lock'), '"express@^4.17.0":\n  version "4.17.1"\n', 'utf8');
    writeFileSync(join(deepDir, 'Cargo.lock'), '[[package]]\nname = "serde_yaml"\nversion = "0.9.10"\n', 'utf8');

    const advs = {
      npm: [{ name: 'express', le: '4.17.1', id: 'CVE-2024-9991', cwe: 'CWE-601', sev: 'HIGH', note: 'open redirect' }],
      cargo: [{ name: 'serde_yaml', lt: '0.9.20', id: 'CVE-2024-9992', cwe: 'CWE-502', sev: 'CRITICAL', note: 'unsafe yaml' }]
    };

    const scanner = new SecurityScanner(deepDir);
    const res = await scanner.scan({ onlyDiff: false, sca: true, advisories: advs });

    const crossFlow = res.findings.find(f => f.crossFile === true && f.file === 'routes.ts');
    assert.ok(crossFlow, 'Expected cross-file taint flow finding on routes.ts');
    assert.equal(crossFlow.cwe, 'CWE-89');

    const ciHit = res.findings.find(f => f.ruleId === 'wide/cicd-gha-pull-request-target-checkout');
    assert.ok(ciHit, 'Expected CI/CD workflow rule hit');

    const tfHit = res.findings.find(f => f.ruleId === 'wide/iac-terraform-public-ingress');
    assert.ok(tfHit, 'Expected Terraform public ACL hit');

    const expressSca = res.findings.find(f => f.source === 'sca' && f.packageName === 'express');
    const cargoSca = res.findings.find(f => f.source === 'sca' && f.packageName === 'serde_yaml');
    assert.ok(expressSca && expressSca.reachable === true && expressSca.description.includes('[REACHABLE'));
    assert.ok(cargoSca && cargoSca.reachable === false && cargoSca.description.includes('[INSTALLED'));

    assert.equal(res.findings.some(f => f.snippet?.includes('EXAMPLE_YOUR_API_KEY_HERE')), false);
  });
});
