'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function git(args, cwd) {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null;
  } catch {
    return null;
  }
}

function command(command, args, cwd) {
  try {
    return execFileSync(command, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null;
  } catch {
    return null;
  }
}

function packageVersions(packageJson) {
  return Object.fromEntries(
    ['dependencies', 'devDependencies', 'optionalDependencies']
      .flatMap((section) => Object.entries(packageJson[section] || {}))
      .sort(([a], [b]) => a.localeCompare(b)),
  );
}

function create({ root, startedAt, finishedAt, options = {} }) {
  const packagePath = path.join(root, 'package.json');
  const manifestPath = path.join(root, 'benchmark', 'manifest.json');
  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  const revision = git(['rev-parse', 'HEAD'], root);
  return {
    schemaVersion: 1,
    runId: crypto.randomUUID(),
    startedAt,
    finishedAt,
    repository: {
      revision,
      dirty: revision ? Boolean(git(['status', '--porcelain'], root)) : null,
    },
    inputs: {
      benchmarkManifest: 'benchmark/manifest.json',
      benchmarkManifestSha256: sha256File(manifestPath),
      packageJson: 'package.json',
      packageJsonSha256: sha256File(packagePath),
    },
    options,
    tools: {
      node: process.version,
      v8: process.versions.v8,
      npm: command('npm', ['--version'], root),
    },
    environment: {
      platform: process.platform,
      arch: process.arch,
      cwd: root,
      nodeEnv: process.env.NODE_ENV || null,
      ci: process.env.CI === 'true',
    },
    dependencies: packageVersions(packageJson),
  };
}

module.exports = { create, sha256File };
