'use strict';

/**
 * Scope-aware recon pipeline planning and execution.
 *
 * This wraps common ProjectDiscovery-style tools without assuming they are
 * installed. Every output remains recon evidence; this module never promotes a
 * scanner match to a vulnerability.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const exec = promisify(execFile);

const TOOLS = {
  subfinder: { args: (domain) => ['-d', domain, '-silent'], inputFlag: null },
  uncover: { args: (domain) => ['-q', domain, '-silent'], inputFlag: null },
  dnsx: { args: () => ['-silent'], inputFlag: '-l' },
  httpx: { args: () => ['-silent', '-json', '-status-code', '-title', '-tech-detect'], inputFlag: '-l' },
  katana: { args: () => ['-silent', '-jsonl', '-depth', '3'], inputFlag: '-list' },
  nuclei: { args: () => ['-jsonl', '-severity', 'info,low,medium,high,critical'], inputFlag: '-l' },
};

function hostInScope(host, scopes = []) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  return scopes.some((raw) => {
    const s = String(raw || '').toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    return h === s || h.endsWith(`.${s}`);
  });
}

function urlInScope(value, scopes = []) {
  try { return hostInScope(new URL(value).hostname, scopes); } catch { return false; }
}

function filterScoped(lines, scopes = []) {
  return [...new Set((lines || []).map((x) => String(x).trim()).filter(Boolean))]
    .filter((line) => {
      try { return urlInScope(line, scopes); } catch { return hostInScope(line, scopes); }
    });
}

function outputLineInScope(line, scopes = []) {
  try {
    const parsed = JSON.parse(line);
    const candidates = [parsed.url, parsed.host, parsed.hostname, parsed['matched-at'], parsed['template-url']]
      .filter(Boolean);
    return candidates.length ? candidates.some((value) => urlInScope(value, scopes) || hostInScope(value, scopes)) : true;
  } catch {
    return filterScoped([line], scopes).length > 0;
  }
}

function filterToolOutput(text, scopes = []) {
  return String(text || '').split(/\r?\n/).filter((line) => line && outputLineInScope(line, scopes)).join('\n');
}

function plan(domain, scopes = [], opts = {}) {
  if (!domain || !scopes.length || !hostInScope(domain, scopes)) {
    return { ok: false, reason: 'a root domain and matching explicit scope are required', steps: [] };
  }
  const max = Math.max(1, Math.min(Number(opts.maxTargets || 5000), 50000));
  return {
    ok: true,
    domain,
    scopes,
    maxTargets: max,
    steps: [
      { id: 'subdomains', tool: 'subfinder', args: TOOLS.subfinder.args(domain), input: domain, output: 'subdomains.txt' },
      { id: 'discovery-enrichment', tool: 'uncover', args: TOOLS.uncover.args(domain), input: domain, output: 'uncover.txt' },
      { id: 'resolve', tool: 'dnsx', args: TOOLS.dnsx.args(), input: 'targets.txt', output: 'resolved.txt' },
      { id: 'live-http', tool: 'httpx', args: TOOLS.httpx.args(), input: 'resolved.txt', output: 'httpx.jsonl' },
      { id: 'crawl', tool: 'katana', args: TOOLS.katana.args(), input: 'httpx.jsonl', output: 'katana.jsonl' },
      { id: 'triage', tool: 'nuclei', args: TOOLS.nuclei.args(), input: 'katana.jsonl', output: 'nuclei.jsonl' },
    ],
  };
}

async function available(tool) {
  try {
    await exec('bash', ['-lc', `command -v ${tool}`], { timeout: 3000 });
    return true;
  } catch { return false; }
}

async function runStep(step, workdir, opts = {}) {
  const input = step.input && path.join(workdir, step.input);
  const output = path.join(workdir, step.output);
  const maxBytes = opts.maxBytes || 20 * 1024 * 1024;
  const inputArgs = input && fs.existsSync(input) && step.inputFlag ? [step.inputFlag, input] : [];
  const args = [...inputArgs, ...step.args];
  try {
    const result = await exec(step.tool, args, {
      cwd: workdir,
      timeout: opts.timeoutMs || 120000,
      maxBuffer: maxBytes,
    });
    const stdout = opts.scopes ? filterToolOutput(result.stdout || '', opts.scopes) : (result.stdout || '');
    fs.writeFileSync(output, stdout ? `${stdout}\n` : '', { mode: 0o600 });
    return { id: step.id, tool: step.tool, ok: true, output, bytes: fs.statSync(output).size };
  } catch (error) {
    return { id: step.id, tool: step.tool, ok: false, output, error: String(error.message || error).slice(0, 300) };
  }
}

async function run(domain, scopes, opts = {}) {
  const p = plan(domain, scopes, opts);
  if (!p.ok) return p;
  const workdir = opts.workdir || fs.mkdtempSync(path.join(os.tmpdir(), 'pentharness-recon-'));
  fs.mkdirSync(workdir, { recursive: true, mode: 0o700 });
  const tools = {};
  for (const step of p.steps) tools[step.tool] = await available(step.tool);
  const results = [];
  for (const step of p.steps) {
    if (!tools[step.tool]) {
      results.push({ id: step.id, tool: step.tool, ok: false, skipped: true, reason: 'tool not installed' });
      continue;
    }
    const result = await runStep(step, workdir, { ...opts, scopes: p.scopes });
    results.push(result);
    if (step.id === 'discovery-enrichment' || step.id === 'subdomains') {
      const discovered = [];
      for (const file of ['subdomains.txt', 'uncover.txt']) {
        const source = path.join(workdir, file);
        if (fs.existsSync(source)) discovered.push(...fs.readFileSync(source, 'utf8').split(/\r?\n/));
      }
      const scoped = filterScoped(discovered, p.scopes).slice(0, p.maxTargets);
      fs.writeFileSync(path.join(workdir, 'targets.txt'), `${scoped.join('\n')}${scoped.length ? '\n' : ''}`, { mode: 0o600 });
    }
  }
  return { ...p, workdir, tools, results };
}

module.exports = {
  TOOLS, hostInScope, urlInScope, filterScoped, filterToolOutput, plan, available, runStep, run,
};
