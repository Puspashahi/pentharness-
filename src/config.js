'use strict';

const fs = require('fs');
const { configFromEnv: aiConfigFromEnv } = require('./ai-client');

const DEFAULTS = Object.freeze({
  scope: [],
  execute: false,
  throttle: 0,
  maxRequests: 100,
  maxBytes: 10 * 1024 * 1024,
  maxTimeMs: 300000,
  maxConcurrency: 1,
  allowStateChange: false,
  approvalToken: null,
  approvalSecret: null,
  headers: {},
  ai: null,
});

function positiveInt(value, name, allowZero = false) {
  const n = Number(value);
  if (!Number.isInteger(n) || (allowZero ? n < 0 : n <= 0)) throw new Error(`${name} must be ${allowZero ? 'a non-negative' : 'a positive'} integer`);
  return n;
}

function readRecipe(file) {
  if (!file) return {};
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) {
    throw new Error(`config recipe could not be read: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('config recipe must be a JSON object');
  return parsed.pentharness || parsed.replay || parsed;
}

function parseHeaders(value) {
  if (!value) return {};
  if (typeof value === 'object' && !Array.isArray(value)) return { ...value };
  return String(value).split(/\n+/).filter(Boolean).reduce((out, line) => {
    const index = line.indexOf(':');
    if (index <= 0) throw new Error(`invalid header configuration: ${line}`);
    out[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    return out;
  }, {});
}

function resolve(options = {}, env = process.env) {
  const recipe = readRecipe(options.config || options.recipe);
  const merged = {
    ...DEFAULTS,
    ...recipe,
    ...(env.PENTHARNESS_SCOPE ? { scope: env.PENTHARNESS_SCOPE.split(',').filter(Boolean) } : {}),
    ...(env.PENTHARNESS_MAX_REQUESTS ? { maxRequests: env.PENTHARNESS_MAX_REQUESTS } : {}),
    ...(env.PENTHARNESS_MAX_BYTES ? { maxBytes: env.PENTHARNESS_MAX_BYTES } : {}),
    ...(env.PENTHARNESS_MAX_TIME_MS ? { maxTimeMs: env.PENTHARNESS_MAX_TIME_MS } : {}),
    ...(env.PENTHARNESS_MAX_CONCURRENCY ? { maxConcurrency: env.PENTHARNESS_MAX_CONCURRENCY } : {}),
    ...(env.PENTHARNESS_APPROVAL_TOKEN ? { approvalToken: env.PENTHARNESS_APPROVAL_TOKEN } : {}),
    ...(env.PENTHARNESS_APPROVAL_SECRET ? { approvalSecret: env.PENTHARNESS_APPROVAL_SECRET } : {}),
    ...(env.PENTHARNESS_HEADERS ? { headers: env.PENTHARNESS_HEADERS } : {}),
    ...(env.PENTHARNESS_AI_PROVIDER ? { ai: {
      provider: env.PENTHARNESS_AI_PROVIDER,
      model: env.PENTHARNESS_AI_MODEL,
      baseUrl: env.PENTHARNESS_AI_BASE_URL,
    } } : {}),
    ...options,
  };
  const config = {
    ...merged,
    scope: Array.isArray(merged.scope) ? merged.scope.map(String).filter(Boolean) : [String(merged.scope)].filter(Boolean),
    headers: parseHeaders(merged.headers),
    throttle: positiveInt(merged.throttle, 'throttle', true),
    maxRequests: positiveInt(merged.maxRequests, 'maxRequests'),
    maxBytes: positiveInt(merged.maxBytes, 'maxBytes'),
    maxTimeMs: positiveInt(merged.maxTimeMs, 'maxTimeMs'),
    maxConcurrency: positiveInt(merged.maxConcurrency, 'maxConcurrency'),
    execute: merged.execute === true,
    allowStateChange: merged.allowStateChange === true,
  };
  if (config.execute && !config.scope.length) throw new Error('execute requires explicit scope');
  if (config.allowStateChange && (!config.approvalToken || !config.approvalSecret)) {
    throw new Error('allowStateChange requires approvalToken and approvalSecret');
  }
  if (config.approvalToken && !config.approvalSecret) throw new Error('approvalToken requires approvalSecret');
  if (merged.ai) {
    config.ai = aiConfigFromEnv(env, typeof merged.ai === 'object' ? merged.ai : { provider: merged.ai });
  }
  return Object.freeze(config);
}

function publicConfig(config) {
  return {
    scope: config.scope,
    execute: config.execute,
    throttle: config.throttle,
    maxRequests: config.maxRequests,
    maxBytes: config.maxBytes,
    maxTimeMs: config.maxTimeMs,
    maxConcurrency: config.maxConcurrency,
    allowStateChange: config.allowStateChange,
    approvalConfigured: Boolean(config.approvalToken && config.approvalSecret),
    headers: Object.keys(config.headers),
    ai: config.ai ? {
      provider: config.ai.provider,
      baseUrl: config.ai.baseUrl,
      model: config.ai.model,
      apiKeyConfigured: Boolean(config.ai.apiKey),
    } : null,
  };
}

module.exports = { DEFAULTS, resolve, readRecipe, publicConfig };
