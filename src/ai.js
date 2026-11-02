'use strict';

const PRESETS = Object.freeze({
  nvidia: { baseUrl: 'https://integrate.api.nvidia.com/v1', keyEnv: 'NVIDIA_API_KEY', model: 'meta/llama-3.1-8b-instruct' },
  xai: { baseUrl: 'https://api.x.ai/v1', keyEnv: 'XAI_API_KEY', model: 'grok-3-mini' },
  grok: { baseUrl: 'https://api.x.ai/v1', keyEnv: 'XAI_API_KEY', model: 'grok-3-mini' },
  openai: { baseUrl: 'https://api.openai.com/v1', keyEnv: 'OPENAI_API_KEY', model: 'gpt-4o-mini' },
  openrouter: { baseUrl: 'https://openrouter.ai/api/v1', keyEnv: 'OPENROUTER_API_KEY', model: 'openai/gpt-4o-mini' },
  groq: { baseUrl: 'https://api.groq.com/openai/v1', keyEnv: 'GROQ_API_KEY', model: 'llama-3.1-8b-instant' },
  together: { baseUrl: 'https://api.together.xyz/v1', keyEnv: 'TOGETHER_API_KEY', model: 'meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo' },
  deepseek: { baseUrl: 'https://api.deepseek.com/v1', keyEnv: 'DEEPSEEK_API_KEY', model: 'deepseek-chat' },
  copilot: { baseUrl: 'https://api.githubcopilot.com', keyEnv: 'GITHUB_TOKEN', model: 'gpt-4o-mini' },
  ollama: { baseUrl: 'http://127.0.0.1:11434/v1', keyEnv: null, model: 'llama3.2' },
  custom: { baseUrl: null, keyEnv: 'PENTHARNESS_AI_API_KEY', model: null },
});

function providerConfig(options = {}, env = process.env) {
  const name = String(options.provider || env.PENTHARNESS_AI_PROVIDER || '').toLowerCase();
  if (!name) throw new Error('AI provider is required; set --ai-provider or PENTHARNESS_AI_PROVIDER');
  const preset = PRESETS[name];
  if (!preset) throw new Error(`unsupported AI provider: ${name}`);
  const baseUrl = options.baseUrl || env.PENTHARNESS_AI_BASE_URL || preset.baseUrl;
  if (!baseUrl) throw new Error(`${name} requires --ai-base-url or PENTHARNESS_AI_BASE_URL`);
  const keyEnv = options.keyEnv || env.PENTHARNESS_AI_KEY_ENV || preset.keyEnv;
  const key = options.apiKey || (keyEnv ? env[keyEnv] : '') || '';
  if (name !== 'ollama' && !key) throw new Error(`missing AI API key; set ${keyEnv || 'PENTHARNESS_AI_API_KEY'}`);
  return {
    provider: name,
    baseUrl: baseUrl.replace(/\/+$/, ''),
    model: options.model || env.PENTHARNESS_AI_MODEL || preset.model,
    key,
    timeoutMs: Number(options.timeoutMs || env.PENTHARNESS_AI_TIMEOUT_MS || 60000),
    maxTokens: Number(options.maxTokens || env.PENTHARNESS_AI_MAX_TOKENS || 1200),
  };
}

function redact(value) {
  return String(value)
    .replace(/\b(sk|xai|nvapi|gsk|ghp|github_pat)_[A-Za-z0-9._-]{12,}\b/g, '[REDACTED_TOKEN]')
    .replace(/(authorization\s*:\s*bearer\s+)[^\s,}]+/ig, '$1[REDACTED_TOKEN]')
    .replace(/(["']?(?:password|passwd|secret|api[_-]?key|token)["']?\s*[:=]\s*)["']?[^"',}\s]+/ig, '$1[REDACTED]');
}

function extractJson(text) {
  const raw = String(text || '').trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  try { return JSON.parse(raw); } catch {}
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('AI response did not contain a JSON object');
  try { return JSON.parse(match[0]); } catch (error) { throw new Error(`AI response JSON is invalid: ${error.message}`); }
}

async function complete(options, messages, fetchImpl = fetch) {
  const cfg = providerConfig(options, options.env || process.env);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    const response = await fetchImpl(`${cfg.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(cfg.key ? { authorization: `Bearer ${cfg.key}` } : {}),
        ...(cfg.provider === 'openrouter' ? { 'HTTP-Referer': 'https://github.com/Puspashahi/pentharness-' } : {}),
      },
      body: JSON.stringify({ model: cfg.model, messages, temperature: 0, max_tokens: cfg.maxTokens }),
      signal: controller.signal,
    });
    const body = await response.text();
    if (!response.ok) throw new Error(`AI provider ${cfg.provider} returned HTTP ${response.status}: ${redact(body).slice(0, 500)}`);
    let parsed;
    try { parsed = JSON.parse(body); } catch (error) { throw new Error(`AI provider returned invalid JSON: ${error.message}`); }
    const content = parsed.choices?.[0]?.message?.content;
    if (!content) throw new Error('AI provider response did not contain choices[0].message.content');
    return { provider: cfg.provider, model: cfg.model, content, usage: parsed.usage || null };
  } finally {
    clearTimeout(timer);
  }
}

async function triageQueue(queue, options = {}, fetchImpl = fetch) {
  if (!Array.isArray(queue)) throw new TypeError('AI queue must be an array');
  const bounded = queue.filter((item) => item && item.kind === 'lead').slice(0, Number(options.limit || 10));
  const system = [
    'You are a security triage assistant. Analyze only the supplied evidence.',
    'Return one JSON object with an answers property keyed by lead id.',
    'Each answer may contain severity, impact, by_design, reproduction, proof, and title.',
    'Never invent evidence, credentials, or successful exploitation. If uncertain, say so in impact and leave proof unchanged.',
  ].join(' ');
  const user = redact(JSON.stringify(bounded));
  const result = await complete(options, [{ role: 'system', content: system }, {
    role: 'user',
    content: `Review this bounded pentest queue and return JSON only:\n${user}`,
  }], fetchImpl);
  const parsed = extractJson(result.content);
  return { ...result, answers: parsed.answers && typeof parsed.answers === 'object' ? parsed.answers : {} };
}

module.exports = { PRESETS, providerConfig, redact, extractJson, complete, triageQueue };
