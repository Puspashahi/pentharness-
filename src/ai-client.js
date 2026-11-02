'use strict';

const PRESETS = Object.freeze({
  openai: { baseUrl: 'https://api.openai.com/v1', envKey: 'OPENAI_API_KEY' },
  nvidia: { baseUrl: 'https://integrate.api.nvidia.com/v1', envKey: 'NVIDIA_API_KEY' },
  grok: { baseUrl: 'https://api.x.ai/v1', envKey: 'XAI_API_KEY' },
  xai: { baseUrl: 'https://api.x.ai/v1', envKey: 'XAI_API_KEY' },
  openrouter: { baseUrl: 'https://openrouter.ai/api/v1', envKey: 'OPENROUTER_API_KEY' },
  groq: { baseUrl: 'https://api.groq.com/openai/v1', envKey: 'GROQ_API_KEY' },
  mistral: { baseUrl: 'https://api.mistral.ai/v1', envKey: 'MISTRAL_API_KEY' },
  together: { baseUrl: 'https://api.together.xyz/v1', envKey: 'TOGETHER_API_KEY' },
  github: { baseUrl: 'https://models.inference.ai.azure.com', envKey: 'GITHUB_TOKEN' },
  'github-models': { baseUrl: 'https://models.inference.ai.azure.com', envKey: 'GITHUB_TOKEN' },
  ollama: { baseUrl: 'http://127.0.0.1:11434/v1', envKey: null },
  lmstudio: { baseUrl: 'http://127.0.0.1:1234/v1', envKey: null },
});

const SECRET = /(?:api[_-]?key|token|secret|password|authorization|cookie)\s*[:=]\s*(['"]?)[^\s,'"}]+/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi;
const MAX_CONTEXT = 64 * 1024;

function normalizeProvider(value) {
  const provider = String(value || '').trim().toLowerCase();
  if (provider === 'copilot') return 'github-models';
  return provider;
}

function redact(value) {
  return String(value || '')
    .replace(BEARER, 'Bearer [REDACTED]')
    .replace(SECRET, (match, quote) => match.slice(0, match.indexOf(quote) >= 0 ? match.indexOf(quote) + 1 : match.length) + '[REDACTED]');
}

function configFromEnv(env = process.env, options = {}) {
  const provider = normalizeProvider(options.provider || env.PENTHARNESS_AI_PROVIDER);
  if (!provider) return null;
  const preset = PRESETS[provider];
  if (!preset && !options.baseUrl && !env.PENTHARNESS_AI_BASE_URL) {
    throw new Error(`unsupported AI provider "${provider}"; use a known preset or provide baseUrl`);
  }
  const baseUrl = String(options.baseUrl || env.PENTHARNESS_AI_BASE_URL || preset.baseUrl).replace(/\/+$/, '');
  const apiKey = options.apiKey || (preset && preset.envKey ? env[preset.envKey] : null) || env.PENTHARNESS_AI_API_KEY || '';
  const model = options.model || env.PENTHARNESS_AI_MODEL;
  if (!model) throw new Error('AI model is required (set PENTHARNESS_AI_MODEL or pass model)');
  return Object.freeze({
    provider,
    baseUrl,
    apiKey: String(apiKey),
    model: String(model),
    timeoutMs: Number(options.timeoutMs || env.PENTHARNESS_AI_TIMEOUT_MS || 30000),
    maxTokens: Number(options.maxTokens || env.PENTHARNESS_AI_MAX_TOKENS || 1200),
    organization: options.organization || env.PENTHARNESS_AI_ORGANIZATION || null,
  });
}

class AIClient {
  constructor(config, fetchImpl = globalThis.fetch) {
    if (!config || !config.baseUrl || !config.model) throw new TypeError('AI client requires baseUrl and model');
    if (typeof fetchImpl !== 'function') throw new TypeError('AI client requires fetch');
    this.config = config;
    this.fetch = fetchImpl;
  }

  async chat(messages, options = {}) {
    if (!Array.isArray(messages) || !messages.length) throw new TypeError('AI messages must be a non-empty array');
    const body = {
      model: options.model || this.config.model,
      messages: messages.map((message) => ({
        role: String(message.role || 'user'),
        content: redact(String(message.content || '')).slice(0, MAX_CONTEXT),
      })),
      temperature: options.temperature ?? 0,
      max_tokens: options.maxTokens || this.config.maxTokens,
    };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs || this.config.timeoutMs);
    try {
      const headers = { 'content-type': 'application/json' };
      if (this.config.apiKey) headers.authorization = `Bearer ${this.config.apiKey}`;
      if (this.config.organization) headers['openai-organization'] = this.config.organization;
      const response = await this.fetch(`${this.config.baseUrl}/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await response.text();
      let payload;
      try { payload = JSON.parse(text); } catch { payload = null; }
      if (!response.ok) throw new Error(`AI provider ${response.status}: ${redact(payload?.error?.message || text).slice(0, 500)}`);
      const content = payload?.choices?.[0]?.message?.content;
      if (typeof content !== 'string') throw new Error('AI provider returned no assistant content');
      return {
        provider: this.config.provider,
        model: body.model,
        text: content,
        usage: payload.usage || null,
        requestId: response.headers?.get?.('x-request-id') || null,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async advise(instruction, context = {}) {
    const bounded = redact(JSON.stringify(context)).slice(0, MAX_CONTEXT);
    return this.chat([
      {
        role: 'system',
        content: 'You are an advisory security-testing assistant. Propose bounded hypotheses, mutations, prioritization, or explanations. Never declare a vulnerability or override scope, approval, proof, or deterministic validators. Return concise JSON when requested.',
      },
      { role: 'user', content: `${instruction}\n\nBounded context:\n${bounded}` },
    ]);
  }
}

function publicConfig(config) {
  return {
    provider: config.provider,
    baseUrl: config.baseUrl,
    model: config.model,
    timeoutMs: config.timeoutMs,
    maxTokens: config.maxTokens,
    organizationConfigured: Boolean(config.organization),
    apiKeyConfigured: Boolean(config.apiKey),
  };
}

module.exports = { PRESETS, AIClient, configFromEnv, publicConfig, redact, normalizeProvider };
