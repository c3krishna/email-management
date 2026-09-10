/**
 * Central AI / Ollama model defaults for email security.
 *
 * Models below match what is already pulled on miniai.worktual.tech
 * (verified via /api/tags).
 *
 * Primary — spam / phishing / threat / validation: qwen2.5:14b-instruct
 * Fast   — Postfix milter hot-path:               qwen2.5:7b-instruct
 * Deep   — orchestration / BEC / vuln reasoning:  deepseek-r1:32b
 * Pattern — secondary assist / UI:                gemma3:12b
 *
 * Override via env:
 *   OLLAMA_URL, AI_MODEL, AI_MODEL_FAST, AI_MODEL_DEEP, AI_MODEL_PATTERN
 */

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://miniai.worktual.tech:11434';

const AI_MODEL = process.env.AI_MODEL || 'qwen2.5:14b-instruct-q4_K_M';
const AI_MODEL_FAST = process.env.AI_MODEL_FAST || 'qwen2.5:7b-instruct-q4_K_M';
const AI_MODEL_DEEP = process.env.AI_MODEL_DEEP || 'deepseek-r1:32b';
const AI_MODEL_PATTERN = process.env.AI_MODEL_PATTERN || 'gemma3:12b';

const AI_MODELS = {
  primary: AI_MODEL,
  fast: AI_MODEL_FAST,
  deep: AI_MODEL_DEEP,
  pattern: AI_MODEL_PATTERN,
  label: 'Qwen2.5 14B',
  display: `Qwen2.5 14B · deep ${AI_MODEL_DEEP}`,
};

module.exports = {
  OLLAMA_URL,
  AI_MODEL,
  AI_MODEL_FAST,
  AI_MODEL_DEEP,
  AI_MODEL_PATTERN,
  AI_MODELS,
};
