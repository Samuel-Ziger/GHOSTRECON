import fs from 'node:fs/promises';
import path from 'node:path';

export const HACKBOT_AGENTS = Object.freeze([
  {
    name: 'orchestrator',
    label: 'Orquestrador',
    role: 'Planeja, delega em paralelo e consolida a resposta.',
    tools: ['plan', 'spawn_researchers', 'analyse_sarif', 'analyse_document', 'ask_tutor', 'ask_remote_agent'],
  },
  {
    name: 'researcher',
    label: 'Pesquisador',
    role: 'Pesquisa uma pergunta focada e entrega evidências e fontes.',
    tools: ['web_search', 'fetch_page', 'cwe_lookup'],
  },
  {
    name: 'analyst',
    label: 'Analista SARIF',
    role: 'Classifica achados SARIF, prioridade, CWE e correção.',
    tools: ['load_sarif', 'sarif_summary', 'sarif_findings', 'cwe_lookup'],
  },
  {
    name: 'document_analyst',
    label: 'Analista de documentos',
    role: 'Revisa código, configuração, logs, JSON e resultados de scanners.',
    tools: ['load_document', 'read_document', 'search_document', 'cwe_lookup'],
  },
  {
    name: 'tutor',
    label: 'Tutor',
    role: 'Explica conceitos de segurança sem ferramentas externas.',
    tools: [],
  },
]);

export const HACKBOT_MODEL_CATALOG = Object.freeze([
  {
    id: 'codex-cli',
    label: 'Codex CLI · MCPs selecionáveis',
    model: 'gpt-daybreak-blue-latest',
    base_url: null,
    api_key_env: 'CODEX_LOGIN',
    provider: 'codex-cli',
    source: 'codex-cli',
    kind: 'local-subscription',
    status: 'available-when-codex-is-logged-in',
    recommended_for: ['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'],
  },
  {
    id: 'openai-default',
    label: 'OpenAI · padrão HackBot',
    model: 'gpt-5.6-luna',
    base_url: 'https://api.openai.com/v1',
    api_key_env: 'OPENAI_API_KEY',
    kind: 'remote',
    status: 'available-when-key-is-configured',
    recommended_for: ['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'],
  },
  {
    id: 'openrouter-auto',
    label: 'OpenRouter · seleção automática',
    model: 'openrouter/auto',
    base_url: 'https://openrouter.ai/api/v1',
    api_key_env: 'OPENROUTER_API_KEY',
    provider: 'openai',
    source: 'direct',
    kind: 'remote',
    status: 'available-when-key-is-configured',
    recommended_for: ['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'],
  },
  {
    id: 'claude-sonnet-openrouter',
    label: 'Claude Sonnet · via OpenRouter',
    model: 'anthropic/claude-sonnet-4.5',
    base_url: 'https://openrouter.ai/api/v1',
    api_key_env: 'OPENROUTER_API_KEY',
    provider: 'openai',
    source: 'direct',
    kind: 'remote',
    status: 'available-when-key-is-configured',
    recommended_for: ['orchestrator', 'analyst', 'document_analyst'],
  },
  {
    id: 'deepseek-flash',
    label: 'DeepSeek · Flash',
    model: 'deepseek-flash',
    base_url: 'https://api.deepseek.com',
    api_key_env: 'DEEPSEEK_API_KEY',
    provider: 'openai',
    source: 'direct',
    kind: 'remote',
    status: 'available-when-key-is-configured',
    recommended_for: ['researcher', 'analyst', 'document_analyst', 'tutor'],
  },
  {
    id: 'kimi-k2-5',
    label: 'Kimi / Moonshot · K2.5',
    model: 'kimi-k2.5',
    base_url: 'https://api.moonshot.ai/v1',
    api_key_env: 'MOONSHOT_API_KEY',
    provider: 'openai',
    source: 'direct',
    kind: 'remote',
    status: 'available-when-key-is-configured',
    recommended_for: ['orchestrator', 'researcher', 'document_analyst'],
  },
  {
    id: 'glm-4-6',
    label: 'GLM / Z.AI · GLM-4.6',
    model: 'glm-4.6',
    base_url: 'https://api.z.ai/api/paas/v4',
    api_key_env: 'ZHIPU_API_KEY',
    provider: 'openai',
    source: 'direct',
    kind: 'remote',
    status: 'available-when-key-is-configured',
    recommended_for: ['orchestrator', 'researcher', 'analyst'],
  },
  {
    id: 'mistral-large',
    label: 'Mistral · Large',
    model: 'mistral-large-latest',
    base_url: 'https://api.mistral.ai/v1',
    api_key_env: 'MISTRAL_API_KEY',
    provider: 'openai',
    source: 'direct',
    kind: 'remote',
    status: 'available-when-key-is-configured',
    recommended_for: ['researcher', 'analyst', 'document_analyst'],
  },
  {
    id: 'qwen3-4b-instruct-2507-q4km',
    label: 'Qwen3-4B-Instruct-2507 · Q4_K_M',
    model: 'Qwen3-4B-Instruct-2507',
    base_url: 'http://127.0.0.1:11434/v1',
    api_key_env: 'LOCAL_LLM_API_KEY',
    kind: 'local-candidate',
    status: 'not-downloaded-by-ghostrecon',
    recommended_for: ['orchestrator', 'tutor'],
  },
  {
    id: 'qwen3-5-2b-q4km',
    label: 'Qwen3.5-2B · Q4_K_M',
    model: 'Qwen3.5-2B',
    base_url: 'http://127.0.0.1:11434/v1',
    api_key_env: 'LOCAL_LLM_API_KEY',
    kind: 'local-candidate',
    status: 'not-downloaded-by-ghostrecon',
    recommended_for: ['researcher', 'tutor'],
  },
  {
    id: 'qwen2-5-coder-1-5b-q4km',
    label: 'Qwen2.5-Coder-1.5B · Q4_K_M',
    model: 'Qwen2.5-Coder-1.5B',
    base_url: 'http://127.0.0.1:11434/v1',
    api_key_env: 'LOCAL_LLM_API_KEY',
    kind: 'local-candidate',
    status: 'not-downloaded-by-ghostrecon',
    recommended_for: ['document_analyst'],
  },
  {
    id: 'whiterabbitneo-2-5-qwen-coder-7b-q4km',
    label: 'WhiteRabbitNeo-2.5-Qwen-Coder-7B · Q4_K_M',
    model: 'WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B',
    base_url: 'http://127.0.0.1:11434/v1',
    api_key_env: 'LOCAL_LLM_API_KEY',
    kind: 'local-candidate',
    status: 'not-downloaded-by-ghostrecon',
    recommended_for: ['researcher', 'analyst'],
  },
  {
    id: 'foundation-sec-1-1-8b-q4km',
    label: 'Foundation-Sec-1.1-8B-Instruct · Q4_K_M',
    model: 'Foundation-Sec-1.1-8B-Instruct',
    base_url: 'http://127.0.0.1:11434/v1',
    api_key_env: 'LOCAL_LLM_API_KEY',
    kind: 'local-candidate',
    status: 'not-downloaded-by-ghostrecon',
    recommended_for: ['analyst', 'document_analyst'],
  },
]);

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;
const MODEL_NAME = /^[^\s\0][^\0]{0,199}$/;

function defaultBinding() {
  return {
    model: 'gpt-5.6-luna',
    base_url: 'https://api.openai.com/v1',
    api_key_env: 'OPENAI_API_KEY',
    source: 'direct',
    profile_id: null,
    provider: 'openai',
    mcp_servers: [],
  };
}

export function hackbotRuntimePaths(root) {
  const dir = path.join(root, '.runtime', 'hackbot');
  return {
    dir,
    bindings: path.join(dir, 'model-bindings.json'),
    conversations: path.join(dir, 'conversations.json'),
    serviceToken: path.join(dir, 'service-token'),
    data: path.join(dir, 'data'),
  };
}

function normalizeBaseUrl(value) {
  const text = String(value || '').trim().slice(0, 2_000);
  if (!text) return null;
  let parsed;
  try { parsed = new URL(text); } catch { throw new Error('base_url de modelo inválida'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('base_url deve usar HTTP ou HTTPS');
  const loopback = ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(parsed.hostname.toLowerCase());
  if (parsed.protocol === 'http:' && !loopback) {
    throw new Error('HTTP sem TLS só é aceito para providers locais em loopback');
  }
  parsed.username = '';
  parsed.password = '';
  return parsed.toString().replace(/\/$/, '');
}

export function normalizeHackbotBindings(input) {
  const source = input?.bindings && typeof input.bindings === 'object' ? input.bindings : input;
  const bindings = {};
  for (const agent of HACKBOT_AGENTS) {
    const row = source?.[agent.name] || defaultBinding();
    const model = String(row.model || '').trim();
    const bindingSource = String(row.source || 'direct').trim().toLowerCase();
    if (!['direct', 'artex', 'codex-cli'].includes(bindingSource)) throw new Error(`origem de modelo inválida para ${agent.name}`);
    const profileId = row.profile_id == null || row.profile_id === '' ? null : Number(row.profile_id);
    if (bindingSource === 'artex' && (!Number.isSafeInteger(profileId) || profileId <= 0)) {
      throw new Error(`perfil GhostIA inválido para ${agent.name}`);
    }
    const apiKeyEnv = String(row.api_key_env || 'OPENAI_API_KEY').trim().toUpperCase();
    if (!MODEL_NAME.test(model)) throw new Error(`modelo inválido para ${agent.name}`);
    if (bindingSource === 'direct' && !ENV_NAME.test(apiKeyEnv)) throw new Error(`variável de chave inválida para ${agent.name}`);
    const mcpServers = [];
    for (const raw of Array.isArray(row.mcp_servers) ? row.mcp_servers : []) {
      const id = String(raw || '').trim();
      if (!/^(?:codex:)?[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(id)) throw new Error(`MCP inválido para ${agent.name}`);
      if (!mcpServers.includes(id)) mcpServers.push(id);
      if (mcpServers.length > 16) throw new Error(`muitos MCPs para ${agent.name}`);
    }
    if (bindingSource !== 'codex-cli' && mcpServers.length) {
      throw new Error(`MCPs pessoais só podem ser vinculados ao Codex CLI (${agent.name})`);
    }
    bindings[agent.name] = {
      model,
      base_url: bindingSource === 'direct' ? normalizeBaseUrl(row.base_url) : null,
      api_key_env: bindingSource === 'artex' ? 'ARTEX_INTERNAL_SESSION' : bindingSource === 'codex-cli' ? 'CODEX_LOGIN' : apiKeyEnv,
      source: bindingSource,
      profile_id: bindingSource === 'artex' ? profileId : null,
      provider: String(row.provider || 'openai').trim().toLowerCase().slice(0, 40) || 'openai',
      mcp_servers: bindingSource === 'codex-cli' ? mcpServers : [],
    };
  }
  return { version: 3, updated_at: new Date().toISOString(), bindings };
}

export async function readHackbotBindings(root) {
  const file = hackbotRuntimePaths(root).bindings;
  try {
    const raw = await fs.readFile(file, 'utf8');
    return normalizeHackbotBindings(JSON.parse(raw));
  } catch (error) {
    if (error?.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
    return normalizeHackbotBindings({});
  }
}

export async function writeHackbotBindings(root, input) {
  const config = normalizeHackbotBindings(input);
  const { dir, bindings } = hackbotRuntimePaths(root);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const temporary = `${bindings}.${process.pid}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await fs.rename(temporary, bindings);
  await fs.chmod(bindings, 0o600).catch(() => {});
  return config;
}

export function publicHackbotBindings(config, env = process.env) {
  const bindings = {};
  for (const [agent, row] of Object.entries(config.bindings || {})) {
    bindings[agent] = {
      ...row,
      api_key_present: row.source === 'artex' || row.source === 'codex-cli' ? false : Boolean(env[row.api_key_env]),
      credential_source: row.source === 'artex' ? 'ghostia-profile' : row.source === 'codex-cli' ? 'codex-login' : 'environment',
      configured: (row.source === 'artex' && Number.isSafeInteger(row.profile_id) && row.profile_id > 0)
        || row.source === 'codex-cli'
        || Boolean(env[row.api_key_env])
        || /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::|\/|$)/i.test(String(row.base_url || '')),
    };
  }
  return { ...config, bindings };
}
