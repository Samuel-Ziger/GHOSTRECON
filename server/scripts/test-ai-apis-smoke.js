/**
 * Smoke test: verifica se Gemini e o segundo provider (OpenRouter ou Anthropic) respondem.
 * Uso: node server/scripts/test-ai-apis-smoke.js
 */
import '../load-env.js';
import { callGemini, callOpenRouter, callClaude, aiKeysConfigured } from '../modules/ai-dual-report.js';

const PING = 'Responde apenas com a palavra PONG em maiúsculas, sem mais texto.';

async function main() {
  const cap = aiKeysConfigured();
  console.log('Chaves detectadas:', { gemini: cap.gemini, openrouter: cap.openrouter, claude: cap.claude });

  const geminiModel = process.env.GHOSTRECON_GEMINI_MODEL?.trim() || 'gemini-2.5-flash';
  const openrouterModel = process.env.GHOSTRECON_OPENROUTER_MODEL?.trim() || 'anthropic/claude-3.5-sonnet';
  const claudeModel = process.env.GHOSTRECON_CLAUDE_MODEL?.trim() || 'claude-3-5-sonnet-20241022';

  const geminiKey = process.env.GEMINI_API_KEY?.trim() || process.env.GOOGLE_AI_API_KEY?.trim();
  const openrouterKey = process.env.OPENROUTER_API_KEY?.trim();
  const claudeKey = process.env.ANTHROPIC_API_KEY?.trim();

  let okAll = true;

  if (geminiKey) {
    process.stdout.write(`Gemini (${geminiModel})… `);
    try {
      const t = await callGemini(PING, geminiKey, geminiModel);
      const preview = String(t).replace(/\s+/g, ' ').slice(0, 120);
      console.log('OK —', preview || '(vazio)');
    } catch (e) {
      okAll = false;
      console.log('FALHOU —', e?.message || e);
    }
  } else {
    console.log('Gemini: omitido (sem chave)');
  }

  if (openrouterKey) {
    process.stdout.write(`OpenRouter (${openrouterModel})… `);
    try {
      const t = await callOpenRouter(PING, openrouterKey, openrouterModel, {
        systemPrompt: 'Segue instruções do utilizador de forma mínima.',
      });
      const preview = String(t).replace(/\s+/g, ' ').slice(0, 120);
      console.log('OK —', preview || '(vazio)');
    } catch (e) {
      okAll = false;
      console.log('FALHOU —', e?.message || e);
    }
  } else if (claudeKey) {
    process.stdout.write(`Claude Anthropic (${claudeModel})… `);
    try {
      const t = await callClaude(PING, claudeKey, claudeModel);
      const preview = String(t).replace(/\s+/g, ' ').slice(0, 120);
      console.log('OK —', preview || '(vazio)');
    } catch (e) {
      okAll = false;
      console.log('FALHOU —', e?.message || e);
    }
  } else {
    console.log('Segundo provider: omitido (sem OPENROUTER_API_KEY nem ANTHROPIC_API_KEY)');
  }

  if (!cap.any) {
    console.error('\nNenhuma chave IA configurada (Gemini + OpenRouter ou Anthropic).');
    process.exit(1);
  }

  process.exit(okAll ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
