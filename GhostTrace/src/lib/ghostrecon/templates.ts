/** Modelos de vulnerabilidade por tipo de achado (herdado do Relatorio.txt / anotacao legado). */
export const SEV_TEMPLATES: Record<
  string,
  {
    title: string;
    desc: string;
    scenario: string;
    rec: string;
    tags: string;
    cvss?: string;
  }
> = {
  supabase_payment_bypass: {
    title:
      'Escalada de Privilégio de Pagamento — Ativação de Plano Premium sem Pagamento via PATCH Direto na API',
    desc: 'Foi identificada uma vulnerabilidade crítica de lógica de negócio: qualquer usuário autenticado pode ativar o plano premium da plataforma sem realizar qualquer pagamento, simplesmente enviando uma requisição PATCH direta ao endpoint /rest/v1/user_plans com os campos plan_type e premium_expires_at.',
    scenario:
      'Um atacante autenticado com uma conta gratuita pode:\n- Enviar uma única requisição PATCH ao endpoint de assinatura\n- Obter acesso premium imediato e permanente sem pagamento\n- Contornar todo o sistema de cobrança e monetização da plataforma\n- Compartilhar o método com outros usuários, comprometendo as receitas da organização',
    rec: 'Implementar política RLS restritiva com WITH CHECK que bloqueie alteração direta de plan_type e premium_expires_at.\nGerenciar mudanças de plano exclusivamente via função de servidor segura (Edge Function) com validação de webhook do Stripe.\nNunca confiar em campos de assinatura enviados diretamente pelo cliente.\nImplementar auditoria e alertas para mudanças na tabela user_plans.',
    tags: 'Web Application, Business Logic Flaw, Broken Access Control, Payment Bypass, Privilege Escalation',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N'
  },
  supabase_business_logic_study_records: {
    title:
      'Business Logic Flaw — Backend sem Validação de Input em Registros de Estudo (Injeção de Dados Falsos)',
    desc: 'Foi identificada uma falha de lógica de negócio no endpoint POST /rest/v1/study_records. O backend aceita e persiste registros de estudo com valores completamente irreais sem qualquer validação de consistência ou plausibilidade.',
    scenario:
      'Um usuário autenticado mal-intencionado pode:\n- Inserir registros de estudo com valores absurdos para dominar rankings artificialmente\n- Falsificar progresso e metas da plataforma sem estudo real\n- Manipular dados de analytics e dashboards\n- Prejudicar usuários legítimos cujas posições de ranking são afetadas',
    rec: 'Implementar validação server-side de todos os campos:\n- Limites máximos plausíveis para duration_seconds (máx. 43200s = 12h)\n- correct_count ≤ questions_count\n- record_date ≤ data atual\nImplementar limite diário de horas registradas por usuário.\nNunca confiar nos dados do cliente para cálculos de ranking.',
    tags: 'Web Application, Business Logic Flaw, Insufficient Input Validation, Data Integrity',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N'
  },
  supabase_idor_user_plans_anon: {
    title:
      'Broken Access Control — Exposição de Dados de Assinatura via API Supabase (user_plans)',
    desc: 'Foi identificado que a tabela user_plans do Supabase está acessível via API REST por qualquer usuário autenticado, expondo dados sensíveis de assinatura incluindo plan_type, premium_expires_at, stripe_customer_id e stripe_subscription_id.',
    scenario:
      'Um usuário autenticado mal-intencionado pode:\n- Enumerar e listar dados de assinatura de outros usuários da plataforma\n- Obter identificadores Stripe (customer_id, subscription_id) de terceiros\n- Mapear quais usuários possuem plano premium\n- Utilizar as informações para ataques adicionais (engenharia social, ataques ao Stripe)',
    rec: 'Implementar política RLS restritiva no Supabase para a tabela user_plans:\nCREATE POLICY "user sees own plans" ON user_plans FOR SELECT USING (auth.uid() = user_id);\nNunca expor identificadores de sistemas externos (Stripe IDs) desnecessariamente.\nRealizar auditoria completa das permissões de todas as tabelas.',
    tags: 'Web Application, Broken Access Control, IDOR, Information Disclosure, Misconfiguration',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
  },
  supabase_stripe_field_manipulation: {
    title:
      'Estado Inconsistente de Assinatura — Manipulação Direta de Campos do Stripe via API',
    desc: 'Foi identificado que usuários autenticados podem modificar diretamente campos relacionados à assinatura (stripe_subscription_id, stripe_customer_id, plan_type, premium_expires_at) via PATCH na API REST do Supabase, sem qualquer validação com o Stripe.',
    scenario:
      'Um atacante autenticado pode:\n- Corromper o estado de assinatura de sua própria conta\n- Manipular campos de pagamento para criar estados inválidos\n- Contornar verificações de integridade da assinatura\n- Usar como base para exploração adicional (Payment Bypass)',
    rec: 'Remover permissão de UPDATE direto em campos sensíveis (plan_type, premium_expires_at, stripe_*) via API pública.\nImplementar validação server-side obrigatória para quaisquer mudanças de plano.\nSincronizar estado de assinatura exclusivamente via webhook do Stripe.',
    tags: 'Web Application, Broken Access Control, Business Logic Flaw, Payment Security',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N'
  },
  supabase_missing_rate_limit: {
    title: 'Ausência de Rate Limiting e de Autenticação de Dois Fatores no Endpoint de Login',
    desc: 'Foi identificado que o endpoint de autenticação POST /auth/v1/token?grant_type=password não implementa qualquer mecanismo de limitação de tentativas (rate limiting) nem exige autenticação de dois fatores (2FA/MFA).',
    scenario:
      'Um atacante que possua o endereço de e-mail de um usuário pode:\n- Iterar automaticamente listas de senhas comuns contra o endpoint de login\n- Obter acesso à conta sem qualquer bloqueio ou alerta\n- Acessar dados de estudo, progresso, ranking e status de assinatura da vítima',
    rec: 'Implementar rate limiting (máx. 5-10 tentativas por IP/e-mail com backoff progressivo).\nHabilitar autenticação de dois fatores (TOTP/MFA) para todos os usuários.\nImplementar bloqueio temporário ou CAPTCHA após número definido de falhas.\nMonitorar tentativas consecutivas de login falhas.',
    tags: 'Web Application, Broken Authentication, Brute Force, Missing Rate Limiting',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
  }
};
