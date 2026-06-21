import { enrichTechWithVersions } from './tech-versions.js';

/**
 * Detecção heurística de stack (headers + snippet HTML/JS) + versões em banner/meta.
 */
export function detectTech(headers, bodySnippet) {
  const list = [];
  const server = headers.get('server');
  if (server) list.push(`Server: ${server}`);
  const xp = headers.get('x-powered-by');
  if (xp) list.push(`X-Powered-By: ${xp}`);
  const gen = headers.get('x-generator');
  if (gen) list.push(`X-Generator: ${gen}`);
  const asp = headers.get('x-aspnet-version') || headers.get('x-aspnetmvc-version');
  if (asp) list.push(`ASP.NET/${asp}`);
  if (headers.get('x-nextjs-cache') || headers.get('x-nextjs-matched-path')) list.push('Next.js (headers)');
  if (headers.get('x-vercel-id')) list.push('Vercel');
  if (headers.get('x-envoy-upstream-service-time')) list.push('Envoy');
  if (headers.get('x-drupal-cache') || headers.get('x-drupal-dynamic-cache')) list.push('Drupal');
  if (headers.get('x-litespeed-cache')) list.push('LiteSpeed');
  const cf = headers.get('cf-ray');
  if (cf) list.push('Cloudflare (CF-Ray presente)');

  const lower = bodySnippet.slice(0, 12000).toLowerCase();
  const hints = [
    ['wp-content', 'WordPress'],
    ['react', 'React (hint)'],
    ['__next', 'Next.js (hint)'],
    ['nuxt', 'Nuxt (hint)'],
    ['angular', 'Angular (hint)'],
    ['laravel', 'Laravel (hint)'],
    ['django', 'Django (hint)'],
    ['rails', 'Ruby on Rails (hint)'],
    ['spring', 'Spring (hint)'],
    ['/wp-includes/', 'WordPress'],
    ['content="drupal', 'Drupal'],
    ['joomla', 'Joomla'],
    ['grafana/public/build', 'Grafana'],
    ['keycloak', 'Keycloak'],
    ['swagger-ui', 'Swagger UI'],
    ['redoc', 'ReDoc'],
    ['vite', 'Vite (hint)'],
    ['sveltekit', 'SvelteKit (hint)'],
    ['data-reactroot', 'React (hint)'],
    ['id="__next"', 'Next.js (hint)'],
    ['id="__nuxt"', 'Nuxt (hint)'],
  ];
  for (const [needle, label] of hints) {
    if (lower.includes(needle) && !list.some((l) => l.includes(label.split(' ')[0]))) list.push(label);
  }

  const base = [...new Set(list)];
  return enrichTechWithVersions(headers, bodySnippet.slice(0, 50000), base);
}
