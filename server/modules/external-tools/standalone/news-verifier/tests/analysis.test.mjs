import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analisarConteudo,
  analisarDominio,
  analisarURLAvancada,
  calcVeredicto,
  dominioEstaNaWhitelist,
} from '../script.js';

test('faixas de veredito preservam os cinco níveis', () => {
  assert.equal(calcVeredicto(7).tipo, 'safe');
  assert.equal(calcVeredicto(3).titulo, '⚠ Requer Atenção');
  assert.equal(calcVeredicto(0).titulo, '⚠ Conteúdo Questionável');
  assert.equal(calcVeredicto(-4).tipo, 'suspicious');
  assert.equal(calcVeredicto(-5).tipo, 'danger');
});

test('whitelist aceita subdomínio real, mas não sufixo controlado', () => {
  assert.equal(dominioEstaNaWhitelist('g1.globo.com'), true);
  assert.equal(dominioEstaNaWhitelist('noticias.g1.globo.com'), true);
  assert.equal(dominioEstaNaWhitelist('g1.globo.com.evil.test'), false);
});

test('domínios confiáveis e de desinformação mantêm sinais opostos', () => {
  const trusted = analisarDominio(new URL('https://g1.globo.com/politica'));
  const fake = analisarDominio(new URL('http://verdadeoculta.com/noticia'));
  assert.ok(trusted.score >= 8);
  assert.ok(fake.score <= -6);
});

test('análise reconhece encurtador e download executável como riscos', () => {
  const shortener = analisarDominio(new URL('https://bit.ly/oferta'));
  const factors = analisarURLAvancada(new URL('https://exemplo.test/oferta.zip'));
  assert.ok(shortener.fatores.some((factor) => factor.texto.toLowerCase().includes('encurtado')));
  assert.ok(factors.some((factor) => factor.texto.toLowerCase().includes('executável')));
});

test('orquestração funciona sem DOM e retorna motivos do veredito', () => {
  const result = analisarConteudo(new URL('https://g1.globo.com/noticia'));
  assert.equal(result.veredicto.tipo, 'safe');
  assert.match(result.motivos[0], /g1\.globo\.com/);
  assert.ok(result.motivos.some((reason) => reason.includes('Pontuação')));
});
