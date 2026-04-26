import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getIntrospectionQuery, analyzeSchema, buildAliasDosProbe,
  buildFieldSuggestionProbe, probeGraphqlEndpoint,
} from '../modules/graphql-recon.mjs';

const introspection = {
  data: {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: { name: 'Mutation' },
      subscriptionType: null,
      types: [
        { name: 'Query', fields: [{ name: 'me' }, { name: 'posts' }] },
        { name: 'Mutation', fields: [{ name: 'createUser' }, { name: 'resetPassword' }] },
        { name: 'User', fields: [{ name: 'email' }, { name: 'password' }, { name: 'apiKey' }] },
      ],
    },
  },
};

test('graphql: getIntrospectionQuery devolve query padrão', () => {
  assert.ok(getIntrospectionQuery().includes('__schema'));
});

test('graphql: analyzeSchema captura mutations e queries', () => {
  const a = analyzeSchema(introspection);
  assert.equal(a.queryType, 'Query');
  assert.equal(a.mutationType, 'Mutation');
  assert.deepEqual(a.queries.sort(), ['me', 'posts']);
  assert.deepEqual(a.mutations.sort(), ['createUser', 'resetPassword']);
});

test('graphql: analyzeSchema detecta sensitive fields', () => {
  const a = analyzeSchema(introspection);
  assert.ok(a.sensitiveFields.find((f) => f.includes('password')));
  assert.ok(a.sensitiveFields.find((f) => f.includes('apiKey')));
});

test('graphql: buildAliasDosProbe gera N aliases', () => {
  const q = buildAliasDosProbe('createUser', 5);
  assert.equal((q.match(/createUser/g) || []).length, 5);
});

test('graphql: buildFieldSuggestionProbe inclui __type', () => {
  const q = buildFieldSuggestionProbe('Query');
  assert.ok(q.includes('__type'));
});

test('graphql: probeGraphqlEndpoint emite finding quando introspection ativo', async () => {
  const exec = async (q) => {
    if (q.includes('IntrospectionQuery')) return introspection;
    return null;
  };
  const r = await probeGraphqlEndpoint('https://api.acme.com/graphql', { executor: exec });
  assert.ok(r.findings.find((f) => f.category === 'graphql-introspection'));
  assert.ok(r.findings.find((f) => f.category === 'graphql-sensitive-field'));
});

test('graphql: probeGraphqlEndpoint detecta field-suggestion quando intro fechado', async () => {
  const exec = async (q) => {
    if (q.includes('IntrospectionQuery')) return { errors: [{ message: 'introspection disabled' }] };
    return { errors: [{ message: 'Cannot query field "aaa". Did you mean "user"?' }] };
  };
  const r = await probeGraphqlEndpoint('https://api.acme.com/graphql', { executor: exec });
  assert.ok(r.findings.find((f) => f.category === 'graphql-field-suggestion'));
});
