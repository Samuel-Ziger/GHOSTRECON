import test from 'node:test';
import assert from 'node:assert/strict';
import { responseLooksLikeSqlError } from '../modules/verify.js';

test('responseLooksLikeSqlError: sintaxe MySQL', () => {
  assert.ok(responseLooksLikeSqlError('You have an error in your SQL syntax near \'1\\\'\' at line 1'));
});

test('responseLooksLikeSqlError: mysqli', () => {
  assert.ok(responseLooksLikeSqlError('Warning: mysqli_query(): (HY000/1064): You have an error in your SQL syntax'));
});

test('responseLooksLikeSqlError: aspas não fechadas', () => {
  assert.ok(responseLooksLikeSqlError('Unclosed quotation mark after the character string'));
});

test('responseLooksLikeSqlError: HTML normal não dispara', () => {
  assert.ok(!responseLooksLikeSqlError('<html><body>Welcome id=1 product page</body></html>'));
});
