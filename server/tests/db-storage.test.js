import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

describe('db storage mode', () => {
  it('GHOSTRECON_STORAGE=sqlite força modo local', async () => {
    const prev = process.env.GHOSTRECON_STORAGE;
    const prevUrl = process.env.DATABASE_URL;
    process.env.GHOSTRECON_STORAGE = 'sqlite';
    process.env.DATABASE_URL = 'postgresql://user:pass@127.0.0.1:5432/test';
    const db = await import('../modules/db.js');
    assert.equal(db.resolveStorageMode(), 'sqlite');
    assert.equal(db.usePostgresPrimary(), false);
    assert.match(db.storageLabel(), /SQLite/);
    process.env.GHOSTRECON_STORAGE = prev;
    process.env.DATABASE_URL = prevUrl;
  });

  it('sem GHOSTRECON_STORAGE usa postgres quando DATABASE_URL existe', async () => {
    const prev = process.env.GHOSTRECON_STORAGE;
    const prevUrl = process.env.DATABASE_URL;
    delete process.env.GHOSTRECON_STORAGE;
    process.env.DATABASE_URL = 'postgresql://user:pass@127.0.0.1:5432/test';
    const db = await import('../modules/db.js');
    assert.equal(db.resolveStorageMode(), 'postgres');
    assert.equal(db.usePostgresPrimary(), true);
    process.env.GHOSTRECON_STORAGE = prev;
    process.env.DATABASE_URL = prevUrl;
  });
});
