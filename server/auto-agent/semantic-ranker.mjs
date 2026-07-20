import { createHash } from 'node:crypto';

function tokens(value) {
  return String(value || '').toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
    .split(/[^a-z0-9._-]+/).filter((token) => token.length > 2);
}

export function localTextEmbedding(value, dimensions = 256) {
  const vector = new Float32Array(dimensions);
  const words = tokens(value);
  for (let index = 0; index < words.length; index += 1) {
    for (const feature of [words[index], words.slice(index, index + 2).join(' ')]) {
      if (!feature) continue;
      const digest = createHash('sha256').update(feature).digest();
      const slot = digest.readUInt32BE(0) % dimensions;
      vector[slot] += digest[4] & 1 ? 1 : -1;
    }
  }
  const norm = Math.sqrt(vector.reduce((sum, number) => sum + number * number, 0)) || 1;
  return Float32Array.from(vector, (number) => number / norm);
}

export function cosineSimilarity(left, right) {
  let score = 0;
  const length = Math.min(left?.length || 0, right?.length || 0);
  for (let index = 0; index < length; index += 1) score += left[index] * right[index];
  return Math.max(-1, Math.min(1, score));
}
