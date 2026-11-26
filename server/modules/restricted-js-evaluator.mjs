// A deliberately small JavaScript parser/interpreter for constant-only client
// logic. It never invokes eval, Function, vm, DOM APIs, timers or networking.
// Unsupported syntax fails closed and is reported as a candidate by callers.

const DEFAULT_LIMITS = Object.freeze({
  maxSourceBytes: 400_000,
  maxFunctions: 64,
  maxTokens: 20_000,
  maxSteps: 5_000,
  maxDepth: 40,
  maxCollection: 1_000,
  maxStringLength: 16_000,
  maxObjectKeys: 512,
});

class RestrictedSyntaxError extends Error {
  constructor(message, position = -1) {
    super(position >= 0 ? `${message} at ${position}` : message);
    this.name = 'RestrictedSyntaxError';
    this.position = position;
  }
}

class Lexer {
  constructor(input, limits) {
    this.input = input;
    this.limits = limits;
    this.pos = 0;
    this.tokens = 0;
  }

  next() {
    this.skipTrivia();
    if (this.tokens++ > this.limits.maxTokens) throw new RestrictedSyntaxError('token limit exceeded', this.pos);
    if (this.pos >= this.input.length) return { type: 'eof', value: '', pos: this.pos };
    const start = this.pos;
    const ch = this.input[this.pos];

    if (ch === '"' || ch === "'") return this.readString(ch, start);
    if (ch === '`') throw new RestrictedSyntaxError('template literals are unsupported', start);
    if (/[A-Za-z_$]/.test(ch)) {
      this.pos += 1;
      while (this.pos < this.input.length && /[A-Za-z0-9_$]/.test(this.input[this.pos])) this.pos += 1;
      return { type: 'identifier', value: this.input.slice(start, this.pos), pos: start };
    }
    if (/[0-9]/.test(ch)) {
      this.pos += 1;
      while (this.pos < this.input.length && /[0-9._]/.test(this.input[this.pos])) this.pos += 1;
      const raw = this.input.slice(start, this.pos).replaceAll('_', '');
      const value = Number(raw);
      if (!Number.isFinite(value)) throw new RestrictedSyntaxError('invalid number', start);
      return { type: 'number', value, pos: start };
    }
    const pair = this.input.slice(this.pos, this.pos + 2);
    if (['+=', '==', '!=', '=>', '++', '--'].includes(pair)) {
      this.pos += 2;
      return { type: 'punctuator', value: pair, pos: start };
    }
    if ('{}[](),;:=+-.'.includes(ch)) {
      this.pos += 1;
      return { type: 'punctuator', value: ch, pos: start };
    }
    throw new RestrictedSyntaxError(`unsupported character ${JSON.stringify(ch)}`, start);
  }

  skipTrivia() {
    for (;;) {
      while (this.pos < this.input.length && /\s/.test(this.input[this.pos])) this.pos += 1;
      if (this.input.startsWith('//', this.pos)) {
        this.pos += 2;
        while (this.pos < this.input.length && !/[\r\n]/.test(this.input[this.pos])) this.pos += 1;
        continue;
      }
      if (this.input.startsWith('/*', this.pos)) {
        const end = this.input.indexOf('*/', this.pos + 2);
        if (end < 0) throw new RestrictedSyntaxError('unterminated comment', this.pos);
        this.pos = end + 2;
        continue;
      }
      return;
    }
  }

  readString(quote, start) {
    this.pos += 1;
    let out = '';
    while (this.pos < this.input.length) {
      const ch = this.input[this.pos++];
      if (ch === quote) return { type: 'string', value: out, pos: start };
      if (ch === '\n' || ch === '\r') throw new RestrictedSyntaxError('newline in string', start);
      if (ch !== '\\') {
        out += ch;
        continue;
      }
      if (this.pos >= this.input.length) throw new RestrictedSyntaxError('unterminated escape', start);
      const escaped = this.input[this.pos++];
      const map = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', 0: '\0' };
      if (escaped === 'u') {
        const hex = this.input.slice(this.pos, this.pos + 4);
        if (!/^[0-9a-f]{4}$/i.test(hex)) throw new RestrictedSyntaxError('invalid unicode escape', this.pos);
        out += String.fromCharCode(Number.parseInt(hex, 16));
        this.pos += 4;
      } else if (escaped === 'x') {
        const hex = this.input.slice(this.pos, this.pos + 2);
        if (!/^[0-9a-f]{2}$/i.test(hex)) throw new RestrictedSyntaxError('invalid hex escape', this.pos);
        out += String.fromCharCode(Number.parseInt(hex, 16));
        this.pos += 2;
      } else {
        out += map[escaped] ?? escaped;
      }
      if (out.length > this.limits.maxStringLength) throw new RestrictedSyntaxError('string limit exceeded', start);
    }
    throw new RestrictedSyntaxError('unterminated string', start);
  }
}

class Parser {
  constructor(source, limits) {
    this.lexer = new Lexer(source, limits);
    this.current = this.lexer.next();
  }

  advance() {
    const token = this.current;
    this.current = this.lexer.next();
    return token;
  }

  is(value) { return this.current.value === value; }

  expect(value) {
    if (!this.is(value)) throw new RestrictedSyntaxError(`expected ${value}, got ${this.current.value || this.current.type}`, this.current.pos);
    return this.advance();
  }

  expectIdentifier() {
    if (this.current.type !== 'identifier') throw new RestrictedSyntaxError('identifier expected', this.current.pos);
    return this.advance().value;
  }

  optionalSemicolon() { if (this.is(';')) this.advance(); }

  parseFunction() {
    this.expect('function');
    const name = this.expectIdentifier();
    this.expect('(');
    const params = [];
    if (!this.is(')')) {
      for (;;) {
        params.push(this.expectIdentifier());
        if (!this.is(',')) break;
        this.advance();
      }
    }
    this.expect(')');
    const body = this.parseBlock();
    if (this.current.type !== 'eof') throw new RestrictedSyntaxError('trailing syntax', this.current.pos);
    return { type: 'Function', name, params, body };
  }

  parseBlock() {
    this.expect('{');
    const body = [];
    while (!this.is('}')) {
      if (this.current.type === 'eof') throw new RestrictedSyntaxError('unterminated block', this.current.pos);
      body.push(this.parseStatement());
    }
    this.expect('}');
    return { type: 'Block', body };
  }

  parseStatement() {
    if (this.is(';')) {
      this.advance();
      return { type: 'Empty' };
    }
    if (['const', 'let', 'var'].includes(this.current.value)) return this.parseVariable();
    if (this.is('for')) return this.parseForOf();
    if (this.is('return')) return this.parseReturn();
    if (this.is('{')) return this.parseBlock();
    if (this.current.type === 'identifier') {
      const name = this.advance().value;
      if (!this.is('+=') && !this.is('=')) throw new RestrictedSyntaxError('only direct assignment is supported', this.current.pos);
      const operator = this.advance().value;
      const value = this.parseExpression();
      this.optionalSemicolon();
      return { type: 'Assignment', name, operator, value };
    }
    throw new RestrictedSyntaxError(`unsupported statement ${this.current.value}`, this.current.pos);
  }

  parseVariable() {
    const kind = this.advance().value;
    const name = this.expectIdentifier();
    this.expect('=');
    const value = this.parseExpression();
    this.optionalSemicolon();
    return { type: 'Variable', kind, name, value };
  }

  parseForOf() {
    this.expect('for');
    this.expect('(');
    if (!['const', 'let', 'var'].includes(this.current.value)) throw new RestrictedSyntaxError('for-of declaration expected', this.current.pos);
    const kind = this.advance().value;
    const name = this.expectIdentifier();
    this.expect('of');
    const iterable = this.parseExpression();
    this.expect(')');
    const body = this.parseStatement();
    return { type: 'ForOf', kind, name, iterable, body };
  }

  parseReturn() {
    this.expect('return');
    const value = this.parseExpression();
    this.optionalSemicolon();
    return { type: 'Return', value };
  }

  parseExpression() {
    let left = this.parsePrimary();
    while (this.is('+')) {
      this.advance();
      left = { type: 'Binary', operator: '+', left, right: this.parsePrimary() };
    }
    return left;
  }

  parsePrimary() {
    let node;
    if (this.current.type === 'string' || this.current.type === 'number') {
      node = { type: 'Literal', value: this.advance().value };
    } else if (this.current.type === 'identifier') {
      const value = this.advance().value;
      if (['true', 'false', 'null'].includes(value)) {
        node = { type: 'Literal', value: value === 'true' ? true : value === 'false' ? false : null };
      } else {
        node = { type: 'Identifier', name: value };
      }
    } else if (this.is('{')) {
      node = this.parseObject();
    } else if (this.is('[')) {
      node = this.parseArray();
    } else if (this.is('(')) {
      this.advance();
      node = this.parseExpression();
      this.expect(')');
    } else {
      throw new RestrictedSyntaxError(`unsupported expression ${this.current.value}`, this.current.pos);
    }

    while (this.is('[') || this.is('.')) {
      if (this.is('[')) {
        this.advance();
        const property = this.parseExpression();
        this.expect(']');
        node = { type: 'Member', object: node, property };
      } else {
        this.advance();
        node = { type: 'Member', object: node, property: { type: 'Literal', value: this.expectIdentifier() } };
      }
    }
    return node;
  }

  parseObject() {
    this.expect('{');
    const properties = [];
    while (!this.is('}')) {
      let key;
      if (this.current.type === 'string' || this.current.type === 'identifier' || this.current.type === 'number') {
        key = String(this.advance().value);
      } else {
        throw new RestrictedSyntaxError('object key expected', this.current.pos);
      }
      this.expect(':');
      properties.push({ key, value: this.parseExpression() });
      if (!this.is(',')) break;
      this.advance();
      if (this.is('}')) break;
    }
    this.expect('}');
    return { type: 'Object', properties };
  }

  parseArray() {
    this.expect('[');
    const elements = [];
    while (!this.is(']')) {
      elements.push(this.parseExpression());
      if (!this.is(',')) break;
      this.advance();
      if (this.is(']')) break;
    }
    this.expect(']');
    return { type: 'Array', elements };
  }
}

function findClosingBrace(source, openIndex) {
  let depth = 0;
  let quote = '';
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let i = openIndex; i < source.length; i += 1) {
    const ch = source[i];
    const next = source[i + 1];
    if (lineComment) {
      if (ch === '\n' || ch === '\r') lineComment = false;
      continue;
    }
    if (blockComment) {
      if (ch === '*' && next === '/') { blockComment = false; i += 1; }
      continue;
    }
    if (quote) {
      if (escaped) { escaped = false; continue; }
      if (ch === '\\') { escaped = true; continue; }
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '/' && next === '/') { lineComment = true; i += 1; continue; }
    if (ch === '/' && next === '*') { blockComment = true; i += 1; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export function extractRestrictedFunctions(rawSource, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const source = String(rawSource || '').slice(0, limits.maxSourceBytes);
  const functions = [];
  const re = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{/g;
  let match;
  while (functions.length < limits.maxFunctions && (match = re.exec(source)) !== null) {
    const open = re.lastIndex - 1;
    const close = findClosingBrace(source, open);
    if (close < 0) break;
    functions.push({
      name: match[1],
      paramsText: match[2],
      source: source.slice(match.index, close + 1),
      start: match.index,
      end: close + 1,
    });
    re.lastIndex = close + 1;
  }
  return functions;
}

class Evaluator {
  constructor(limits) {
    this.limits = limits;
    this.steps = 0;
  }

  tick(depth = 0) {
    this.steps += 1;
    if (this.steps > this.limits.maxSteps) throw new RestrictedSyntaxError('evaluation step limit exceeded');
    if (depth > this.limits.maxDepth) throw new RestrictedSyntaxError('evaluation depth limit exceeded');
  }

  expression(node, env, depth = 0) {
    this.tick(depth);
    switch (node.type) {
      case 'Literal': return node.value;
      case 'Identifier':
        if (!env.has(node.name)) throw new RestrictedSyntaxError(`unknown identifier ${node.name}`);
        return env.get(node.name);
      case 'Binary': {
        const left = this.expression(node.left, env, depth + 1);
        const right = this.expression(node.right, env, depth + 1);
        if (node.operator !== '+') throw new RestrictedSyntaxError('unsupported binary operator');
        const value = typeof left === 'string' || typeof right === 'string' ? String(left) + String(right) : Number(left) + Number(right);
        if (typeof value === 'string' && value.length > this.limits.maxStringLength) throw new RestrictedSyntaxError('result string limit exceeded');
        return value;
      }
      case 'Object': {
        if (node.properties.length > this.limits.maxObjectKeys) throw new RestrictedSyntaxError('object key limit exceeded');
        const value = Object.create(null);
        for (const property of node.properties) value[property.key] = this.expression(property.value, env, depth + 1);
        return value;
      }
      case 'Array':
        if (node.elements.length > this.limits.maxCollection) throw new RestrictedSyntaxError('array limit exceeded');
        return node.elements.map((item) => this.expression(item, env, depth + 1));
      case 'Member': {
        const object = this.expression(node.object, env, depth + 1);
        const property = String(this.expression(node.property, env, depth + 1));
        if (['__proto__', 'prototype', 'constructor'].includes(property)) throw new RestrictedSyntaxError('unsafe property');
        if (property === 'length' && (typeof object === 'string' || Array.isArray(object))) return object.length;
        if (object == null || (typeof object !== 'object' && typeof object !== 'string')) throw new RestrictedSyntaxError('invalid member target');
        if (!Object.prototype.hasOwnProperty.call(Object(object), property)) throw new RestrictedSyntaxError(`missing property ${property}`);
        return object[property];
      }
      default: throw new RestrictedSyntaxError(`unsupported expression node ${node.type}`);
    }
  }

  statement(node, env, depth = 0) {
    this.tick(depth);
    switch (node.type) {
      case 'Empty': return null;
      case 'Variable':
        env.set(node.name, this.expression(node.value, env, depth + 1));
        return null;
      case 'Assignment': {
        if (!env.has(node.name)) throw new RestrictedSyntaxError(`assignment to unknown ${node.name}`);
        const right = this.expression(node.value, env, depth + 1);
        if (node.operator === '=') env.set(node.name, right);
        else {
          const left = env.get(node.name);
          const value = typeof left === 'string' || typeof right === 'string' ? String(left) + String(right) : Number(left) + Number(right);
          if (typeof value === 'string' && value.length > this.limits.maxStringLength) throw new RestrictedSyntaxError('result string limit exceeded');
          env.set(node.name, value);
        }
        return null;
      }
      case 'ForOf': {
        const iterable = this.expression(node.iterable, env, depth + 1);
        if (typeof iterable !== 'string' && !Array.isArray(iterable)) throw new RestrictedSyntaxError('for-of requires constant string/array');
        if (iterable.length > this.limits.maxCollection) throw new RestrictedSyntaxError('iteration limit exceeded');
        for (const value of iterable) {
          env.set(node.name, value);
          const control = this.statement(node.body, env, depth + 1);
          if (control?.returned) return control;
        }
        return null;
      }
      case 'Block':
        for (const child of node.body) {
          const control = this.statement(child, env, depth + 1);
          if (control?.returned) return control;
        }
        return null;
      case 'Return': return { returned: true, value: this.expression(node.value, env, depth + 1) };
      default: throw new RestrictedSyntaxError(`unsupported statement node ${node.type}`);
    }
  }
}

export function evaluateRestrictedFunctionSource(source, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  try {
    if (Buffer.byteLength(String(source || '')) > limits.maxSourceBytes) {
      throw new RestrictedSyntaxError('source size limit exceeded');
    }
    const ast = new Parser(String(source || ''), limits).parseFunction();
    if (ast.params.length) throw new RestrictedSyntaxError('only zero-argument functions are evaluable');
    const evaluator = new Evaluator(limits);
    const control = evaluator.statement(ast.body, new Map());
    if (!control?.returned) throw new RestrictedSyntaxError('function did not return a value');
    if (!['string', 'number', 'boolean'].includes(typeof control.value)) throw new RestrictedSyntaxError('non-scalar return value');
    return { ok: true, name: ast.name, value: control.value, steps: evaluator.steps, ast };
  } catch (error) {
    return {
      ok: false,
      reason: error instanceof RestrictedSyntaxError ? error.message : 'restricted evaluator failed',
    };
  }
}

export { DEFAULT_LIMITS as restrictedEvaluatorLimits };
