import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { EVENT_TYPES } from './webhooks';

/**
 * Contract validation: the machine-readable POC contract in
 * docs/openapi.json must stay internally valid, its fixtures must
 * validate against it, and the invariants the POC pins (no secret field,
 * optional HMAC, event-type parity with the code) must hold. CI runs this
 * on every change; the breaking-change gate diffs the spec itself.
 */

const docsDir = path.join(__dirname, '..', 'docs');
const spec = JSON.parse(fs.readFileSync(path.join(docsDir, 'openapi.json'), 'utf8'));
const fixturesDir = path.join(docsDir, 'contract', 'fixtures');

function ajv() {
  const instance = new Ajv2020({ strict: false, allErrors: true });
  addFormats(instance);
  // Register the whole components block so $refs between schemas resolve.
  instance.addSchema(
    { $id: 'openapi.json', components: spec.components },
    'openapi.json'
  );
  return instance;
}

describe('OpenAPI contract document', () => {
  it('is OpenAPI 3.1 with normative X.TLD placeholders', () => {
    expect(spec.openapi).toBe('3.1.0');
    expect(spec.servers[0].url).toBe('https://identity.X.TLD');
    // localsplash.ai must never appear normatively in the contract.
    expect(JSON.stringify(spec.servers)).not.toContain('localsplash.ai');
  });

  it('covers authorize, token, registration, events, and directory', () => {
    for (const p of [
      '/authorize',
      '/api/token',
      '/api/apps/register',
      '/api/events',
      '/api/directory/users',
      '/api/directory/users/{iUserId}',
    ]) {
      expect(spec.paths[p], `missing path ${p}`).toBeDefined();
    }
  });

  it('every component schema compiles', () => {
    const instance = ajv();
    for (const name of Object.keys(spec.components.schemas)) {
      expect(() => instance.compile({ $ref: `openapi.json#/components/schemas/${name}` })).not.toThrow();
    }
  });
});

describe('fixtures validate against the contract', () => {
  const files = fs.readdirSync(fixturesDir).filter((f) => f.endsWith('.json'));

  it('has a fixture set', () => {
    expect(files.length).toBeGreaterThanOrEqual(5);
  });

  for (const file of files) {
    it(`${file}`, () => {
      const fixture = JSON.parse(fs.readFileSync(path.join(fixturesDir, file), 'utf8'));
      const schemaName = fixture.$schema as string;
      expect(schemaName, `${file} must name its schema in $schema`).toBeTruthy();
      expect(spec.components.schemas[schemaName], `unknown schema ${schemaName}`).toBeDefined();

      const { $schema: _drop, ...payload } = fixture;
      const validate = ajv().compile({ $ref: `openapi.json#/components/schemas/${schemaName}` });
      const valid = validate(payload);
      expect(validate.errors ?? []).toEqual([]);
      expect(valid).toBe(true);
    });
  }
});

describe('pinned POC invariants', () => {
  it('no request schema requires a secret-key field or HMAC signature', () => {
    for (const name of ['TokenRequest', 'RegistrationRequest', 'DirectoryEnsureRequest']) {
      const schema = spec.components.schemas[name];
      const required: string[] = schema.required ?? [];
      const properties = Object.keys(schema.properties ?? {});
      for (const key of [...required, ...properties]) {
        expect(key.toLowerCase()).not.toMatch(/secret|signature|hmac/);
      }
    }
  });

  it('the delivery signature is declared optional', () => {
    const reg = spec.components.schemas.RegistrationResponse;
    expect(reg.required).not.toContain('secret');
    expect(reg.required).not.toContain('signature');
    expect(reg.properties.signature.properties.required.const).toBe(false);
  });

  it('contract event types match the code exactly', () => {
    expect(spec.components.schemas.EventType.enum).toEqual([...EVENT_TYPES]);
  });

  it('superAdmin provenance is pinned in the schema description', () => {
    const desc: string = spec.components.schemas.TokenResponse.properties.user.properties.superAdmin.description;
    expect(desc).toContain('Session');
    expect(desc).toContain('AuthCode');
    expect(desc).toMatch(/never recalculates from email/i);
  });

  it('token redemption pins exact redirect binding and single-use, 5-minute codes', () => {
    const desc: string = spec.paths['/api/token'].post.description;
    expect(desc).toMatch(/exact/i);
    expect(desc).toMatch(/single-use/i);
    expect(desc).toMatch(/5 minutes/i);
  });
});
