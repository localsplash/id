import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  validateRedirectUri,
  verifySsoCode,
  encodeState,
  decodeState,
  suggestParentDomain,
  isValidDomain,
  isValidDomainList,
} from './web';
import {
  availableLoginMethods,
  isSuperAdmin,
  isTenantLocked,
  parseDomainList,
  superAdminDomains,
  verifiedDomain,
  parseMicrosoftIdToken,
  getProvider,
} from './providers';
import type { Settings } from './settings';

const settings: Settings = { PARENT_DOMAIN: 'wisp.net' };

describe('validateRedirectUri', () => {
  it('accepts any https app under the parent domain', () => {
    expect(validateRedirectUri('https://echo.wisp.net/auth/callback', settings)).toBe(
      'https://echo.wisp.net/auth/callback'
    );
    expect(validateRedirectUri('https://aida.wisp.net/cb', settings)).toBe(
      'https://aida.wisp.net/cb'
    );
    expect(validateRedirectUri('https://wisp.net/cb', settings)).toBe('https://wisp.net/cb');
  });

  it('rejects hosts outside the parent domain, including suffix tricks', () => {
    expect(validateRedirectUri('https://evil.com/cb', settings)).toBeNull();
    expect(validateRedirectUri('https://notwisp.net/cb', settings)).toBeNull();
    expect(validateRedirectUri('https://wisp.net.evil.com/cb', settings)).toBeNull();
  });

  it('rejects http in production but allows it in development', () => {
    expect(validateRedirectUri('http://echo.wisp.net/cb', settings)).toBeNull();
    expect(validateRedirectUri('http://echo.wisp.net/cb', settings, 'development')).toBe(
      'http://echo.wisp.net/cb'
    );
  });

  it('rejects everything until PARENT_DOMAIN is configured', () => {
    expect(validateRedirectUri('https://echo.wisp.net/cb', {})).toBeNull();
  });

  it('rejects malformed URLs and embedded credentials', () => {
    expect(validateRedirectUri('not a url', settings)).toBeNull();
    expect(validateRedirectUri('https://user:pass@echo.wisp.net/cb', settings)).toBeNull();
  });
});

describe('verifySsoCode', () => {
  const secret = 'shh';
  function makeCode(payload: Record<string, unknown>): { code: string; sig: string } {
    const code = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(code).digest('hex');
    return { code, sig };
  }

  it('accepts a properly signed, unexpired code', () => {
    const { code, sig } = makeCode({
      clientId: '42',
      nonce: 'n'.repeat(32),
      exp: Math.floor(Date.now() / 1000) + 30,
    });
    expect(verifySsoCode(secret, code, sig)?.clientId).toBe('42');
  });

  it('rejects a tampered signature', () => {
    const { code } = makeCode({
      clientId: '42',
      nonce: 'n'.repeat(32),
      exp: Math.floor(Date.now() / 1000) + 30,
    });
    expect(verifySsoCode(secret, code, 'ab'.repeat(32))).toBeNull();
  });

  it('rejects an expired code', () => {
    const { code, sig } = makeCode({
      clientId: '42',
      nonce: 'n'.repeat(32),
      exp: Math.floor(Date.now() / 1000) - 5,
    });
    expect(verifySsoCode(secret, code, sig)).toBeNull();
  });
});

describe('availableLoginMethods', () => {
  it('offers nothing when nothing is configured', () => {
    expect(availableLoginMethods({})).toEqual([]);
  });

  it('offers a provider only when every required key is set', () => {
    expect(availableLoginMethods({ GOOGLE_CLIENT_ID: 'x' }).map((m) => m.id)).toEqual([]);
    expect(
      availableLoginMethods({ GOOGLE_CLIENT_ID: 'x', GOOGLE_CLIENT_SECRET: 'y' }).map((m) => m.id)
    ).toEqual(['google']);
  });

  it('offers the ISP bridge when both plugin URL and secret exist', () => {
    const methods = availableLoginMethods({
      UISP_PLUGIN_URL: 'https://my.wisp.net/plugin',
      UISP_SSO_SECRET: 's',
    });
    expect(methods).toEqual([
      { id: 'uisp', label: 'ISP account', href: 'https://my.wisp.net/plugin', kind: 'external' },
    ]);
  });
});

describe('isSuperAdmin', () => {
  const google = getProvider('google')!;
  const microsoft = getProvider('microsoft')!;

  it('grants for a Google account on the parent domain', () => {
    expect(
      isSuperAdmin(google, { sub: 's', email: 'a@wisp.net', name: 'A' }, settings)
    ).toBe(true);
    expect(
      isSuperAdmin(google, { sub: 's', email: 'x@gmail.com', name: 'A', hd: 'wisp.net' }, settings)
    ).toBe(true);
  });

  it("never grants via Microsoft on a multiplexed authority ('common')", () => {
    expect(
      isSuperAdmin(microsoft, { sub: 's', email: 'a@wisp.net', name: 'A' }, settings)
    ).toBe(false);
    expect(
      isSuperAdmin(
        microsoft,
        { sub: 's', email: 'a@wisp.net', name: 'A' },
        { ...settings, MICROSOFT_TENANT: 'organizations' }
      )
    ).toBe(false);
  });

  it('grants via Microsoft when the app is locked to one tenant', () => {
    expect(
      isSuperAdmin(
        microsoft,
        { sub: 's', email: 'a@wisp.net', name: 'A' },
        { ...settings, MICROSOFT_TENANT: 'a2b4c6d8-0000-0000-0000-000000000000' }
      )
    ).toBe(true);
  });

  it('honours SUPERADMIN_DOMAIN over PARENT_DOMAIN', () => {
    const s: Settings = { PARENT_DOMAIN: 'wisp.net', SUPERADMIN_DOMAIN: 'corp.example' };
    expect(isSuperAdmin(google, { sub: 's', email: 'a@wisp.net', name: 'A' }, s)).toBe(false);
    expect(isSuperAdmin(google, { sub: 's', email: 'a@corp.example', name: 'A' }, s)).toBe(true);
  });

  it('grants nothing when no domain is configured', () => {
    expect(isSuperAdmin(google, { sub: 's', email: 'a@wisp.net', name: 'A' }, {})).toBe(false);
  });

  // A Google Workspace domain alias: the apps are served from example.ai but
  // every token carries the Workspace primary, example.com. Naming the app
  // domain alone must not grant, and naming the primary must.
  describe('Workspace domain alias (apps on one domain, identities on another)', () => {
    const aliasUser = {
      sub: 's',
      email: 'ada@localsplash.com',
      name: 'Ada',
      hd: 'localsplash.com',
    };

    it('does not grant on the application domain alone', () => {
      expect(isSuperAdmin(google, aliasUser, { PARENT_DOMAIN: 'localsplash.ai' })).toBe(false);
    });

    it('grants when SUPERADMIN_DOMAIN names the domain the provider vouches for', () => {
      expect(
        isSuperAdmin(google, aliasUser, {
          PARENT_DOMAIN: 'localsplash.ai',
          SUPERADMIN_DOMAIN: 'localsplash.com',
        })
      ).toBe(true);
    });

    it('accepts a list, so a later secondary-domain user also qualifies', () => {
      const settings = {
        PARENT_DOMAIN: 'localsplash.ai',
        SUPERADMIN_DOMAIN: 'localsplash.com, localsplash.ai',
      };
      expect(isSuperAdmin(google, aliasUser, settings)).toBe(true);
      expect(
        isSuperAdmin(
          google,
          { sub: 's2', email: 'bob@localsplash.ai', name: 'Bob', hd: 'localsplash.ai' },
          settings
        )
      ).toBe(true);
      // An unrelated domain still gets nothing.
      expect(
        isSuperAdmin(google, { sub: 's3', email: 'eve@evil.com', name: 'Eve' }, settings)
      ).toBe(false);
    });
  });
});

describe('parseDomainList', () => {
  it('normalises case, whitespace and a stray @', () => {
    expect(parseDomainList(' Localsplash.COM , @localsplash.ai ')).toEqual([
      'localsplash.com',
      'localsplash.ai',
    ]);
  });

  it('drops empty entries', () => {
    expect(parseDomainList(',, ,')).toEqual([]);
    expect(parseDomainList('a.com,,b.com')).toEqual(['a.com', 'b.com']);
  });
});

describe('superAdminDomains', () => {
  it('falls back to the application domain when unset', () => {
    expect(superAdminDomains({ PARENT_DOMAIN: 'wisp.net' })).toEqual(['wisp.net']);
  });

  it('overrides the fallback entirely once set', () => {
    expect(
      superAdminDomains({ PARENT_DOMAIN: 'localsplash.ai', SUPERADMIN_DOMAIN: 'localsplash.com' })
    ).toEqual(['localsplash.com']);
  });
});

describe('verifiedDomain', () => {
  it('prefers the hosted domain, which names the Workspace rather than the address', () => {
    expect(verifiedDomain({ sub: 's', email: 'a@gmail.com', name: 'A', hd: 'wisp.net' })).toBe(
      'wisp.net'
    );
  });

  it('falls back to the address domain, lowercased', () => {
    expect(verifiedDomain({ sub: 's', email: 'Ada@Localsplash.COM', name: 'A' })).toBe(
      'localsplash.com'
    );
  });

  it('returns empty for an address it cannot read', () => {
    expect(verifiedDomain({ sub: 's', email: '', name: 'A' })).toBe('');
  });
});

describe('parseMicrosoftIdToken', () => {
  function idToken(claims: Record<string, unknown>): string {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    return `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64(claims)}.signature`;
  }

  it('reads a work/school account and lowercases the address', () => {
    const info = parseMicrosoftIdToken(
      idToken({ sub: 'sub-123', name: 'Ada', email: 'Ada@Contoso.COM' })
    );
    expect(info).toEqual({ sub: 'sub-123', email: 'ada@contoso.com', name: 'Ada' });
  });

  it('rejects a token with no usable address or subject', () => {
    expect(parseMicrosoftIdToken(idToken({ sub: 's', name: 'No Mail' }))).toBeNull();
    expect(parseMicrosoftIdToken(idToken({ email: 'a@b.c' }))).toBeNull();
    expect(parseMicrosoftIdToken('not-a-jwt')).toBeNull();
  });
});

describe('isTenantLocked', () => {
  it('treats only a real tenant as locked', () => {
    expect(isTenantLocked({})).toBe(false);
    expect(isTenantLocked({ MICROSOFT_TENANT: 'common' })).toBe(false);
    expect(isTenantLocked({ MICROSOFT_TENANT: 'consumers' })).toBe(false);
    expect(isTenantLocked({ MICROSOFT_TENANT: 'a2b4c6d8-1111-2222-3333-444455556666' })).toBe(true);
    expect(isTenantLocked({ MICROSOFT_TENANT: 'contoso.onmicrosoft.com' })).toBe(true);
  });
});

describe('setup wizard helpers', () => {
  it('suggests the parent domain by stripping the app label', () => {
    expect(suggestParentDomain('id.wisp.net')).toBe('wisp.net');
    expect(suggestParentDomain('id.dev.localsplash.ai')).toBe('dev.localsplash.ai');
    expect(suggestParentDomain('wisp.net')).toBe('wisp.net');
    expect(suggestParentDomain('id.wisp.net:3200')).toBe('wisp.net');
  });

  it('validates domains', () => {
    expect(isValidDomain('wisp.net')).toBe(true);
    expect(isValidDomain('a.b.example.com')).toBe(true);
    expect(isValidDomain('not a domain')).toBe(false);
    expect(isValidDomain('nodots')).toBe(false);
    expect(isValidDomain('-bad.com')).toBe(false);
  });

  it('validates a comma-separated admin domain list', () => {
    expect(isValidDomainList('localsplash.com')).toBe(true);
    expect(isValidDomainList('localsplash.com, localsplash.ai')).toBe(true);
    expect(isValidDomainList('@localsplash.com')).toBe(true);
    expect(isValidDomainList('')).toBe(false);
    expect(isValidDomainList('localsplash.com, nodots')).toBe(false);
  });
});

describe('state round trip', () => {
  it('encodes and decodes', () => {
    const state = { csrf: 'c', context: 'login' as const, provider: 'google' };
    expect(decodeState(encodeState(state))).toEqual(state);
  });

  it('returns null on garbage', () => {
    expect(decodeState('!!!')).toBeNull();
  });
});
