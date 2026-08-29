import { describe, it, expect } from 'vitest';
import {
  parseIpv4,
  parseCidr,
  parseCidrList,
  ipInCidr,
  ipInCidrs,
  socketPeerIpv4,
  resolveClientIp,
  formatIpv4,
} from './net';

function req(remoteAddress: string | undefined, xff?: string) {
  return {
    socket: { remoteAddress } as never,
    headers: xff === undefined ? {} : { 'x-forwarded-for': xff },
  };
}

describe('parseIpv4', () => {
  it('parses dotted quads', () => {
    expect(parseIpv4('10.0.0.1')).toBe((10 << 24) + 1);
    expect(parseIpv4('255.255.255.255')).toBe(0xffffffff);
    expect(parseIpv4('0.0.0.0')).toBe(0);
  });

  it('rejects malformed, IPv6, and IPv4-mapped-IPv6 forms', () => {
    expect(parseIpv4('')).toBeNull();
    expect(parseIpv4('10.0.0')).toBeNull();
    expect(parseIpv4('10.0.0.256')).toBeNull();
    expect(parseIpv4('10.0.0.1.5')).toBeNull();
    expect(parseIpv4('::1')).toBeNull();
    expect(parseIpv4('::ffff:10.0.0.1')).toBeNull();
    expect(parseIpv4('2001:db8::1')).toBeNull();
    expect(parseIpv4('not-an-ip')).toBeNull();
  });

  it('rejects leading zeros (octal ambiguity)', () => {
    expect(parseIpv4('010.0.0.1')).toBeNull();
    expect(parseIpv4('10.0.0.01')).toBeNull();
  });
});

describe('parseCidr / parseCidrList', () => {
  it('parses subnets and bare addresses (implied /32)', () => {
    expect(parseCidr('10.9.0.0/16')).toEqual({ base: parseIpv4('10.9.0.0'), prefix: 16 });
    expect(parseCidr('203.0.113.7')).toEqual({ base: parseIpv4('203.0.113.7'), prefix: 32 });
    expect(parseCidr('203.0.113.7/32')).toEqual({ base: parseIpv4('203.0.113.7'), prefix: 32 });
  });

  it('rejects bad prefixes and non-IPv4 bases', () => {
    expect(parseCidr('10.0.0.0/33')).toBeNull();
    expect(parseCidr('10.0.0.0/-1')).toBeNull();
    expect(parseCidr('10.0.0.0/x')).toBeNull();
    expect(parseCidr('::1/128')).toBeNull();
  });

  it('parses a comma-separated list and throws on any bad entry', () => {
    expect(parseCidrList('10.0.0.0/8, 203.0.113.7')).toHaveLength(2);
    expect(parseCidrList('')).toEqual([]);
    expect(parseCidrList(' , ')).toEqual([]);
    expect(() => parseCidrList('10.0.0.0/8, nope')).toThrow(/Invalid IPv4 CIDR/);
  });
});

describe('ipInCidr(s)', () => {
  const cidrs = parseCidrList('10.9.0.0/16, 203.0.113.7/32');

  it('matches exact /32 and subnet membership', () => {
    expect(ipInCidrs(parseIpv4('203.0.113.7')!, cidrs)).toBe(true);
    expect(ipInCidrs(parseIpv4('10.9.44.5')!, cidrs)).toBe(true);
    expect(ipInCidrs(parseIpv4('10.10.0.1')!, cidrs)).toBe(false);
    expect(ipInCidrs(parseIpv4('203.0.113.8')!, cidrs)).toBe(false);
  });

  it('handles /0 and high-bit addresses correctly', () => {
    expect(ipInCidr(parseIpv4('250.1.2.3')!, parseCidr('0.0.0.0/0')!)).toBe(true);
    expect(ipInCidr(parseIpv4('250.1.2.3')!, parseCidr('250.0.0.0/8')!)).toBe(true);
    expect(ipInCidr(parseIpv4('249.1.2.3')!, parseCidr('250.0.0.0/8')!)).toBe(false);
  });
});

describe('socketPeerIpv4', () => {
  it('normalises the kernel-reported IPv4-mapped form', () => {
    expect(socketPeerIpv4('::ffff:127.0.0.1')).toBe(parseIpv4('127.0.0.1'));
    expect(socketPeerIpv4('127.0.0.1')).toBe(parseIpv4('127.0.0.1'));
  });

  it('rejects real IPv6 and missing peers', () => {
    expect(socketPeerIpv4('::1')).toBeNull();
    expect(socketPeerIpv4('2001:db8::5')).toBeNull();
    expect(socketPeerIpv4(undefined)).toBeNull();
  });
});

describe('resolveClientIp', () => {
  const proxies = parseCidrList('172.16.0.0/24');

  it('defaults to the socket peer and ignores X-Forwarded-For from an untrusted peer', () => {
    const r = resolveClientIp(req('203.0.113.7', '10.9.0.5'), proxies);
    expect(r).toEqual({ ip: '203.0.113.7', ipNum: parseIpv4('203.0.113.7'), forwarded: false });
  });

  it('spoofed forwarding headers cannot bypass the policy without a trusted proxy', () => {
    const r = resolveClientIp(req('203.0.113.7', '10.9.0.5, 172.16.0.1'), []);
    expect(r?.ip).toBe('203.0.113.7');
    expect(r?.forwarded).toBe(false);
  });

  it('honours the forwarded client when the direct peer is a trusted proxy', () => {
    const r = resolveClientIp(req('172.16.0.1', '10.9.0.5'), proxies);
    expect(r).toEqual({ ip: '10.9.0.5', ipNum: parseIpv4('10.9.0.5'), forwarded: true });
  });

  it('walks a proxy chain right-to-left across trusted hops only', () => {
    // client 10.9.0.5 → proxy 172.16.0.2 → proxy 172.16.0.1 → id
    const r = resolveClientIp(req('172.16.0.1', '10.9.0.5, 172.16.0.2'), proxies);
    expect(r?.ip).toBe('10.9.0.5');
    // The attacker-prepended hop before the real client is NOT the answer.
    const r2 = resolveClientIp(req('172.16.0.1', '1.2.3.4, 10.9.0.5, 172.16.0.2'), proxies);
    expect(r2?.ip).toBe('10.9.0.5');
  });

  it('rejects malformed, IPv6, or mapped entries in the forwarded chain', () => {
    expect(resolveClientIp(req('172.16.0.1', '::ffff:10.9.0.5'), proxies)).toBeNull();
    expect(resolveClientIp(req('172.16.0.1', '2001:db8::1'), proxies)).toBeNull();
    expect(resolveClientIp(req('172.16.0.1', 'garbage'), proxies)).toBeNull();
    expect(resolveClientIp(req('172.16.0.1', ''), proxies)?.ip).toBe('172.16.0.1');
  });

  it('rejects a real-IPv6 socket peer deterministically', () => {
    expect(resolveClientIp(req('2001:db8::5', '10.9.0.5'), proxies)).toBeNull();
    expect(resolveClientIp(req(undefined), proxies)).toBeNull();
  });

  it('treats an all-proxy chain as the leftmost proxy (NAT edge)', () => {
    const r = resolveClientIp(req('172.16.0.1', '172.16.0.9'), proxies);
    expect(r?.ip).toBe('172.16.0.9');
  });
});

describe('formatIpv4', () => {
  it('round-trips', () => {
    for (const ip of ['0.0.0.0', '10.9.0.5', '203.0.113.7', '255.255.255.255']) {
      expect(formatIpv4(parseIpv4(ip)!)).toBe(ip);
    }
  });
});
