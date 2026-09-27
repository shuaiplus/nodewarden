import assert from 'node:assert/strict';
import test from 'node:test';

import { getClientIdentifier } from '../src/services/ratelimit';

const identify = (headers: Record<string, string>, url = 'https://vault.example.test/') => getClientIdentifier(new Request(url, { headers }));

test('client addresses keep their IPv4 identity and collapse IPv6 to its /64', () => {
  const expected: Array<[string, string | null]> = [
    ['203.0.113.10', 'ip4:203.0.113.10'],
    ['::ffff:203.0.113.10', 'ip4:203.0.113.10'],
    ['::203.0.113.10', 'ip4:203.0.113.10'],
    ['[2001:DB8:a::1%eth0]', 'ip6:2001:0db8:000a:0000'],
    ['2001:db8:a:b:1:2:3:4', 'ip6:2001:0db8:000a:000b'],
    ['1::2::3', null],
    ['203.0.113.256', null],
  ];
  for (const [address, identity] of expected) assert.equal(identify({ 'CF-Connecting-IP': address }), identity, address);
});

test('header precedence skips invalid candidates and only localhost falls back to loopback', () => {
  assert.equal(identify({ 'CF-Connecting-IP': 'bogus', 'X-Real-IP': '198.51.100.1', 'X-Forwarded-For': '192.0.2.1' }), 'ip4:198.51.100.1');
  assert.equal(identify({ 'X-Forwarded-For': ' 192.0.2.1 , 198.51.100.1' }), 'ip4:192.0.2.1');
  assert.equal(identify({}, 'http://localhost:8787/'), 'ip4:127.0.0.1');
  assert.equal(identify({}), null);
});
