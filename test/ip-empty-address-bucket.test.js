import test from 'node:test';
import assert from 'node:assert/strict';
import { createIpPseudonymizationHook, createIpPseudonymizer, pseudonymizeIp } from '../src/ip.js';
import { RateLimiter } from '../src/rate-limit.js';

function replyRecorder() {
  return {
    status: 200,
    body: undefined,
    sent: false,
    code(status) {
      this.status = status;
      return this;
    },
    send(body) {
      this.body = body;
      this.sent = true;
      return this;
    },
  };
}

test('pseudonymizeIp treats an empty address as absent', () => {
  assert.equal(pseudonymizeIp(''), undefined);
});

test('address-less requests do not collide in a shared rate-limit bucket', async t => {
  const limiter = new RateLimiter({
    global: { verifyRpm: 1, settleRpm: 10, settleRph: 100, settleRpd: 1000, feeSpd: 1e9 },
    keys: {},
  });
  t.after(() => limiter.close());

  const audit = [];
  const hook = createIpPseudonymizationHook(createIpPseudonymizer(), (event, fields) => {
    audit.push({ event, ...fields });
  });
  const requests = [
    { ip: '', socket: { remoteAddress: '203.0.113.7' } },
    { ip: '', socket: { remoteAddress: '198.51.100.9' } },
  ];

  for (const req of requests) {
    const reply = replyRecorder();
    await hook(req, reply);
    assert.equal(reply.sent, false);
    assert.match(req.ip, /^[0-9a-f]{24}$/);
    assert.equal((await limiter.checkVerify(req)).allowed, true);
    await limiter.recordVerify(req);
  }

  assert.notEqual(requests[0].ip, requests[1].ip);
  assert.equal(limiter.store.map.size, 2);
  assert.deepEqual(audit, []);
});

test('unresolved client address is rejected and audited before rate limiting', async t => {
  const limiter = new RateLimiter({
    global: { verifyRpm: 1, settleRpm: 10, settleRph: 100, settleRpd: 1000, feeSpd: 1e9 },
    keys: {},
  });
  t.after(() => limiter.close());

  const audit = [];
  const hook = createIpPseudonymizationHook(createIpPseudonymizer(), (event, fields) => {
    audit.push({ event, ...fields });
  });
  const req = { ip: '', socket: {}, url: '/verify?ignored=1' };
  const reply = replyRecorder();

  await hook(req, reply);

  assert.equal(req.ip, undefined);
  assert.equal(reply.status, 400);
  assert.deepEqual(reply.body, {
    error: 'invalid_request',
    reason: 'client_address_unresolved',
  });
  assert.deepEqual(audit, [
    {
      event: 'client_address_unresolved',
      actor: 'unknown',
      route: '/verify',
      reason: 'client_address_unresolved',
      outcome: 'rejected',
    },
  ]);
  if (!reply.sent) {
    const check = await limiter.checkVerify(req);
    if (check.allowed) await limiter.recordVerify(req);
  }
  assert.equal(limiter.store.map.size, 0);
});
