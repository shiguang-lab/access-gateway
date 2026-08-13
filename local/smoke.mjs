const baseURL = process.env.POINTS_LOCAL_BASE_URL || 'http://127.0.0.1:18080';
const origin = new URL(baseURL).origin;

class Client {
  constructor() {
    this.cookie = '';
  }

  async request(path, { method = 'GET', body, headers = {}, redirect = 'manual' } = {}) {
    const response = await fetch(baseURL + path, {
      method,
      redirect,
      headers: {
        Accept: 'application/json',
        Origin: origin,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(this.cookie ? { Cookie: this.cookie } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) {
      const pair = setCookie.split(';', 1)[0];
      this.cookie = pair.endsWith('=') ? '' : pair;
    }
    const text = await response.text();
    let value = null;
    try { value = text ? JSON.parse(text) : null; } catch { value = text; }
    return { status: response.status, headers: response.headers, body: value };
  }

  async login(userId) {
    const returnTo = `${origin}/`;
    const result = await this.request('/api/auth/local/login', {
      method: 'POST', body: { userId, returnTo },
    });
    expectStatus(result, 200, `login ${userId}`);
    assert(result.body.redirect === returnTo, `login ${userId} return_to contract`);
    assert(this.cookie.startsWith('sg_local_session='), `login ${userId} session cookie`);
    return result;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(`assertion failed: ${message}`);
  process.stdout.write(`ok - ${message}\n`);
}

function expectStatus(result, expected, message) {
  const error = result.body && typeof result.body === 'object' ? result.body.error : '';
  assert(result.status === expected, `${message}: expected ${expected}, got ${result.status}${error ? ` (${error})` : ''}`);
}

async function waitForGateway() {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(baseURL + '/health/ready');
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error('gateway did not become ready');
}

async function createApplication(client, name) {
  const result = await client.request('/api/v1/integration-admin/points/applications', {
    method: 'POST',
    body: {
      name,
      description: 'local identity contract smoke',
      environment: 'development',
      scopes: ['points:balance:read', 'points:reserve'],
      perTransactionLimit: 1000,
      dailyLimit: 5000,
      maxReservationTtlSeconds: 900,
    },
  });
  expectStatus(result, 201, `create ${name}`);
  assert(result.body.application?.id, `${name} returns application id`);
  assert(result.body.credential?.clientSecret, `${name} returns one-time credential`);
  return result.body.application;
}

await waitForGateway();

const anonymous = new Client();
expectStatus(await anonymous.request('/api/v1/me/points'), 401, 'anonymous personal API denied');
const redirect = await anonymous.request('/', { headers: { Accept: 'text/html' } });
expectStatus(redirect, 302, 'anonymous workbench redirects');
assert(redirect.headers.get('location') === '/login?return_to=%2F', 'redirect preserves local return_to');
const loginPage = await anonymous.request('/login?return_to=/', { headers: { Accept: 'text/html' } });
expectStatus(loginPage, 200, 'local unified login page available');
assert(String(loginPage.body).includes('拾光本地统一登录'), 'local login page is explicit fixture');
expectStatus(await anonymous.request('/api/v1/integration/token', { method: 'POST' }), 405, 'browser machine token path is unreachable');
expectStatus(await anonymous.request('/api/v1/points/reservations', { method: 'POST', body: {} }), 405, 'browser machine mutation path is unreachable');

const ordinary = new Client();
await ordinary.login('local-ordinary');
expectStatus(await ordinary.request('/api/auth/session'), 200, 'ordinary session');
expectStatus(await ordinary.request('/api/v1/me/capabilities'), 200, 'ordinary capabilities');
expectStatus(await ordinary.request('/api/v1/admin/points/applications'), 403, 'ordinary platform API denied');

const owner = new Client();
await owner.login('local-owner');
const appA = await createApplication(owner, 'Local owner application');
const ownerList = await owner.request('/api/v1/integration-admin/points/applications');
expectStatus(ownerList, 200, 'owner application list');
assert(ownerList.body.items?.some((item) => item.id === appA.id), 'owner sees own application');

const otherOwner = new Client();
await otherOwner.login('local-other-owner');
const appB = await createApplication(otherOwner, 'Local other application');
expectStatus(await owner.request(`/api/v1/integration-admin/points/applications/${appB.id}`), 404, 'cross-application lookup is concealed');
expectStatus(await otherOwner.request(`/api/v1/integration-admin/points/applications/${appA.id}`), 404, 'reverse cross-application lookup is concealed');

const auditor = new Client();
await auditor.login('local-auditor');
expectStatus(await auditor.request('/api/v1/admin/points/applications'), 200, 'auditor global read');
expectStatus(await auditor.request('/api/v1/admin/points/adjustments', {
  method: 'POST', body: { subject: { type: 'USER', id: 'local-ordinary' }, amount: 1, reason: 'forbidden smoke' },
}), 403, 'auditor global write denied');

const pointsAdmin = new Client();
await pointsAdmin.login('local-points-admin');
expectStatus(await pointsAdmin.request('/api/v1/admin/points/applications'), 200, 'points admin global read');
expectStatus(await pointsAdmin.request(`/api/v1/admin/points/applications/${appA.id}/members`, {
  method: 'POST', body: { userId: 'local-ordinary' },
}), 201, 'points admin assigns application ADMIN membership');
const memberCapabilities = await ordinary.request('/api/v1/me/capabilities');
expectStatus(memberCapabilities, 200, 'application ADMIN capabilities refresh from database');
assert(memberCapabilities.body.applications?.some((item) => item.applicationId === appA.id && item.membershipRole === 'ADMIN'), 'ordinary receives application ADMIN only through membership');
expectStatus(await ordinary.request(`/api/v1/integration-admin/points/applications/${appA.id}`), 200, 'application ADMIN reaches assigned application');
expectStatus(await ordinary.request(`/api/v1/integration-admin/points/applications/${appB.id}`), 404, 'application ADMIN cannot reach another application');
expectStatus(await pointsAdmin.request('/api/auth/iam/points-role-assignments/search', {
  method: 'POST', body: { query: 'ordinary', limit: 5 },
}), 403, 'points admin cannot manage IAM roles');

const iamAdmin = new Client();
await iamAdmin.login('local-iam-admin');
expectStatus(await iamAdmin.request('/api/auth/iam/points-role-assignments/local-iam-admin', {
  method: 'PUT', body: { roles: ['platform:points-admin'] }, headers: { 'Idempotency-Key': 'local-self-role-change-0001' },
}), 403, 'IAM admin cannot change own high-privilege roles');
expectStatus(await iamAdmin.request('/api/auth/iam/points-role-assignments/search', {
  method: 'POST', body: { query: 'ordinary', limit: 5 },
}), 200, 'IAM admin can search role directory');

const replayKey = 'local-role-grant-replay-0001';
const grant = await iamAdmin.request('/api/auth/iam/points-role-assignments/local-ordinary', {
  method: 'PUT', body: { roles: ['platform:points-auditor'] }, headers: { 'Idempotency-Key': replayKey },
});
expectStatus(grant, 200, 'IAM role grant');
assert(grant.body.replayed === false, 'first durable command is not replayed');
const replay = await iamAdmin.request('/api/auth/iam/points-role-assignments/local-ordinary', {
  method: 'PUT', body: { roles: ['platform:points-auditor'] }, headers: { 'Idempotency-Key': replayKey },
});
expectStatus(replay, 200, 'same IAM command replay');
assert(replay.body.replayed === true && replay.body.operationId === grant.body.operationId, 'replay returns stable operation');
expectStatus(await iamAdmin.request('/api/auth/iam/points-role-assignments/local-ordinary', {
  method: 'PUT', body: { roles: ['platform:points-admin'] }, headers: { 'Idempotency-Key': replayKey },
}), 409, 'same idempotency key with different payload conflicts');
const refreshed = await ordinary.request('/api/auth/session');
expectStatus(refreshed, 200, 'existing ordinary session refreshes');
assert(refreshed.body.platformRoles?.includes('platform:points-auditor'), 'role grant refreshes existing session without relogin');
expectStatus(await ordinary.request('/api/v1/admin/points/applications'), 200, 'refreshed auditor role reaches Points');

expectStatus(await iamAdmin.request('/api/auth/iam/points-role-assignments/local-ordinary', {
  method: 'PUT', body: { roles: [] }, headers: { 'Idempotency-Key': 'local-role-revoke-0001' },
}), 200, 'IAM role revoke');
const revoked = await ordinary.request('/api/auth/session');
assert(!revoked.body.platformRoles?.includes('platform:points-auditor'), 'role revoke refreshes existing session');
expectStatus(await ordinary.request('/api/v1/admin/points/applications'), 403, 'revoked role loses platform read');

expectStatus(await iamAdmin.request('/api/auth/local/provider/fail-next', {
  method: 'POST', body: { targetUserId: 'local-owner' },
}), 200, 'arm fake provider unknown outcome');
expectStatus(await iamAdmin.request('/api/auth/iam/points-role-assignments/local-owner', {
  method: 'PUT', body: { roles: ['platform:points-auditor'] }, headers: { 'Idempotency-Key': 'local-reconcile-0001' },
}), 503, 'unknown provider outcome requires reconciliation');
const commands = await iamAdmin.request('/api/auth/local/iam-commands');
expectStatus(commands, 200, 'IAM manager can list recoverable commands');
const command = commands.body.commands?.find((item) => item.targetUserId === 'local-owner' && item.status === 'RECONCILE_REQUIRED');
assert(command?.operationId, 'reconcile-required command is durable');
const retried = await iamAdmin.request(`/api/auth/local/iam-commands/${command.operationId}/retry`, { method: 'POST' });
expectStatus(retried, 200, 'controlled retry succeeds');
assert(retried.body.operationId === command.operationId, 'retry preserves operation id');

expectStatus(await ordinary.request('/api/auth/logout', { method: 'POST' }), 200, 'logout succeeds');
expectStatus(await ordinary.request('/api/auth/session'), 401, 'logout revokes session');

process.stdout.write('points local identity full-stack smoke passed\n');
