/**
 * KeePassXC browser protocol client against a fake KeePassXC that speaks the
 * same protocol (key exchange, NaCl box, nonce + 1).
 */

const { describe, test, before, after } = require('node:test')
const assert = require('node:assert/strict')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const nacl = require('tweetnacl')
const {
  KeePassXC,
  incrementNonce,
  jsonEnd,
  entryUrl,
  pickEntry,
  findLogins
} = require('./keepassxc')
const widget = require('./main')

const b64 = u8 => Buffer.from(u8).toString('base64')
const fromB64 = s => new Uint8Array(Buffer.from(s, 'base64'))

function fakeKeePassXC (pipe) {
  const server = nacl.box.keyPair()
  const db = {
    associations: {},
    entries: [
      { url: 'ssh://server1:22', login: 'alice', password: 'pw-alice', name: 'server1', uuid: 'u1' },
      { url: 'ssh://multi:22', login: 'a', password: 'pw-a', name: 'multi a', uuid: 'u2' },
      { url: 'ssh://multi:22', login: 'b', password: 'pw-b', name: 'multi b', uuid: 'u3' },
      // an entry with only the host as URL; KeePassXC reads it as https://
      { url: 'https://10.0.0.5', login: 'admin', password: 'pw-admin', name: '10.0.0.5', uuid: 'u4' }
    ],
    seen: []
  }
  const srv = net.createServer(sock => {
    let clientKey = null
    let tested = false
    sock.setEncoding('utf8')
    sock.on('data', raw => {
      // the test client sends one message per write
      const req = JSON.parse(raw)
      if (req.action === 'change-public-keys') {
        clientKey = fromB64(req.publicKey)
        sock.write(JSON.stringify({
          action: req.action,
          publicKey: b64(server.publicKey),
          nonce: b64(incrementNonce(fromB64(req.nonce))),
          success: 'true'
        }))
        return
      }
      const msg = JSON.parse(Buffer.from(nacl.box.open(fromB64(req.message), fromB64(req.nonce), clientKey, server.secretKey)).toString())
      db.seen.push(msg)
      let out
      if (msg.action === 'associate') {
        db.associations.electerm = msg.idKey
        out = { success: 'true', id: 'electerm', hash: 'h' }
      } else if (msg.action === 'test-associate') {
        tested = db.associations[msg.id] === msg.key
        out = { success: tested ? 'true' : 'false' }
      } else if (!tested) {
        // like KeePassXC: no logins before a test-associate on this connection
        sock.write(JSON.stringify({ action: req.action, errorCode: '8', error: 'Association failed' }))
        return
      } else if (msg.action === 'get-logins') {
        const entries = db.entries.filter(e => e.url === msg.url)
        if (!entries.length) {
          sock.write(JSON.stringify({ action: req.action, errorCode: '15', error: 'No logins found' }))
          return
        }
        out = { entries, count: entries.length, success: 'true' }
      } else if (msg.action === 'set-login') {
        db.entries.push({ url: msg.url, login: msg.login, password: msg.password, name: msg.title, uuid: 'new' })
        out = { success: 'true' }
      }
      const nonce = incrementNonce(fromB64(req.nonce))
      sock.write(JSON.stringify({
        action: req.action,
        message: b64(nacl.box(Buffer.from(JSON.stringify({ ...out, action: msg.action })), nonce, clientKey, server.secretKey)),
        nonce: b64(nonce)
      }))
    })
  })
  return new Promise(resolve => srv.listen(pipe, () => resolve({ srv, db })))
}

describe('KeePassXC client', () => {
  const pipe = process.platform === 'win32'
    ? `\\\\.\\pipe\\electerm-widget-keepassxc-test-${process.pid}`
    : path.join(os.tmpdir(), `electerm-widget-keepassxc-test-${process.pid}.sock`)
  let fake
  let pairing = null
  let client

  before(async () => {
    fake = await fakeKeePassXC(pipe)
    client = new KeePassXC({
      path: pipe,
      loadPairing: () => pairing,
      savePairing: p => { pairing = p }
    })
  })
  after(() => {
    client.close()
    fake.srv.close()
  })

  test('not paired yet', async () => {
    assert.deepEqual(await client.status(), { paired: false })
    await assert.rejects(client.getLogins('ssh://server1:22'), /not paired/)
  })

  test('pairing is stored and confirmed by test-associate', async () => {
    await client.associate()
    assert.equal(pairing.id, 'electerm')
    assert.ok(pairing.idKey)
    assert.deepEqual(await client.status(), { paired: true, id: 'electerm' })
  })

  test('get-logins by url, with the pairing key', async () => {
    const entries = await client.getLogins('ssh://server1:22')
    assert.deepEqual(entries.map(e => [e.login, e.password]), [['alice', 'pw-alice']])
    const req = fake.db.seen.find(m => m.action === 'get-logins')
    assert.deepEqual(req.keys, [{ id: 'electerm', key: pairing.idKey }])
  })

  test('no entry is an empty list, not an error', async () => {
    assert.deepEqual(await client.getLogins('ssh://unknown:22'), [])
  })

  test('set-login stores a new entry', async () => {
    assert.equal(await client.setLogin({ url: 'ssh://new:22', login: 'u', password: 'p', title: 'new' }), true)
    assert.deepEqual((await client.getLogins('ssh://new:22')).map(e => e.password), ['p'])
  })

  test('get-logins on a new connection does the test-associate first', async () => {
    const c = new KeePassXC({ path: pipe, loadPairing: () => pairing, savePairing () {} })
    try {
      assert.equal((await c.getLogins('ssh://server1:22')).length, 1)
    } finally {
      c.close()
    }
  })

  test('only an unambiguous entry for the URL is used directly', async () => {
    const exact = await findLogins(client, { type: 'ssh', host: 'server1' })
    assert.equal(exact.pick.login, 'alice')
    assert.deepEqual(exact.alternatives, [])
    const multi = await findLogins(client, { type: 'ssh', host: 'multi' })
    assert.equal(multi.pick, 'choose')
    assert.deepEqual(multi.entries.map(e => e.login), ['a', 'b'])
  })

  test('without an entry for the URL: choose, with the bare host as alternative', async () => {
    const r = await findLogins(client, { type: 'rdp', host: '10.0.0.5' })
    assert.equal(r.url, 'rdp://10.0.0.5:3389')
    assert.deepEqual(r.entries, [])
    assert.deepEqual(r.alternatives.map(e => e.login), ['admin'])
    assert.equal(r.pick, 'choose')
    const none = await findLogins(client, { type: 'rdp', host: '10.0.0.6' })
    assert.deepEqual([none.entries, none.alternatives, none.pick], [[], [], 'choose'])
  })

  test('widget: search by host lists the entries, passwords stay out of the rows', async () => {
    widget.useClient(client)
    const r = await widget.run({ query: '10.0.0.5' })
    assert.equal(r.messageType, 'success')
    assert.deepEqual(r.table.rows, [{ id: 'u4', name: '10.0.0.5', login: 'admin', url: 'https://10.0.0.5' }])
    assert.ok(!JSON.stringify(r).includes('pw-admin'))
    const multi = await widget.run({ query: 'ssh://multi:22' })
    assert.deepEqual(multi.table.rows.map(row => row.login), ['a', 'b'])
  })

  test('widget: a row opens a tab with the password, ports by scheme', async () => {
    widget.useClient(client)
    const { table } = await widget.run({ query: 'server1' })
    const ssh = await widget.openSsh(table.rows[0])
    assert.deepEqual(
      [ssh.openTab.type, ssh.openTab.host, ssh.openTab.port, ssh.openTab.username, ssh.openTab.password],
      ['ssh', 'server1', 22, 'alice', 'pw-alice']
    )
    const rdp = await widget.openRdp(table.rows[0])
    assert.equal(rdp.openTab.port, 3389)
    const d = await widget.details(table.rows[0])
    assert.equal(d.details.find(x => x.label === 'Password').secret, true)
    await widget.forget()
    await assert.rejects(widget.openSsh(table.rows[0]), /Search again/)
  })

  test('widget: nothing found, and the provider calls', async () => {
    widget.useClient(client)
    const none = await widget.run({ query: 'nowhere' })
    assert.equal(none.messageType, 'warning')
    assert.equal((await widget.getCredentials({ type: 'ssh', host: 'server1' })).pick.login, 'alice')
    assert.deepEqual(await widget.saveCredentials({ target: { type: 'rdp', host: 'h2' }, login: 'u', password: 'p' }), { ok: true, url: 'rdp://h2:3389' })
  })

  test('widget: not paired asks to pair', async () => {
    widget.useClient(new KeePassXC({ path: pipe, loadPairing: () => null, savePairing () {} }))
    const r = await widget.run({ query: 'server1' })
    assert.equal(r.buttons[0].action, 'pair')
  })

  test('a closed KeePassXC is a readable error', async () => {
    const c = new KeePassXC({ path: pipe + '-missing', loadPairing: () => null, savePairing () {} })
    await assert.rejects(c.status().then(() => c.getLogins('x')), /not running|not paired/)
  })
})

describe('KeePassXC helpers', () => {
  test('search urls: a URL as it is, a host for each session type and https', () => {
    assert.deepEqual(widget.searchUrls('rdp://h:3390'), ['rdp://h:3390'])
    assert.deepEqual(widget.searchUrls(' h '), ['ssh://h:22', 'rdp://h:3389', 'telnet://h:23', 'https://h'])
    assert.deepEqual(widget.searchUrls('h:2222'), ['ssh://h:2222', 'rdp://h:2222', 'telnet://h:2222', 'https://h'])
    assert.deepEqual(widget.searchUrls('[fe80::1]'), ['ssh://[fe80::1]:22', 'rdp://[fe80::1]:3389', 'telnet://[fe80::1]:23', 'https://[fe80::1]'])
    assert.deepEqual(widget.searchUrls(''), [])
  })

  test('tab host from an IPv6 URL', () => {
    const tab = widget.buildTab({ url: 'ssh://[fe80::1]:2222', login: 'u', password: 'p' }, 'ssh')
    assert.deepEqual([tab.host, tab.port], ['fe80::1', 2222])
  })

  test('nonce + 1 is little endian with carry', () => {
    assert.deepEqual([...incrementNonce(Uint8Array.from([255, 255, 1]))], [0, 0, 2])
    assert.deepEqual([...incrementNonce(Uint8Array.from([1, 0]))], [2, 0])
  })

  test('jsonEnd finds the end of the first object, strings with braces included', () => {
    const a = JSON.stringify({ a: '}{"' })
    assert.equal(jsonEnd(a + '{"b":1}'), a.length)
    assert.equal(jsonEnd('{"a":'), -1)
  })

  test('entry url per bookmark type', () => {
    assert.equal(entryUrl({ host: 'server1' }), 'ssh://server1:22')
    assert.equal(entryUrl({ type: 'ssh', host: 'h', port: 2222 }), 'ssh://h:2222')
    assert.equal(entryUrl({ type: 'rdp', host: '10.0.0.5' }), 'rdp://10.0.0.5:3389')
    assert.equal(entryUrl({ type: 'ssh', host: 'fe80::1' }), 'ssh://[fe80::1]:22')
  })

  test('pick: the only entry, the one of the bookmark user, else choose', () => {
    const e = [{ login: 'a' }, { login: 'b' }]
    assert.equal(pickEntry([], ''), null)
    assert.deepEqual(pickEntry([{ login: 'x' }], ''), { login: 'x' })
    assert.deepEqual(pickEntry(e, 'b'), { login: 'b' })
    assert.equal(pickEntry(e, ''), 'choose')
    assert.equal(pickEntry([{ login: 'x' }], 'y'), 'choose')
  })
})
