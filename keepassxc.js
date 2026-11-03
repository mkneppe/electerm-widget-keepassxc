/**
 * KeePassXC as password store, through its browser integration protocol
 * (the one keepassxc-browser uses):
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md
 *
 * The widget talks to KeePassXC's socket directly (a named pipe on Windows),
 * the messages are JSON, everything after the key exchange encrypted with NaCl
 * box. Pairing ("associate") happens once and is confirmed in KeePassXC; the
 * widget keeps the pairing id and key, never the database or its master
 * password.
 * Entries are looked up by URL: ssh://host:port, rdp://host:port, ...
 */

const net = require('net')
const os = require('os')
const path = require('path')
const fs = require('fs')
const nacl = require('tweetnacl')

const NONCE_LENGTH = 24
const TIMEOUT = 60000 // KeePassXC may wait for the user (unlock, allow access)

const b64 = u8 => Buffer.from(u8).toString('base64')
const fromB64 = s => new Uint8Array(Buffer.from(s, 'base64'))

// the nonce of a reply is the request nonce + 1, little endian
function incrementNonce (nonce) {
  const n = Uint8Array.from(nonce)
  for (let i = 0; i < n.length; i++) {
    n[i] = (n[i] + 1) & 0xff
    if (n[i] !== 0) {
      break
    }
  }
  return n
}

function socketPath (env = process.env, platform = process.platform) {
  const name = 'org.keepassxc.KeePassXC.BrowserServer'
  if (platform === 'win32') {
    return `\\\\.\\pipe\\${name}_${env.USERNAME || os.userInfo().username}`
  }
  if (platform === 'darwin') {
    return path.join(env.TMPDIR || '/tmp', name)
  }
  const runtime = env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.()}`
  // the flatpak / snap location first, then the classic one
  const app = path.join(runtime, 'app', 'org.keepassxc.KeePassXC', name)
  return fs.existsSync(app) ? app : path.join(runtime, name)
}

class KeePassXC {
  /**
   * @param {object} opts
   * @param {function} opts.loadPairing () => {id, idKey} | null
   * @param {function} opts.savePairing (pairing) => void
   * @param {string} [opts.path] socket path, for tests
   */
  constructor (opts) {
    this.opts = opts
    this.keyPair = nacl.box.keyPair()
    this.clientID = b64(nacl.randomBytes(NONCE_LENGTH))
    this.serverKey = null
    // KeePassXC answers get-logins / set-login only after a test-associate
    // on the same connection
    this.verified = false
    this.socket = null
    this.buffer = ''
    this.pending = []
  }

  connect () {
    if (this.socket && !this.socket.destroyed) {
      return Promise.resolve()
    }
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(this.opts.path || socketPath())
      socket.setEncoding('utf8')
      socket.once('connect', () => {
        this.socket = socket
        resolve()
      })
      socket.once('error', e => {
        reject(new Error('KeePassXC is not running, or its browser integration is off (' + e.code + ')'))
      })
      socket.on('data', d => this.onData(d))
      socket.on('close', () => {
        this.socket = null
        this.serverKey = null
        this.verified = false
        for (const p of this.pending.splice(0)) {
          p.reject(new Error('KeePassXC closed the connection'))
        }
      })
    })
  }

  // a read can hold part of a message or several; KeePassXC sends one JSON
  // object per message without a separator
  onData (chunk) {
    this.buffer += chunk
    let msg
    while (this.buffer) {
      const end = jsonEnd(this.buffer)
      if (end < 0) {
        return
      }
      try {
        msg = JSON.parse(this.buffer.slice(0, end))
      } catch (e) {
        this.buffer = ''
        return
      }
      this.buffer = this.buffer.slice(end)
      const i = this.pending.findIndex(p => p.action === msg.action)
      if (i >= 0) {
        const [p] = this.pending.splice(i, 1)
        clearTimeout(p.timer)
        p.resolve(msg)
      }
    }
  }

  send (request) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = this.pending.filter(p => p.timer !== timer)
        reject(new Error('KeePassXC did not answer'))
      }, TIMEOUT)
      this.pending.push({ action: request.action, resolve, reject, timer })
      this.socket.write(JSON.stringify(request))
    })
  }

  async exchangeKeys () {
    await this.connect()
    if (this.serverKey) {
      return
    }
    const nonce = nacl.randomBytes(NONCE_LENGTH)
    const res = await this.send({
      action: 'change-public-keys',
      publicKey: b64(this.keyPair.publicKey),
      nonce: b64(nonce),
      clientID: this.clientID
    })
    if (!res.publicKey || res.success !== 'true') {
      throw new Error(res.error || 'KeePassXC refused the key exchange')
    }
    this.serverKey = fromB64(res.publicKey)
    this.verified = false
  }

  /**
   * One encrypted request.
   * @param {object} payload the message, with its action
   * @param {boolean} triggerUnlock ask KeePassXC to show its unlock dialog
   */
  async call (payload, triggerUnlock = false) {
    await this.exchangeKeys()
    const nonce = nacl.randomBytes(NONCE_LENGTH)
    const message = nacl.box(
      Buffer.from(JSON.stringify(payload)),
      nonce,
      this.serverKey,
      this.keyPair.secretKey
    )
    const res = await this.send({
      action: payload.action,
      message: b64(message),
      nonce: b64(nonce),
      clientID: this.clientID,
      ...(triggerUnlock ? { triggerUnlock: 'true' } : {})
    })
    if (res.error || !res.message) {
      const e = new Error(res.error || 'KeePassXC: no answer for ' + payload.action)
      e.code = res.errorCode
      throw e
    }
    const expected = b64(incrementNonce(nonce))
    if (res.nonce !== expected) {
      throw new Error('KeePassXC answered with a wrong nonce')
    }
    const plain = nacl.box.open(fromB64(res.message), fromB64(res.nonce), this.serverKey, this.keyPair.secretKey)
    if (!plain) {
      throw new Error('KeePassXC answer could not be decrypted')
    }
    return JSON.parse(Buffer.from(plain).toString('utf8'))
  }

  keys () {
    const pairing = this.opts.loadPairing()
    return pairing ? [{ id: pairing.id, key: pairing.idKey }] : []
  }

  /**
   * Pair electerm with the open database; KeePassXC asks the user for a name.
   */
  async associate () {
    const idKey = b64(nacl.box.keyPair().publicKey)
    const res = await this.call({
      action: 'associate',
      key: b64(this.keyPair.publicKey),
      idKey
    }, true)
    if (res.success !== 'true' || !res.id) {
      throw new Error('KeePassXC did not confirm the pairing')
    }
    const pairing = { id: res.id, idKey, hash: res.hash }
    this.opts.savePairing(pairing)
    return { id: res.id }
  }

  // the pairing key, confirmed by KeePassXC on this connection
  async pairedKey () {
    const [key] = this.keys()
    if (!key) {
      throw new Error('electerm is not paired with KeePassXC yet: Settings > Widgets > KeePassXC Search, press "Search / pair" with an empty field, then "Pair with KeePassXC"')
    }
    await this.exchangeKeys()
    if (!this.verified) {
      const res = await this.call({ action: 'test-associate', id: key.id, key: key.key }, true)
      if (res.success !== 'true') {
        throw new Error('KeePassXC does not know this pairing any more: pair again in Settings > Widgets > KeePassXC Search')
      }
      this.verified = true
    }
    return key
  }

  /**
   * @return {Promise<{paired: boolean, id?: string}>}
   */
  async status () {
    const [key] = this.keys()
    if (!key) {
      return { paired: false }
    }
    try {
      const res = await this.call({ action: 'test-associate', id: key.id, key: key.key }, true)
      this.verified = res.success === 'true'
      return { paired: this.verified, id: key.id }
    } catch (e) {
      return { paired: false, id: key.id, error: e.message }
    }
  }

  /**
   * @param {string} url e.g. ssh://host:22
   * @return {Promise<{login: string, password: string, name: string, uuid: string}[]>}
   */
  async getLogins (url) {
    const key = await this.pairedKey()
    try {
      const res = await this.call({ action: 'get-logins', url, submitUrl: url, keys: [key] }, true)
      return (res.entries || []).map(e => ({
        login: e.login,
        password: e.password,
        name: e.name,
        uuid: e.uuid
      }))
    } catch (e) {
      // 15: no logins found
      if (String(e.code) === '15') {
        return []
      }
      throw e
    }
  }

  /**
   * A new entry, or an update of `uuid`.
   */
  async setLogin ({ url, login, password, title, uuid }) {
    const key = await this.pairedKey()
    const res = await this.call({
      action: 'set-login',
      url,
      submitUrl: url,
      id: key.id,
      nonce: b64(nacl.randomBytes(NONCE_LENGTH)),
      login,
      password,
      group: 'electerm',
      groupUuid: '',
      uuid: uuid || '',
      title: title || url
    }, true)
    return res.success === 'true'
  }

  close () {
    this.socket?.destroy()
  }
}

// end of the first complete JSON object in `s`, -1 when it is incomplete
function jsonEnd (s) {
  let depth = 0
  let inStr = false
  let esc = false
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (inStr) {
      if (esc) {
        esc = false
      } else if (c === '\\') {
        esc = true
      } else if (c === '"') {
        inStr = false
      }
    } else if (c === '"') {
      inStr = true
    } else if (c === '{') {
      depth++
    } else if (c === '}') {
      depth--
      if (depth === 0) {
        return i + 1
      }
    }
  }
  return -1
}

/**
 * The URL of a bookmark's entry, e.g. ssh://host:22.
 */
function entryUrl (tab) {
  const type = tab.type === 'rdp' || tab.type === 'vnc' || tab.type === 'telnet'
    ? tab.type
    : 'ssh'
  const ports = { ssh: 22, rdp: 3389, vnc: 5900, telnet: 23 }
  const host = String(tab.host || '').includes(':') ? `[${tab.host}]` : tab.host
  return `${type}://${host}:${tab.port || ports[type]}`
}

/**
 * Entries for a bookmark, by its URL (ssh://host:port, ...). Only an unambiguous
 * match is used directly; otherwise the user chooses, also from the entries for
 * the bare host (KeePassXC reads a URL without scheme as https://host) or a new
 * entry for the URL.
 * @param {KeePassXC} kp
 * @param {{type, host, port, username}} target the bookmark
 * @return {Promise<{url, entries, alternatives, pick}>} pick: the entry to
 *   use or 'choose'
 */
async function findLogins (kp, target) {
  const url = entryUrl(target)
  const entries = await kp.getLogins(url)
  const pick = pickEntry(entries, target.username)
  if (pick && pick !== 'choose') {
    return { url, entries, alternatives: [], pick }
  }
  const host = String(target.host || '').includes(':') ? `[${target.host}]` : target.host
  const known = new Set(entries.map(e => e.uuid))
  const alternatives = (await kp.getLogins(`https://${host}`))
    .filter(e => !known.has(e.uuid))
  return { url, entries, alternatives, pick: 'choose' }
}

/**
 * The entry for a bookmark: the one with its user name, else the only one.
 * @return {object|null|'choose'} 'choose' when the user has to pick
 */
function pickEntry (entries, username) {
  if (!entries.length) {
    return null
  }
  if (username) {
    // the bookmark names the user: only an entry for that user fits
    const same = entries.filter(e => e.login === username)
    return same.length === 1 ? same[0] : 'choose'
  }
  return entries.length === 1 ? entries[0] : 'choose'
}

module.exports = {
  KeePassXC,
  socketPath,
  incrementNonce,
  jsonEnd,
  entryUrl,
  pickEntry,
  findLogins
}
