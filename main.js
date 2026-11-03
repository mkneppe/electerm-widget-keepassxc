/**
 * electerm widget: look up SSH / RDP / Telnet logins in KeePassXC and open a
 * session with them. Talks to KeePassXC through its browser integration
 * (see keepassxc.js); the pairing is kept in .state.json next to this file,
 * passwords only in memory, until the next search or "Forget passwords".
 */

const fs = require('fs')
const path = require('path')
const { KeePassXC, entryUrl, findLogins } = require('./keepassxc')

const STATE_FILE = path.join(__dirname, '.state.json')
const defaultPorts = { ssh: 22, rdp: 3389, telnet: 23 }

let client = null
// uuid -> { name, login, password, url } of the last search
const found = new Map()

function loadPairing () {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')).pairing || null
  } catch (e) {
    return null
  }
}

function savePairing (pairing) {
  fs.writeFileSync(STATE_FILE, JSON.stringify({ pairing }), { mode: 0o600 })
}

function getClient () {
  if (!client) {
    client = new KeePassXC({ loadPairing, savePairing })
  }
  return client
}

// tests: a client for a fake KeePassXC
function useClient (c) {
  client = c
  found.clear()
}

const bracket = host => host.includes(':') ? `[${host}]` : host

/**
 * The URLs to ask KeePassXC for. A URL is taken as it is; for a host (or
 * host:port) the entries electerm would look up for its bookmarks
 * (ssh://host:22, rdp://host:3389, telnet://host:23) and the bare host, which
 * KeePassXC reads as https://host.
 */
function searchUrls (query) {
  const q = String(query || '').trim()
  if (!q) {
    return []
  }
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(q)) {
    return [q]
  }
  let host = q
  let port = ''
  const v6 = q.match(/^\[(.+)\](?::(\d+))?$/)
  const v4 = q.match(/^([^:]+):(\d+)$/)
  if (v6) {
    host = v6[1]
    port = v6[2] || ''
  } else if (v4) {
    host = v4[1]
    port = v4[2]
  }
  return [
    ...Object.entries(defaultPorts).map(([type, p]) => `${type}://${bracket(host)}:${port || p}`),
    `https://${bracket(host)}`
  ]
}

/**
 * The tab electerm opens for an entry: host and port from the URL it was found
 * under, the port only when the URL's scheme is the session type.
 */
function buildTab (entry, type) {
  let uri
  try {
    uri = new URL(entry.url)
  } catch (e) {}
  const host = uri && uri.hostname.replace(/^\[(.*)\]$/, '$1')
  if (!host) {
    throw new Error(`No host in ${entry.url}`)
  }
  const port = uri.protocol === `${type}:` && uri.port
    ? Number(uri.port)
    : defaultPorts[type]
  const tab = {
    type,
    title: entry.name || `${type.toUpperCase()} ${host}`,
    host,
    port,
    username: entry.login || '',
    password: entry.password || ''
  }
  if (type === 'ssh') {
    Object.assign(tab, { authType: 'password', enableSsh: true, enableSftp: true })
  }
  return tab
}

const pairButton = label => ({ label, action: 'pair' })
const forgetButton = () => ({ label: 'Forget passwords', action: 'forget' })

function failure (e) {
  const notPaired = /not paired|pair again/.test(e.message)
  return {
    message: e.message,
    messageType: 'error',
    buttons: notPaired ? [pairButton('Pair with KeePassXC')] : undefined
  }
}

async function search (query) {
  const kp = getClient()
  found.clear()
  const urls = searchUrls(query)
  const rows = []
  for (const url of urls) {
    for (const e of await kp.getLogins(url)) {
      if (!found.has(e.uuid)) {
        found.set(e.uuid, { ...e, url })
        rows.push({ id: e.uuid, name: e.name, login: e.login, url })
      }
    }
  }
  if (!rows.length) {
    return {
      message: `No entries in KeePassXC for ${query}`,
      messageType: 'warning',
      details: [{ label: 'Looked up', value: urls.join(', ') }]
    }
  }
  return {
    message: `${rows.length} ${rows.length === 1 ? 'entry' : 'entries'} for ${query}`,
    messageType: 'success',
    table: {
      columns: [
        { key: 'name', title: 'Name' },
        { key: 'login', title: 'User', copy: true },
        { key: 'url', title: 'Found for' }
      ],
      rows,
      rowButtons: [
        { label: 'SSH', action: 'openSsh' },
        { label: 'RDP', action: 'openRdp' },
        { label: 'Telnet', action: 'openTelnet' },
        { label: 'Details', action: 'details' }
      ]
    },
    buttons: [forgetButton()]
  }
}

async function run (values = {}) {
  const query = String(values.query || '').trim()
  try {
    const kp = getClient()
    if (!kp.keys().length) {
      return {
        message: 'Not paired with KeePassXC yet (needed once). Open and unlock your database in KeePassXC and turn on Settings > Browser Integration, then press "Pair with KeePassXC" and confirm the request in KeePassXC with a name, e.g. "electerm".',
        messageType: 'info',
        buttons: [pairButton('Pair with KeePassXC')]
      }
    }
    if (!query) {
      const st = await kp.status()
      return st.paired
        ? { message: `Paired with KeePassXC as "${st.id}". Enter a host or URL to search.`, messageType: 'success', buttons: [pairButton('Pair again')] }
        : failure(new Error(st.error || 'KeePassXC does not know this pairing any more, pair again'))
    }
    return await search(query)
  } catch (e) {
    return failure(e)
  }
}

async function pair (values = {}) {
  try {
    const { id } = await getClient().associate()
    const paired = `Paired with KeePassXC as "${id}".`
    const query = String(values.query || '').trim()
    if (!query) {
      return { message: paired, messageType: 'success' }
    }
    const res = await search(query)
    return { ...res, message: `${paired} ${res.message}` }
  } catch (e) {
    return failure(e)
  }
}

function entryOf (row) {
  const entry = row && found.get(row.id)
  if (!entry) {
    throw new Error('Search again: passwords are kept only until the next search')
  }
  return entry
}

async function open (row, type) {
  const tab = buildTab(entryOf(row), type)
  return {
    openTab: tab,
    message: `Opening ${type.toUpperCase()} ${tab.username ? tab.username + '@' : ''}${tab.host}:${tab.port}`,
    messageType: 'success'
  }
}

async function details (row) {
  const entry = entryOf(row)
  return {
    details: [
      { label: 'Name', value: entry.name || '', copy: true },
      { label: 'User', value: entry.login || '', copy: true },
      { label: 'Password', value: entry.password || '', secret: true, copy: true },
      { label: 'Found for', value: entry.url, copy: true }
    ]
  }
}

async function forget () {
  found.clear()
  return { message: 'Passwords cleared from memory.', messageType: 'info' }
}

/**
 * electerm.credentialProvider: called by electerm when a bookmark without a
 * saved password connects, and to save a login after it worked.
 */
async function getCredentials (target) {
  return findLogins(getClient(), target)
}

async function saveCredentials ({ target, login, password }) {
  const url = entryUrl(target)
  const ok = await getClient().setLogin({
    url,
    login,
    password,
    title: target.title || `${login}@${target.host}`
  })
  return { ok, url }
}

module.exports = {
  run,
  pair,
  forget,
  details,
  openSsh: row => open(row, 'ssh'),
  openRdp: row => open(row, 'rdp'),
  openTelnet: row => open(row, 'telnet'),
  getCredentials,
  saveCredentials,
  searchUrls,
  buildTab,
  useClient
}
