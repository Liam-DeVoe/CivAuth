'use strict'

const net = require('node:net')
const mc = require('minecraft-protocol')

const CIVAUTH_URL = must('CIVAUTH_URL').replace(/\/+$/, '')
const JOIN_SECRET = must('JOIN_SECRET')
const LISTEN_PORT = Number(process.env.LISTEN_PORT || 25565)
const LISTEN_HOST = process.env.LISTEN_HOST || '0.0.0.0'
const MOTD = process.env.MOTD || '§aCivAuth verification§r\nJoin to get a verification code'
const MAX_PLAYERS_SHOWN = Number(process.env.MAX_PLAYERS_SHOWN || 5)
const EXPECT_PROXY_HEADER = process.env.PROXY_PROTOCOL !== '0'
const JOINS_PER_MINUTE = Number(process.env.JOINS_PER_MINUTE || 6)
const PINGS_PER_MINUTE = Number(process.env.PINGS_PER_MINUTE || 120)
const ISSUE_TIMEOUT_MS = 5000

function must (name) {
  const value = process.env[name]
  if (!value) {
    console.error(`${name} is not set`)
    process.exit(2)
  }
  return value
}

const internal = mc.createServer({
  host: '127.0.0.1',
  port: 0,
  version: false,
  fallbackVersion: process.env.FALLBACK_VERSION || undefined,
  'online-mode': true,
  motd: MOTD,
  maxPlayers: 0,
  hideErrors: true,
  beforePing (response, client) {
    response.version = { name: 'any version', protocol: client.protocolVersion }
    response.players = { online: 0, max: MAX_PLAYERS_SHOWN, sample: [] }
    return response
  },
  async beforeLogin (client) {
    const write = client.write.bind(client)
    client.write = (name, params) => { if (name !== 'success') write(name, params) }
    try {
      const uuid = client.uuid.replace(/-/g, '')
      let reason
      try {
        const code = await issueCode(uuid, client.username)
        console.log(`verified ${client.username} ${uuid} from ${client.realAddress}`)
        const rule = { text: '\n' + '═'.repeat(30) + '\n', color: 'gold' }
        reason = {
          text: '',
          extra: [
            rule,
            { text: '\nYour CivAuth code is:\n', color: 'white' },
            { text: `\n${code.slice(0, 3)} ${code.slice(3)}\n`, color: 'green', bold: true },
            rule,
          ]
        }
      } catch (err) {
        console.error(`could not issue a code for ${client.username}: ${err.message}`)
        reason = { text: 'CivAuth could not issue a code. Try again in a minute.', color: 'red' }
      }
      if (!client.ended) client.end('verified', JSON.stringify(reason))
    } catch (err) {
      console.error(`login handler failed for ${client.username}: ${err.message}`)
      if (!client.ended) client.end('error')
    }
  }
})

internal.on('error', err => console.error('minecraft server error', err))

async function issueCode (uuid, name) {
  const response = await fetch(`${CIVAUTH_URL}/join/issue`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${JOIN_SECRET}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ uuid, name }),
    redirect: 'error',
    signal: AbortSignal.timeout(ISSUE_TIMEOUT_MS)
  })
  const out = await response.text()
  if (!response.ok) throw new Error(`${response.status} ${out.trim()}`)
  const code = JSON.parse(out).code
  if (!/^\d{6}$/.test(code)) throw new Error(`bad reply ${out.trim()}`)
  return code
}

const recentJoins = new Map()
const recentPings = new Map()
const pendingAddresses = []
internal.on('connection', client => { client.realAddress = pendingAddresses.shift() || '?' })

function allowed (address, isLogin) {
  const now = Date.now()
  const seen = isLogin ? recentJoins : recentPings
  const limit = isLogin ? JOINS_PER_MINUTE : PINGS_PER_MINUTE
  const times = (seen.get(address) || []).filter(t => now - t < 60_000)
  times.push(now)
  seen.set(address, times)
  if (times.length > limit) {
    if (times.length === limit + 1) console.log(`rate limited ${address} (${isLogin ? 'logins' : 'pings'})`)
    return false
  }
  return true
}
setInterval(() => {
  const now = Date.now()
  for (const seen of [ recentJoins, recentPings ]) {
    for (const [address, times] of seen) {
      if (times.every(t => now - t >= 60_000)) seen.delete(address)
    }
  }
}, 60_000).unref()

function readVarInt (buf, at) {
  let value = 0
  for (let shift = 0; shift <= 28; shift += 7) {
    if (at >= buf.length) return null
    const byte = buf[at++]
    value |= (byte & 0x7f) << shift
    if (!(byte & 0x80)) return [value, at]
  }
  return false
}

function classify (buf) {
  if (buf.length === 0) return 'need'
  if (buf[0] === 0xfe) return 'status'
  let at = 0
  for (const field of ['length', 'id', 'protocol', 'host']) {
    const read = readVarInt(buf, at)
    if (read === null) return 'need'
    if (read === false) return 'bad'
    at = read[1]
    if (field === 'id' && read[0] !== 0) return 'bad'
    if (field === 'host') at += read[0]
  }
  at += 2
  const state = readVarInt(buf, at)
  if (state === null) return 'need'
  if (state === false) return 'bad'
  return state[0] === 2 ? 'login' : 'status'
}

const V2_SIGNATURE = Buffer.from('0d0a0d0a000d0a515549540a', 'hex')

function stripProxyHeader (buf, fallback) {
  if (buf.length >= 16 && buf.subarray(0, 12).equals(V2_SIGNATURE)) {
    const length = buf.readUInt16BE(14)
    if (buf.length < 16 + length) return null
    const family = buf[13] >> 4
    let address = fallback
    if ((buf[12] & 0x0f) === 1) {
      if (family === 1 && length >= 12) address = Array.from(buf.subarray(16, 20)).join('.')
      if (family === 2 && length >= 36) address = ipv6(buf.subarray(16, 32))
    }
    return [address, buf.subarray(16 + length)]
  }
  if (buf.length >= 6 && buf.subarray(0, 6).toString('latin1') === 'PROXY ') {
    const end = buf.indexOf('\r\n')
    if (end === -1) return buf.length > 107 ? [fallback, buf] : null
    const fields = buf.subarray(0, end).toString('latin1').split(' ')
    return [fields[2] || fallback, buf.subarray(end + 2)]
  }
  if (buf.length < 16 && (V2_SIGNATURE.subarray(0, buf.length).equals(buf) || 'PROXY '.startsWith(buf.toString('latin1')))) {
    return null
  }
  return [fallback, buf]
}

function ipv6 (bytes) {
  const parts = []
  for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16))
  return parts.join(':')
}

const publicServer = net.createServer(socket => {
  socket.setNoDelay(true)
  let head = Buffer.alloc(0)
  let handedOff = false
  const start = (address, rest, isLogin) => {
    handedOff = true
    if (!allowed(address, isLogin)) {
      socket.destroy()
      return
    }
    const upstream = net.connect(internal.socketServer.address().port, '127.0.0.1')
    upstream.setNoDelay(true)
    upstream.on('error', () => socket.destroy())
    socket.on('error', () => upstream.destroy())
    pendingAddresses.push(address)
    upstream.once('connect', () => {
      if (rest.length) upstream.write(rest)
      socket.pipe(upstream).pipe(socket)
    })
  }
  let address = null
  socket.on('data', chunk => {
    if (handedOff) return
    head = Buffer.concat([head, chunk])
    if (address === null) {
      const parsed = EXPECT_PROXY_HEADER ? stripProxyHeader(head, socket.remoteAddress) : [ socket.remoteAddress, head ]
      if (parsed === null) {
        if (head.length > 256) socket.destroy()
        return
      }
      address = parsed[0]
      head = parsed[1]
    }
    const kind = classify(head)
    if (kind === 'need' && head.length < 512) return
    socket.pause()
    socket.removeAllListeners('data')
    start(address, head, kind === 'login')
  })
  socket.setTimeout(10_000, () => { if (!handedOff) socket.destroy() })
})

internal.on('listening', () => {
  publicServer.listen(LISTEN_PORT, LISTEN_HOST, () => {
    console.log(`listening on ${LISTEN_HOST}:${LISTEN_PORT}, issuing codes from ${CIVAUTH_URL}`)
  })
})
publicServer.on('error', err => { console.error('listener error', err); process.exit(1) })
