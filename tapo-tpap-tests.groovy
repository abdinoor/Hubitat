#!/usr/bin/env groovy
/* Offline crypto + Hubitat lifecycle tests; tapo-tpap-live.py is read-only.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

def driver = new GroovyShell().parse(new File("tapo-tpap-lan-driver.groovy"))
Map state = [:], events = [:], savedData = [:], jobs = [:]
List requests = [], warnings = []
Map settings = [deviceIp: "192.0.2.10", tpapUsername: "fixture@example.test",
                tpapPassword: " fixture-pässword ", pollSeconds: 300, logEnable: false]
long clock = System.currentTimeMillis()
driver.binding = new Binding([
    state: state, settings: settings,
    now: { -> clock },
    sendEvent: { Map e -> events[e.name] = e.value },
    updateDataValue: { String k, String v -> savedData[k] = v },
    runIn: { int delay, String name, Map opts = [:] -> jobs[name] = [delay: delay, data: opts.data] },
    runInMillis: { int delay, String name -> jobs[name] = [delay: delay] },
    unschedule: { String name = null -> if (name) jobs.remove(name); else jobs.clear() },
    asynchttpPost: { String callback, Map params, Map token -> requests << [callback: callback, params: params, token: token] },
    log: [warn: { v -> warnings << v.toString() }, debug: { v -> }],
    metadata: { Closure c -> }
])
driver.run()
int checks = 0
def test = { String name, Closure body ->
    body()
    checks++
    println "PASS " + name
}
def rejects = { Closure body ->
    boolean rejected = false
    try { body() } catch (IllegalArgumentException e) { rejected = true }
    assert rejected
}
def response = { Map json, int status = 200, Object data = null ->
    new Expando(getJson: { -> json }, getStatus: { -> status },
                hasError: { -> status != 200 }, getData: { -> data })
}
def process = ["venv/bin/python", "tests/tpap_vectors.py"].execute()
String fixtures = process.inputStream.text
String errors = process.errorStream.text
assert process.waitFor() == 0 : errors
Map v = new JsonSlurper().parseText(fixtures)
byte[] key = v.key.decodeBase64(), nonce = v.nonce.decodeBase64()
test("Source avoids Hubitat-rejected System calls and array type expressions") {
    String source = new File("tapo-tpap-lan-driver.groovy").getText("UTF-8")
    assert !(source =~ /System\s*\.\s*arraycopy/)
    assert !(source =~ /\{\s*byte\[\]\s+\w+\s*->/)
    assert !source.contains("instanceof byte[]")
    assert !source.contains("as byte[]")
}
test("PBKDF2 UTF-8, leading/trailing whitespace, 80-byte output") {
    assert driver.b64(driver.pbkdf2(v.password.getBytes("UTF-8"), (v.register.dev_salt as String).decodeBase64(), 3000, 80)) == v.pbkdf2
}
test("RFC 5869 HKDF-SHA256 test case 1") {
    assert driver.hex(driver.hkdf(("0b" * 22).decodeHex(), "000102030405060708090a0b0c".decodeHex(),
        "f0f1f2f3f4f5f6f7f8f9".decodeHex(), 42)) ==
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
}
test("P-256 arithmetic matches independent ecdsa library") {
    def g = driver.decodePoint(driver.GENERATOR.decodeHex())
    assert driver.b64(driver.encodePoint(driver.pointMultiply(new BigInteger(v.x), g))) == v.scalarPoint
    assert driver.pointMultiply(driver.ORDER, g) == null
    assert driver.pointAdd(g, [g[0], driver.P.subtract(g[1])]) == null
    rejects { driver.decodePoint(([4] + ([0] * 64)) as byte[]) }
    rejects { driver.decodePoint([0] as byte[]) }
}
test("SPAKE2+ client matches independently generated server transcript") {
    Map share = driver.makeShare(v.register, v.userRandom.decodeBase64(), driver.credentialString(v.register), new BigInteger(v.x))
    assert share.shared == v.shared
    assert share.confirm == v.devConfirm
    assert share.params.user_share == v.userShare
    assert share.params.user_confirm == v.userConfirm
    assert driver.sessionKeys(v.shared.decodeBase64()) == [key: v.key, nonce: v.nonce]
}
test("AES-CCM matches Python cryptography for 7 message lengths") {
    v.ccm.each { row ->
        byte[] plain = row.plain.decodeBase64(), encrypted = row.cipher.decodeBase64()
        assert driver.b64(driver.ccmEncrypt(key, nonce, plain)) == row.cipher
        assert driver.b64(driver.ccmDecrypt(key, nonce, encrypted)) == row.plain
        encrypted[encrypted.length - 1] ^= 1
        rejects { driver.ccmDecrypt(key, nonce, encrypted) }
    }
}
test("Reject replay sequence, short packets and unauthenticated bytes") {
    Map session = [key: v.key, nonce: v.nonce]
    byte[] plain = '{"error_code":0}'.getBytes("UTF-8")
    byte[] frame = driver.cat([driver.u32(7), driver.ccmEncrypt(key, driver.nonceFor(nonce, 7), plain)])
    assert driver.decryptFrame(session, frame, 7) == plain
    rejects { driver.decryptFrame(session, frame, 8) }
    rejects { driver.decryptFrame(session, new byte[19], 7) }
    assert driver.hex(driver.u32(0xffffffffL)) == "ffffffff"
    rejects { driver.u32(0x100000000L) }
}
test("Unsupported suites, transforms and excessive work fail closed") {
    rejects { driver.makeShare(v.register + [cipher_suites: 2], v.userRandom.decodeBase64(), v.password, BigInteger.ONE) }
    rejects { driver.pbkdf2([1] as byte[], [2] as byte[], 10001, 80) }
    rejects { driver.credentialString([extra_crypt: [type: "other"]]) }
    assert driver.credentialString(v.register) == v.credentials
    assert driver.hex(driver.encodeW(new BigInteger("80", 16))) == "0080"
    assert driver.hex(driver.encodeW(new BigInteger("8000", 16))) == "8000"
    rejects { driver.unb64("TQ==AAAA") }
    rejects { driver.makeShare(v.register + [iterations: 4294967297L], v.userRandom.decodeBase64(), v.password, BigInteger.ONE) }
}
test("Address validation rejects URLs, missing octets and out-of-range values") {
    String saved = settings.deviceIp
    ["192..0.2.10", "http://192.0.2.10", "192.0.2.256", "192.0.2", "192.0.2.10/path"].each { ip ->
        settings.deviceIp = ip
        rejects { driver.configuredHost() }
    }
    settings.deviceIp = saved
    assert driver.configuredHost() == saved
}
test("Password shadow modes 2 and 4 use lowercase SHA-1 without normalization") {
    String saved = settings.tpapPassword
    try {
        [2, 4].each { mode ->
            settings.tpapPassword = "password"
            assert driver.credentialString([extra_crypt: [type: "password_shadow", params: [passwd_id: mode]]]) == "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
            settings.tpapPassword = " password "
            assert driver.credentialString([extra_crypt: [type: "password_shadow", params: [passwd_id: mode]]]) != "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
            settings.tpapPassword = v.password
            assert driver.credentialString([extra_crypt: [type: "password_shadow", params: [passwd_id: mode]]]) == v.credentials
        }
        rejects { driver.credentialString([extra_crypt: [type: "password_shadow", params: [passwd_id: 99]]]) }
    } finally { settings.tpapPassword = saved }
}
test("DAC root parses and missing/bogus attestation is rejected") {
    def root = driver.certificate(driver.ROOT_CA)
    root.checkValidity()
    root.verify(root.publicKey)
    rejects { driver.verifyDac([:], new byte[32], new byte[32]) }
}
test("DAC certificate chain and signature verify; changed nonce fails") {
    def root = driver.certificate(v.dac.root)
    Map reply = [dac_ca: v.dac.leaf, dac_proof: v.dac.proof]
    driver.verifyDacWithRoot(reply, v.shared.decodeBase64(), v.dac.nonce.decodeBase64(), root)
    rejects { driver.verifyDacWithRoot(reply, v.shared.decodeBase64(), new byte[32], root) }
    boolean failed = false
    try { driver.verifyDac(reply, v.shared.decodeBase64(), v.dac.nonce.decodeBase64()) }
    catch (Exception e) { failed = true }
    assert failed : "Untrusted test root must never pass production verification"
}
test("Fresh initialize saves IP before requesting, resets sessions, schedules polling") {
    driver.initialize()
    assert savedData.deviceIP == settings.deviceIp
    assert state.session == null && state.active == null
    assert jobs.poll.delay == 1
    driver.refresh()
    assert requests.size() == 1 && requests.last().token.stage == "discover"
}
test("Read requests coalesce and callbacks cannot cross transaction boundaries") {
    driver.refresh(); driver.refresh()
    assert state.queue.empty && requests.size() == 1
    driver.tpapResponse(response([error_code: 0, result: [:]]), [id: -1, stage: "discover"])
    assert requests.size() == 1 && state.active
}
test("TLS-only device fails closed without downgrade, backoff suppresses traffic") {
    driver.tpapResponse(response([error_code: 0, result: [tpap: [tls: 2, pake: [2]]]]), requests.last().token)
    assert state.active == null && state.session == null && events.commsError == "true"
    int count = requests.size()
    driver.on(); driver.refresh()
    assert requests.size() == count
}
test("Queue bounded, timeout clears secrets and drops commands without replay") {
    driver.initialize(); driver.refresh()
    20.times { driver.on() }
    assert state.queue.size() == 16
    Map oldToken = requests.last().token
    state.handshake = [shared: "test-only-secret"]
    driver.requestTimedOut(oldToken)
    assert state.handshake == null && state.session == null && state.queue.empty
    driver.initialize(); driver.refresh()
    driver.tpapResponse(response([:], 403), oldToken)
    assert state.active
}
test("KLAP-preferred discovery still tries TPAP and requires DAC") {
    driver.initialize(); requests.clear(); events.clear(); driver.refresh()
    driver.tpapResponse(response([error_code: 0, result: [sub_method: "discover", tpap_preferred: false]]), requests.last().token)
    assert requests.last().token.stage == "register"
    assert state.handshake.dac == true && state.handshake.port == 80
    state.handshake.random = v.userRandom
    driver.metaClass.randomScalar = { -> new BigInteger(v.x) }
    driver.tpapResponse(response([error_code: 0, result: v.register]), requests.last().token)
    Map share = new JsonSlurper().parseText(requests.last().params.body)
    assert requests.last().token.stage == "share" && share.params.dac_nonce
    driver.tpapResponse(response([error_code: 0, result: [dev_confirm: v.devConfirm, sessionId: "offline", start_seq: 1]]), requests.last().token)
    assert events.lastError == "Device advertised DAC but omitted its proof"
    assert state.session == null && events.commsError == "true"
    driver.metaClass = null
}
test("Absent or malformed discovery cannot silently enter compatibility mode") {
    [[:], [sub_method: "discover", tpap_preferred: true], [sub_method: "discover", tpap_preferred: false, tpap: null]].each { result ->
        driver.initialize(); requests.clear(); events.clear(); driver.refresh()
        driver.tpapResponse(response([error_code: 0, result: result]), requests.last().token)
        assert requests.size() == 1 && state.active == null && events.commsError == "true"
    }
}
test("Serialized session increments sequence, publishes only authenticated read-back") {
    driver.initialize()
    state.session = [key: v.key, nonce: v.nonce, host: settings.deviceIp,
                     port: 80, sid: "test-session", seq: 7, expires: clock + 60000]
    // Round-trip the state through JSON, as Hubitat does between callbacks.
    Map cloned = new JsonSlurper().parseText(JsonOutput.toJson(state))
    state.clear(); state.putAll(cloned)
    driver.on()
    assert state.session.seq == 8
    assert !events.containsKey("switch")
    Map first = requests.last()
    byte[] ack = driver.cat([driver.u32(7), driver.ccmEncrypt(key, driver.nonceFor(nonce, 7), '{"error_code":0}'.bytes)])
    driver.tpapResponse(response(null, 200, driver.b64(ack)), first.token)
    assert state.session.seq == 9 && requests.last().token.stage == "verify"
    assert !events.containsKey("switch")
    byte[] info = JsonOutput.toJson([error_code: 0, result: [device_on: true, brightness: 62, model: "S505D"]]).bytes
    byte[] packet = driver.cat([driver.u32(8), driver.ccmEncrypt(key, driver.nonceFor(nonce, 8), info)])
    driver.tpapResponse(response(null, 200, driver.b64(packet)), requests.last().token)
    assert events.switch == "on" && events.level == 62 && events.commsError == "false"
    assert events.lastError == "none" // A nonempty value clears stale Hubitat errors persistently.
    assert state.active == null
}
test("Full callback handshake preserves binary secrets through JSON serialization") {
    driver.initialize(); requests.clear(); events.clear(); driver.refresh()
    driver.tpapResponse(response([error_code: 0, result: [mac: "001122334455", tpap: [tls: 0, port: 80, pake: [2], dac: 0]]]), requests.last().token)
    assert requests.last().token.stage == "register"
    Map sent = new JsonSlurper().parseText(requests.last().params.body)
    assert sent.params.cipher_suites == [1] && sent.params.passcode_type == "userpw"
    // Inject deterministic entropy only in the offline harness, never in the source driver.
    state.handshake.random = v.userRandom
    driver.metaClass.randomScalar = { -> new BigInteger(v.x) }
    driver.tpapResponse(response([error_code: 0, result: v.register]), requests.last().token)
    assert requests.last().token.stage == "share"
    Map cloned = new JsonSlurper().parseText(JsonOutput.toJson(state))
    state.clear(); state.putAll(cloned)
    assert state.handshake.shared == v.shared && state.handshake.confirm == v.devConfirm
    driver.tpapResponse(response([error_code: 0, result: [dev_confirm: v.devConfirm, sessionId: "offline-session", start_seq: 42]]), requests.last().token)
    assert state.handshake == null && state.session.key == v.key
    assert requests.last().token.stage == "secure" && state.session.seq == 43
    driver.metaClass = null
    assert driver.randomScalar() != new BigInteger(v.x)
}
test("Authentication failure drops all queued work and never publishes success") {
    driver.initialize(); requests.clear(); events.clear(); driver.refresh(); driver.on()
    driver.tpapResponse(response([error_code: -1501]), requests.last().token)
    assert events.commsError == "true" && !events.containsKey("switch")
    assert state.queue.empty && state.session == null && state.handshake == null
    assert state.authBlocked
    clock += 3600000L
    int count = requests.size()
    driver.poll(); driver.on()
    assert requests.size() == count : "Authentication failure must not retry after cooldown"
    driver.resetSession()
    assert !state.authBlocked
}
test("TPAP access and lockout errors stop further logins until explicit reset") {
    [-2203, -2101].each { code ->
        driver.initialize(); requests.clear(); driver.refresh()
        driver.tpapResponse(response([error_code: code]), requests.last().token)
        assert state.authBlocked && events.lastError.contains(code.toString())
        clock += 3600000L
        driver.poll()
        assert requests.size() == 1
    }
}
test("Incorrect device confirmation never creates a usable session") {
    driver.initialize(); events.clear(); requests.clear()
    state.active = [id: 1234, stage: "share", host: settings.deviceIp, command: [method: "get_device_info", params: [:]]]
    state.handshake = [shared: v.shared, confirm: v.devConfirm, dac: false, port: 80]
    driver.tpapResponse(response([error_code: 0, result: [dev_confirm: driver.b64(new byte[32]), sessionId: "x", start_seq: 1]]), [id: 1234, stage: "share"])
    assert state.session == null && state.handshake == null && requests.empty
    assert events.commsError == "true" && !events.containsKey("switch")
}
test("Corrupted secure response cannot publish a device event") {
    driver.initialize(); events.clear(); requests.clear()
    state.session = [key: v.key, nonce: v.nonce, host: settings.deviceIp, port: 80, sid: "test", seq: 7, expires: clock + 60000]
    driver.refresh()
    byte[] info = JsonOutput.toJson([error_code: 0, result: [device_on: true]]).bytes
    byte[] packet = driver.cat([driver.u32(7), driver.ccmEncrypt(key, driver.nonceFor(nonce, 7), info)])
    packet[packet.length - 1] ^= 1
    driver.tpapResponse(response(null, 200, driver.b64(packet)), requests.last().token)
    assert events.commsError == "true" && !events.containsKey("switch")
}
test("Expired or exhausted session reconnects before sending a command") {
    [expires: clock - 1, seq: 0x100000000L].each { k, value ->
        driver.initialize(); requests.clear()
        state.session = [key: v.key, nonce: v.nonce, host: settings.deviceIp,
                         port: 80, sid: "old-session", seq: 1, expires: clock + 60000] + [(k): value]
        driver.off()
        assert requests.last().token.stage == "discover" && state.session == null
    }
}
test("A transport exception never logs session URLs or credentials") {
    driver.failSafe(new IOException("http://host/stok=SECRET/ds " + settings.tpapPassword))
    assert !warnings.last().contains("SECRET")
    assert !warnings.last().contains(settings.tpapPassword)
}
println "Offline tests passed: " + checks

if (args && args[0] == "--live") {
    assert args.length == 4 && args[3] == "--password-stdin" : "Use tapo-tpap-live.py for a non-echoed password prompt"
    settings.deviceIp = args[1]
    settings.tpapUsername = args[2]
    settings.tpapPassword = new BufferedReader(new InputStreamReader(System.in, "UTF-8")).readLine()
    requests.clear(); events.clear(); warnings.clear()
    driver.initialize()
    driver.refresh()
    int liveExit = 0
    try {
        while (requests) {
            Map pending = requests.remove(0)
            Map params = pending.params
            // Run the exact driver's outgoing request and deliver an async-shaped response.
            println "LIVE stage: " + pending.token.stage
            def connection = new URL(params.uri.toString()).openConnection()
            connection.requestMethod = "POST"
            connection.connectTimeout = 8000
            connection.readTimeout = 8000
            connection.instanceFollowRedirects = false
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", params.requestContentType)
            byte[] body = params.body instanceof byte[] ? params.body : params.body.toString().getBytes("UTF-8")
            connection.outputStream.withCloseable { it.write(body) }
            int status = connection.responseCode
            byte[] data = (status < 400 ? connection.inputStream : connection.errorStream)?.bytes ?: new byte[0]
            Map json = params.contentType == "application/json" ? new JsonSlurper().parseText(new String(data, "UTF-8")) as Map : null
            driver.tpapResponse(response(json, status, driver.b64(data)), pending.token)
            connection.disconnect()
        }
        if (events.commsError != "false") {
            println "LIVE FAILED: " + (events.lastError ?: "No authenticated response")
            liveExit = 1
        } else {
            println "LIVE READ VERIFIED: model=" + savedData.model + " switch=" + events.switch + " level=" + events.level
            println "No power or level commands were sent."
        }
    } catch (Exception e) {
        // Do not print network exceptions that could expose session URLs.
        println "LIVE FAILED: " + e.class.simpleName + " during transport"
        liveExit = 1
    } finally {
        settings.tpapPassword = ""
        state.clear()
    }
    System.exit(liveExit)
}
