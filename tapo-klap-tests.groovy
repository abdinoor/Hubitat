#!/usr/bin/env groovy
// Offline tests of the actual driver; fake credentials, no network requests.
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

def driver = new GroovyShell().parse(new File('tapo-klap-lan-driver.groovy'))
Map state = [:], events = [:], data = [deviceIP:'192.0.2.1'], jobs = [:]
Map settings = [manualIp:'192.0.2.2', klapUsername:'fixture@example.test', klapPassword:' fixture-pässword ', pollRefresh:300, logEnable:false]
List requests = [], logs = []
long clock = 1000000L
driver.binding = new Binding([state:state, settings:settings, now:{ -> clock },
    metadata:{ Closure c -> }, sendEvent:{ Map e -> events[e.name] = e.value },
    getDataValue:{ String k -> data[k] }, updateDataValue:{ String k, String v -> data[k] = v },
    runIn:{ int delay, String name, Map opts=[:] -> jobs[name]=[delay:delay,data:opts.data] },
    runInMillis:{ int delay, String name -> jobs[name]=[delay:delay] },
    unschedule:{ String name=null -> if (name) jobs.remove(name); else jobs.clear() },
    asynchttpPost:{ String cb, Map params, Map token -> requests << [cb:cb,params:params,token:token] },
    device:[displayName:'Offline fixture',currentValue:{ String k -> events[k] }],
    log:[info:{ v -> logs << v.toString() },warn:{ v -> logs << v.toString() },debug:{ v -> logs << v.toString() }]])
driver.run()
def p = ['venv/bin/python','tests/klap_vectors.py'].execute()
String output = p.inputStream.text, errors = p.errorStream.text
assert p.waitFor() == 0 : errors
Map fixture = new JsonSlurper().parseText(output)
int checks = 0
def test = { String name, Closure body -> body(); checks++; println 'PASS ' + name }
def serialized = { -> Map copy = new JsonSlurper().parseText(JsonOutput.toJson(state)); state.clear(); state.putAll(copy) }
def resp = { String body, int status=200, Map headers=[:] -> new Expando(getStatus:{->status}, hasError:{->status!=200}, getData:{->body}, getHeaders:{->headers}) }
def fresh = { -> requests.clear(); events.clear(); driver.updated() }
def finishHandshake = { boolean v2=true ->
    byte[] remote = fixture.remote.decodeBase64(), local = state.klapHandshake.localSeed.decodeBase64()
    byte[] auth = driver.klapComputeAuthHash(settings.klapUsername, settings.klapPassword, v2)
    byte[] proof = driver.klapHandshake1Hash(local, remote, auth, v2)
    byte[] response = new byte[48]
    for (int i=0;i<16;i++) response[i]=remote[i]
    for (int i=0;i<32;i++) response[i+16]=proof[i]
    serialized()
    driver.klapResponse(resp(response.encodeBase64().toString(),200,['Set-Cookie':['TP_SESSIONID=fixture; Path=/']]),requests.last().token)
    assert requests.last().token.stage=='handshake2'
    assert requests.last().params.body.encodeBase64().toString()==driver.klapHandshake2Hash(local,remote,auth,v2).encodeBase64().toString()
    serialized()
    driver.klapResponse(resp(''),requests.last().token)
    assert requests.last().token.stage=='request'
}
// Build a server response at the request sequence, without modifying persisted keys/counter.
def secureReply = { Map reply ->
    Map saved = new JsonSlurper().parseText(JsonOutput.toJson(state.klapSession))
    state.klapSession.seq = (state.klapActive.seq as Integer)-1
    byte[] frame = driver.klapEncrypt(JsonOutput.toJson(reply).getBytes('UTF-8'))[0]
    state.klapSession=saved
    driver.klapResponse(resp(frame.encodeBase64().toString()),requests.last().token)
}
test('No blocking waits or Hubitat-forbidden array expressions') {
    String source = new File('tapo-klap-lan-driver.groovy').text
    assert !source.contains('pauseExecution') && !source.contains('syncResult')
    assert !source.contains('instanceof byte[]') && !source.contains('System.arraycopy')
    assert source.contains('singleThreaded: true')
}
test('Credentials preserve UTF-8 and leading/trailing spaces') {
    assert driver.getKlapCredentials().password == fixture.password
}
fixture.vectors.each { v ->
    test('Independent KLAP ' + (v.v2?'v2':'v1') + ' hashes, keys, signed sequence, AES frame and state serialization') {
        byte[] local=fixture.local.decodeBase64(), remote=fixture.remote.decodeBase64()
        byte[] auth=driver.klapComputeAuthHash(fixture.user,fixture.password,v.v2)
        assert auth.encodeBase64().toString()==v.auth
        assert driver.klapHandshake1Hash(local,remote,auth,v.v2).encodeBase64().toString()==v.handshake1
        assert driver.klapHandshake2Hash(local,remote,auth,v.v2).encodeBase64().toString()==v.handshake2
        driver.klapDeriveSessionKeys(local,remote,auth)
        assert state.klapSession.aesKey==v.key && state.klapSession.aesIvBase==v.iv && state.klapSession.signature==v.sig
        assert state.klapSession.seq==v.initial
        serialized()
        List encrypted=driver.klapEncrypt(v.plaintext.decodeBase64())
        assert encrypted[0].encodeBase64().toString()==v.encrypted
        assert encrypted[1]==v.initial+1
        serialized()
        assert driver.klapDecrypt(v.encrypted.decodeBase64(), encrypted[1]).encodeBase64().toString()==v.plaintext
    }
}
test('Update saves the new IP before the first HTTP request and resets legacy state') {
    data.deviceIP='192.0.2.1'; fresh()
    assert data.deviceIP=='192.0.2.2' && requests.size()==1
    assert requests[0].params.uri=='http://192.0.2.2/app/handshake1'
    assert state.klapSession==null && jobs.poll.delay==300
}
test('Refresh coalesces while commands queue without parallel HTTP') {
    driver.refresh(); driver.refresh(); driver.on(); driver.off()
    assert requests.size()==1 && state.klapQueue*.method==['set_device_info','set_device_info']
}
test('Stale transaction and wrong-stage callbacks are ignored') {
    int count=requests.size()
    driver.klapResponse(resp('',500),[id:-1,stage:'handshake1'])
    driver.klapResponse(resp('',500),requests.last().token+[stage:'request'])
    assert requests.size()==count && state.klapActive
}
[false,true].each { v2 ->
    test('Callback handshake ' + (v2?'v2':'v1') + ' survives JSON state between stages') {
        fresh(); finishHandshake(v2)
        assert state.klapHandshake==null && state.klapSession.format==2
        assert requests.last().params.headers.Cookie=='TP_SESSIONID=fixture'
        assert !events.containsKey('switch')
        serialized(); secureReply([error_code:0,result:[device_on:false,brightness:62]])
        assert events.switch=='off' && events.level==62 && events.commsError=='false' && events.lastError=='none'
        assert state.klapActive==null
    }
}
test('Commands publish read-back only, with two distinct sequence numbers') {
    driver.on(); int seq=state.klapActive.seq
    secureReply([error_code:0])
    assert events.switch=='off' && state.klapActive.stage=='verify' && state.klapActive.seq==seq+1
    secureReply([error_code:0,result:[device_on:true,brightness:62]])
    assert events.switch=='on' && events.commsError=='false' && state.klapActive==null
}
test('Read-back mismatch reports failure rather than optimistic success') {
    driver.off(); secureReply([error_code:0]); secureReply([error_code:0,result:[device_on:true,brightness:62]])
    assert events.commsError=='true' && events.lastError.contains('read-back') && state.klapSession==null
}
test('An ambiguous write timeout drops queued commands and ignores late callbacks') {
    fresh(); finishHandshake(); secureReply([error_code:0,result:[device_on:false]])
    driver.on(); Map token=requests.last().token
    driver.off(); int count=requests.size()
    driver.klapRequestTimedOut(token)
    driver.klapResponse(resp(''),token); driver.on()
    assert requests.size()==count && state.klapSession==null && !state.klapQueue && events.commsError=='true'
}
test('Handshake challenge mismatch stops further authentication until explicit reset') {
    fresh(); driver.klapResponse(resp(new byte[48].encodeBase64().toString()),requests.last().token)
    assert state.klapAuthBlocked && state.klapSession==null
    int count=requests.size(); clock+=600000; driver.refresh()
    assert requests.size()==count
    driver.resetSession(); assert !state.klapAuthBlocked && requests.size()==count+1
}
test('HTTP failures discard work without replay') {
    fresh(); finishHandshake(); int count=requests.size()
    driver.klapResponse(resp('',403),requests.last().token)
    assert requests.size()==count && state.klapActive==null && state.klapSession==null
}
test('Invalid IP never reaches the network') {
    ['192..0.2.1','192.0.2.999','http://192.0.2.1'].each { ip ->
        settings.manualIp=ip; fresh(); assert requests.empty && events.commsError=='true'
    }
    settings.manualIp='192.0.2.2'
}
test('Old raw-byte sessions are discarded safely on upgrade') {
    fresh(); state.klapActive=null; state.klapSession=[aesKey:[1,2,3],seq:7,cookie:'fixture']
    driver.refresh(); assert requests.last().token.stage=='handshake1'
}
test('Expired sessions and sequence exhaustion reconnect before use') {
    [false,true].each { expired ->
        fresh(); finishHandshake(); secureReply([error_code:0,result:[device_on:false]])
        if (expired) state.klapSession.expires=clock-1
        else state.klapSession.seq=Integer.MAX_VALUE
        driver.refresh(); assert requests.last().token.stage=='handshake1'
    }
}
test('Queue is bounded and zero level sends off without brightness zero') {
    fresh(); 25.times { driver.on() }; assert state.klapQueue.size()==16
    fresh(); driver.setLevel(0); assert state.klapQueue.last().params==[device_on:false]
}
test('Malformed binary responses fail closed') {
    fresh(); driver.klapResponse(resp('not-base64'),requests.last().token)
    assert events.commsError=='true' && state.klapSession==null
}
test('Changing IP invalidates an actual pending callback from the old address') {
    fresh(); Map oldToken=requests.last().token
    settings.manualIp='192.0.2.3'; driver.updated()
    int count=requests.size()
    driver.klapResponse(resp('',403),oldToken)
    assert requests.size()==count && state.klapActive.host=='192.0.2.3' && !state.klapAuthBlocked
    assert requests.last().params.uri=='http://192.0.2.3/app/handshake1'
    settings.manualIp='192.0.2.2'
}
test('Completed callback schedules the next queued command using the same serialized session') {
    fresh(); finishHandshake(); driver.on()
    secureReply([error_code:0,result:[device_on:false]])
    assert jobs.drainKlapQueue.delay==50 && state.klapQueue.size()==1
    int seq=state.klapSession.seq
    serialized(); driver.drainKlapQueue()
    assert state.klapActive.command.method=='set_device_info' && state.klapQueue.empty
    assert requests.last().token.stage=='request' && state.klapSession.seq==seq+1
}
println 'Offline tests passed: ' + checks
