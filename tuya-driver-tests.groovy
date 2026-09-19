#!/usr/bin/env groovy
// Tests the production driver with Hubitat API stubs and fake credentials only.
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

def loader = new GroovyClassLoader()
loader.parseClass('package hubitat.helper; class HexUtils { static String byteArrayToHexString(byte[] v) { v.encodeHex().toString() } }')
loader.parseClass('package hubitat.device; enum Protocol { LAN }; class HubAction { enum Type { LAN_TYPE_RAW }; enum Encoding { HEX_STRING }; String message; Map options; HubAction(Object a, Object b, Map c) { message=a; options=c } }')
def driver = new GroovyShell(loader).parse(new File('tuya-lan-driver.groovy'))
Map state=[:], events=[:], data=[host:'192.0.2.1',port:'6668',gwId:'fixture',localKey:'0123456789abcdef'], jobs=[:]
Map settings=[host:'192.0.2.2',port:'6668',gwId:'fixture',localKey:'0123456789abcdef',pollRefresh:60,logEnable:true,txtEnable:true]
List sent=[], logs=[], socketOps=[]
Map socketAddress=[:]
long clock=1000000L
boolean throwSend=false
boolean throwConnect=false
driver.binding=new Binding([state:state,settings:settings,now:{->clock},metadata:{Closure c->},
    getDataValue:{String k->data[k]},updateDataValue:{String k,String v->data[k]=v},removeDataValue:{String k->data.remove(k)},
    sendEvent:{Map e->events[e.name]=e.value},
    sendHubCommand:{a->assert false:'Production must use binary rawSocket, not HubAction'},
    interfaces:[rawSocket:[
        connect:{Map options,String host,int port->
            socketOps<<'connect'
            if(throwConnect)throw new IllegalStateException('secret: '+settings.localKey)
            assert options.byteInterface==true && options.readDelay==150
            socketAddress.destinationAddress=host+':'+port
        },
        sendMessage:{String message->
            socketOps<<'send'
            if(throwSend)throw new IllegalStateException('secret: '+settings.localKey)
            sent<<[message:message,options:new LinkedHashMap(socketAddress)]
        },
        close:{->socketOps<<'close'}]],
    runIn:{int delay,String name,Map opts=[:]->jobs[name]=[delay:delay,data:opts.data]},
    runInMillis:{int delay,String name->jobs[name]=[delay:delay]},
    unschedule:{String name=null->if(name)jobs.remove(name);else jobs.clear()},
    log:[debug:{s->logs<<s.toString()},warn:{s->logs<<s.toString()}]])
driver.run()
def p=['venv/bin/python','tests/tuya_vectors.py'].execute()
String output=p.inputStream.text, errors=p.errorStream.text
assert p.waitFor()==0:errors
Map v=new JsonSlurper().parseText(output)
int count=0
def test={String title,Closure body->body();count++;println 'PASS '+title}
def rejects={Closure c->boolean rejected=false;try{c()}catch(IllegalArgumentException e){rejected=true};assert rejected}
def serialized={->Map s=new JsonSlurper().parseText(JsonOutput.toJson(state));state.clear();state.putAll(s)}
def fresh={->state.clear();events.clear();sent.clear();jobs.clear();logs.clear();socketOps.clear();throwSend=false;throwConnect=false;driver.updated()}
def response={long seq,int cmd,Map dps=null,int rc=0,boolean version=false->
    List bytes=[0,0,0,rc]
    if(dps!=null){if(version)bytes+=([51,46,51]+([0]*12));bytes+=driver.encrypt(v.key.bytes,JsonOutput.toJson([dps:dps])).toList()}
    driver.packMessage(seq as Integer,cmd,bytes as byte[],v.key.bytes).encodeHex().toString()
}
def finishRead={->driver.parse(response(state.tuyaPending.seq,10,['1':false,'2':620]))}
test('Independent Python AES, outbound frames, CRC, return code and version header') {
    assert driver.encrypt(v.key.bytes,v.plaintext).encodeHex().toString()==v.cipher
    assert driver.encodeMessage(41,10,v.plaintext,v.key.bytes).encodeHex().toString()==v.query
    assert driver.encodeMessage(42,7,v.plaintext,v.key.bytes).encodeHex().toString()==v.control
    assert driver.decryptPayload(v.response,v.key.bytes)==v.plaintext
    assert driver.decryptPayload(v.status,v.key.bytes)==v.plaintext
    assert driver.extractPayload(v.ack.decodeHex()).command==7
    assert new JsonSlurper().parseText(driver.decryptPayload(v.ack,v.key.bytes)).returnCode==0
}
test('Installation is self-contained, persists address first and schedules polling') {
    driver.installed()
    assert sent.size()==1 && sent[0].options.destinationAddress=='192.0.2.2:6668' && jobs.poll.delay==60
    assert data.driverVersion=='1.1.1' && !data.containsKey('localKey') && !events.containsKey('localKey')
}
test('Successful read publishes confirmed state and clears errors') {
    finishRead(); assert events.switch=='off' && events.level==62 && events.commsError=='false' && events.lastError=='none'
    assert state.tuyaPending==null
}
test('Request sequences increment and survive persistence/reconfiguration') {
    fresh();finishRead();serialized();driver.refresh();finishRead();driver.updated()
    assert sent.collect{Long.parseLong(it.message.substring(8,16),16)}==[1L,2L,3L]
}
test('Every byte boundary can split a frame, including its prefix and header') {
    for(int i=2;i<v.response.length();i+=2){
        state.tuyaRx='';state.tuyaRxAt=clock
        assert driver.splitTuyaFrames(v.response.substring(0,i)).empty
        serialized()
        assert driver.splitTuyaFrames(v.response.substring(i))==[v.response]
        assert state.tuyaRx==''
    }
}
test('Fragmented parse publishes nothing until the complete response arrives') {
    fresh();String f=response(state.tuyaPending.seq,10,['1':true,'2':620])
    driver.parse('payload:'+f.substring(0,48).bytes.encodeBase64().toString())
    assert !events.containsKey('switch') && state.tuyaPending
    serialized();driver.parse('payload:'+f.substring(48).bytes.encodeBase64().toString())
    assert events.switch=='on' && events.commsError=='false'
}
test('Concatenated frames and a trailing incomplete frame are buffered correctly') {
    state.tuyaRx=''
    assert driver.splitTuyaFrames(v.ack+v.status+v.response.substring(0,20))==[v.ack,v.status]
    assert driver.splitTuyaFrames(v.response.substring(20))==[v.response]
}
test('Noise is discarded while a split prefix is preserved') {
    state.tuyaRx=''
    assert driver.splitTuyaFrames('deadbeef0000aa550000').empty
    assert driver.splitTuyaFrames(v.response.substring(4))==[v.response]
}
test('Stale incomplete data expires instead of contaminating a new request') {
    state.tuyaRx='';driver.splitTuyaFrames(v.response.substring(0,40));clock+=16000
    assert driver.splitTuyaFrames(v.response)==[v.response]
}
test('CRC, prefix, suffix, and length corruption never update device state') {
    [0,15,v.response.length().intdiv(2)-8,v.response.length().intdiv(2)-1].each { index->
        fresh();byte[] bytes=response(state.tuyaPending.seq,10,['1':true,'2':620]).decodeHex();bytes[index]^=1
        rejects {driver.extractPayload(bytes)}
        driver.parse(bytes.encodeHex().toString());assert !events.containsKey('switch')
    }
}
test('Oversized, negative-looking lengths and malformed encodings fail closed') {
    ['000055aa000000010000000affffffff','000055aa000000010000000a00000001'].each {hex->
        state.tuyaRx='';rejects{driver.splitTuyaFrames(hex)}
    }
    rejects{driver.splitTuyaFrames('00'*131073)}
    rejects{driver.parseMessage('payload:not base64!')}
    assert driver.parseMessage('status:ready')==null
}
test('Hex, Base64 ASCII-hex and Base64 binary callbacks decode consistently') {
    assert driver.parseMessage('payload:'+v.response)==v.response
    assert driver.parseMessage('payload:'+v.response.bytes.encodeBase64().toString())==v.response
    assert driver.parseMessage('payload:'+v.response.decodeHex().encodeBase64().toString())==v.response
}
test('Failed transmission reports failure without optimistic switch or level events') {
    fresh();finishRead();throwSend=true;driver.on()
    assert events.switch=='off' && events.level==62 && events.commsError=='true'
    assert state.tuyaPending==null && state.tuyaQueue.empty
}
test('Control acknowledgement triggers a distinct read-back, not success events') {
    fresh();finishRead();driver.on();long seq=state.tuyaPending.seq
    assert events.switch=='off'
    driver.parse(response(seq,7));assert state.tuyaPending.stage=='query' && state.tuyaPending.seq==seq+1
    assert events.switch=='off'
    driver.parse(response(seq+1,10,['1':true,'2':620]))
    assert events.switch=='on' && events.commsError=='false' && state.tuyaPending==null
}
test('Rejected commands and read-back mismatches are reported as failures') {
    fresh();finishRead();driver.on();driver.parse(response(state.tuyaPending.seq,7,null,1))
    assert events.switch=='off' && events.commsError=='true'
    fresh();finishRead();driver.on();driver.parse(response(state.tuyaPending.seq,7));finishRead()
    assert events.switch=='off' && events.commsError=='true' && events.lastError.contains('read-back')
}
test('Watchdogs drop work without replay and ignore obsolete timeout tokens') {
    fresh();Map old=jobs.tuyaTimedOut.data;finishRead();driver.on();driver.off()
    driver.tuyaTimedOut(old);assert state.tuyaPending
    int sentCount=sent.size();driver.tuyaTimedOut(jobs.tuyaTimedOut.data)
    assert sent.size()==sentCount && events.commsError=='true' && state.tuyaQueue.empty
}
test('Unsolicited status reports update state but unrelated responses cannot finish requests') {
    fresh();driver.parse(response(99,10,['1':true]));assert state.tuyaPending
    driver.parse(response(0,8,['1':true,'2':620],0,true))
    assert state.tuyaPending==null && events.switch=='on'
}
test('Queue bounds, refresh coalescing, and level zero off semantics') {
    fresh();20.times{driver.refresh()};assert sent.size()==1 && state.tuyaQueue.empty
    driver.setLevel(0);assert state.tuyaQueue.last().dps==['1':false]
    20.times{driver.on()};assert state.tuyaQueue.size()==16
}
test('Invalid configuration performs no network requests or key disclosure') {
    settings.host='http://192.0.2.1';fresh();assert sent.empty && events.commsError=='true';settings.host='192.0.2.2'
    settings.localKey='bad';fresh();assert sent.empty && events.commsError=='true';settings.localKey=v.key
}
test('Secrets never enter logs/events, even on crypto and transport errors') {
    fresh();finishRead();throwSend=true;driver.on()
    driver.parse('payload:!!!!')
    assert !logs.any{it.contains(v.key)} && !events.containsKey('localKey')
    String source=new File('tuya-lan-driver.groovy').text
    assert !source.contains('attribute "localKey"') && !source.contains('LOG.exception')
    assert !source.contains('System.arraycopy') && !source.contains('instanceof byte[]') && !source.contains('as byte[]')
}
test('Binary TCP opens once per transaction and closes after confirmed read') {
    fresh();assert state.tuyaSocketOpen && socketOps.count('connect')==1
    finishRead();assert !state.tuyaSocketOpen && socketOps.last()=='close'
    driver.on();int connects=socketOps.count('connect')
    serialized();driver.parse(response(state.tuyaPending.seq,7))
    assert state.tuyaSocketOpen && socketOps.count('connect')==connects
    driver.parse(response(state.tuyaPending.seq,10,['1':true,'2':620]))
    assert !state.tuyaSocketOpen && events.commsError=='false'
}
test('Connection failures close the socket without sending or replaying') {
    fresh();finishRead();int before=sent.size();throwConnect=true;driver.on()
    assert sent.size()==before && state.tuyaPending==null && !state.tuyaSocketOpen
    assert events.commsError=='true' && !logs.any{it.contains(v.key)}
}
test('Uncorrelated socket callbacks cannot abort a newer transaction') {
    fresh();Map pending=new LinkedHashMap(state.tuyaPending)
    driver.socketStatus('receive error: secret '+v.key)
    assert state.tuyaPending==pending && !logs.any{it.contains(v.key)}
    driver.tuyaTimedOut(jobs.tuyaTimedOut.data)
    assert !state.tuyaSocketOpen && events.commsError=='true'
}
test('Initialize and uninstall close sockets and remove temporary diagnostics') {
    fresh();state.tuyaDiagnosticPacket='encrypted fixture';state.tuyaDiagnostic=[:];state.tuyaDiagnosticTransport='raw'
    driver.initialize()
    assert !state.containsKey('tuyaDiagnosticPacket') && !state.containsKey('tuyaDiagnosticTransport')
    assert state.tuyaSocketOpen
    driver.uninstalled();assert !state.tuyaSocketOpen && jobs.isEmpty()
}
println 'Offline tests passed: '+count
