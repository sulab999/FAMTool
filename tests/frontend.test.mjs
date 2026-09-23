import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHTML, splitPath, matches, identitySource, settingPaths } from '../crates/gui/ui/format.js';
test('untrusted paths and metadata cannot insert HTML',()=>{assert.equal(escapeHTML('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');});
test('paths are readable across platforms',()=>{assert.deepEqual(splitPath('/Users/me/report.txt'),{name:'report.txt',parent:'/Users/me'});assert.deepEqual(splitPath('C:\\docs\\a.txt'),{name:'a.txt',parent:'C:\\docs'});});
test('filter uses owner independently from process user and supports diagnostics',()=>{const r={event:'modified',path:'/new',from:'/old',owner:'Alice',actor:{user:'Bob',application:'Editor'}};assert(matches(r,'alice','modified'));assert(matches(r,'EDITOR',''));assert(matches(r,'old',''));assert(!matches(r,'alice','removed'));assert(matches({event:'diagnostic',diagnostic:{code:'capture_queue_full'}},'queue','diagnostic'));});
test('inferred identity is clearly distinguished',()=>{assert(identitySource('path_inferred').includes('不是确定'));assert(identitySource('fd_scan; open_descriptor').includes('不代表确定'));});
test('settings paths strip only empty lines and surrounding space',()=>{assert.deepEqual(settingPaths(' /a b \n\n /c\r\n'),['/a b','/c']);});

test('older records with null attribution render safely',()=>{assert.equal(identitySource(null),'系统未提供');assert.equal(identitySource(undefined),'系统未提供');assert(matches({event:'created',path:'/a',actor:{source:null,user:null,application:null},owner:null},'a',''));});

import { pageNumber, pageSummary } from '../crates/gui/ui/format.js';
test('page selection validates blank, decimals and out-of-range input',()=>{
  assert.equal(pageNumber('3',11),3);assert.equal(pageNumber(' 11 ',11),11);
  for(const value of ['', '0','-1','12','1.5','1e2','abc','9007199254740992']) assert.equal(pageNumber(value,11),null);
  assert.equal(pageNumber('1',0),null);
});
test('pagination summaries handle no matches, exact pages and final partial page',()=>{
  assert.deepEqual(pageSummary(0,0,200),{totalPages:0,from:0,to:0});
  assert.deepEqual(pageSummary(400,2,200),{totalPages:2,from:201,to:400});
  assert.deepEqual(pageSummary(401,3,200),{totalPages:3,from:401,to:401});
  assert.deepEqual(pageSummary(2167,11,200),{totalPages:11,from:2001,to:2167});
});

test('system audit identities are distinguished and parent apps can be searched',()=>{
  assert(identitySource('endpoint_security').includes('系统审计'));
  assert(!identitySource('endpoint_security').includes('推断'));
  const r={event:'removed',path:'/watched/授权书_副本.png',actor:{application:'rm'},audit:{executable:'/bin/rm',parent:{executable:'/bin/zsh'},responsible:{executable:'/Applications/Terminal.app/Contents/MacOS/Terminal'}}};
  assert(matches(r,'Terminal','removed'));assert(matches(r,'/bin/rm',''));assert(matches(r,'zsh',''));
});

import { shouldAskAuditPermission, shouldOpenAuditPrivacy } from '../crates/gui/ui/format.js';
test('audit consent prompts only when needed and respects dismissal',()=>{
  const waiting={enabled:true,supported:true,state:'waiting'};
  assert(shouldAskAuditPermission(waiting,false,false));
  assert(!shouldAskAuditPermission(waiting,true,false));assert(!shouldAskAuditPermission(waiting,false,true));
  assert(!shouldAskAuditPermission({...waiting,state:'running'},false,false));
  assert(!shouldAskAuditPermission({...waiting,enabled:false},false,false));
  assert(!shouldAskAuditPermission({...waiting,supported:false},false,false));
});
test('privacy settings auto-open once only after a user authorization request',()=>{
  assert(shouldOpenAuditPrivacy({state:'not_permitted'},true,false));
  assert(!shouldOpenAuditPrivacy({state:'not_permitted'},false,false));
  assert(!shouldOpenAuditPrivacy({state:'not_permitted'},true,true));
  assert(!shouldOpenAuditPrivacy({state:'not_entitled'},true,false));
});
