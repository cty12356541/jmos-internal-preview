import {openArchive,responseFromStore} from './crypto-runtime.mjs';
const root=new URL('./',self.location.href);
const appBase=root.pathname+'app/';
let masterKey=null,store=null,pending=null,generation=0;
const shellClient=client=>{
  if(!client?.url)return false;
  const url=new URL(client.url);
  return url.origin===root.origin&&(url.pathname===root.pathname||url.pathname===root.pathname+'index.html');
};
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));

async function recoverKey(){
  const clients=(await self.clients.matchAll({type:'window',includeUncontrolled:false})).filter(shellClient);
  for(const client of clients){
    const key=await new Promise(resolve=>{
      const channel=new MessageChannel();
      const timer=setTimeout(()=>{channel.port1.close();resolve(null);},1500);
      channel.port1.onmessage=event=>{clearTimeout(timer);channel.port1.close();resolve(event.data?.key||null);};
      client.postMessage({type:'JMOS_SESSION_REQUEST'},[channel.port2]);
    });
    if(key?.type==='secret'&&key.algorithm?.name==='HKDF'&&!key.extractable)return key;
  }
  return null;
}

async function decodeArchive(key,onProgress=()=>{}){
    const releaseResponse=await fetch(new URL('release.json',root),{cache:'no-store'});
    if(!releaseResponse.ok)throw Error('Release unavailable');
    const release=await releaseResponse.json();
    if(release.format!=='jmos-encrypted-v1'||!/^payload-[a-f0-9]{16}\.bin$/.test(release.payload)||!/^[a-f0-9]{64}$/.test(release.sha256))throw Error('Release invalid');
    onProgress(0,release.bytes);
    const response=await fetch(new URL(release.payload,root),{cache:'force-cache'});
    if(!response.ok)throw Error('Archive unavailable');
    const chunks=[];let received=0;
    const reader=response.body.getReader();
    while(true){const {value,done}=await reader.read();if(done)break;chunks.push(value);received+=value.byteLength;if(received>release.bytes)throw Error('Archive integrity failed');onProgress(received,release.bytes);}
    const bytes=new Uint8Array(received);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
    const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join('');
    if(hash!==release.sha256||bytes.byteLength!==release.bytes)throw Error('Archive integrity failed');
    return openArchive(bytes,key,appBase);
}
async function archive(){
  if(store)return store;
  if(pending)return pending;
  const current=generation;
  const work=(async()=>{
    const key=masterKey||await recoverKey();
    if(!key||current!==generation)throw Error('Locked');
    const opened=await decodeArchive(key);
    if(current!==generation)throw Error('Session changed');
    masterKey=key;store=opened;return store;
  })();
  pending=work;
  try{return await work;}finally{if(pending===work)pending=null;}
}

async function lock(exceptClientId=null){
  generation++;masterKey=null;store=null;pending=null;
  for(const client of (await self.clients.matchAll({type:'window',includeUncontrolled:true})).filter(shellClient))if(client.id!==exceptClientId)client.postMessage({type:'JMOS_SESSION_LOCKED'});
}

self.addEventListener('message',event=>{
  if(!shellClient(event.source)||!event.ports[0])return;
  const reply=value=>event.ports[0].postMessage(value);
  event.waitUntil((async()=>{
    if(event.data?.type==='JMOS_UNLOCK'){
      const key=event.data.key;
      if(key?.type!=='secret'||key.algorithm?.name!=='HKDF'||key.extractable){reply({ok:false});return;}
      const current=generation;
      try{
        const opened=await decodeArchive(key,(loaded,total)=>reply({progress:{loaded,total}}));
        if(current!==generation)throw Error('Session changed');
        generation++;masterKey=key;store=opened;pending=null;reply({ok:true});
      }catch{reply({ok:false,error:'密钥不正确，或展示包已更新。请核对密钥后重试。'});}
    }else if(event.data?.type==='JMOS_LOCK'){
      await lock();reply({ok:true});
    }else if(event.data?.type==='JMOS_STATUS')reply({ok:Boolean(store&&masterKey),key:store?masterKey:null});
  })());
});

self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url);
  if(url.origin!==root.origin||!url.pathname.startsWith(appBase))return;
  event.respondWith((async()=>{
    if(!['GET','HEAD'].includes(event.request.method))return new Response('Method not allowed.',{status:405,headers:{'Cache-Control':'no-store'}});
    try{return await responseFromStore(event.request,await archive());}
    catch{
      if(event.request.mode==='navigate'||['document','iframe'].includes(event.request.destination)){
        const gate=new URL(root);gate.searchParams.set('next',url.pathname+url.search);
        return new Response(null,{status:302,headers:{Location:gate.href,'Cache-Control':'no-store'}});
      }
      return new Response('Unlock the preview first.',{status:423,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
    }
  })());
});
