import {openArchive,responseFromStore,fetchEncryptedArchive,PreviewLoadError} from './crypto-runtime.mjs?v=3e8bf968a8c6922b';
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

async function decodeArchive(key,onProgress=()=>{},onNotice=()=>{}){
    const bytes=await fetchEncryptedArchive(root,onProgress,onNotice);
    onNotice('正在解密展示内容…');
    try{return await openArchive(bytes,key,appBase);}
    catch(error){if(error.name==='OperationError')throw new PreviewLoadError('KEY_INVALID','密钥不正确，请核对后重试。');throw new PreviewLoadError('ARCHIVE_INVALID','展示包无法读取，请刷新后重试。');}
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
        const opened=await decodeArchive(key,(loaded,total)=>reply({progress:{loaded,total}}),message=>reply({notice:message}));
        if(current!==generation)throw Error('Session changed');
        generation++;masterKey=key;store=opened;pending=null;reply({ok:true});
      }catch(error){reply({ok:false,error:error instanceof PreviewLoadError?error.message:'解锁过程被中断，请重试。',code:error.code||'SESSION_INTERRUPTED'});}
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
