const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
export const MAGIC=encoder.encode('JMOSENC1');
export const KEY_CONTEXT=encoder.encode('JMOS encrypted preview v1');
const own=(object,key)=>Object.prototype.hasOwnProperty.call(object,key);

export async function importAccessKey(value){
  const text=String(value).trim();
  if(!/^[A-Za-z0-9_-]{43}$/.test(text))throw Error('请粘贴完整的访问密钥。');
  const binary=atob(text.replace(/-/g,'+').replace(/_/g,'/')+'=');
  if(binary.length!==32||btoa(binary).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==text)throw Error('访问密钥格式不正确。');
  return crypto.subtle.importKey('raw',Uint8Array.from(binary,c=>c.charCodeAt(0)),'HKDF',false,['deriveKey']);
}

export function validateStore(store,expectedBase){
  if(store?.version!==1||store.basePath!==expectedBase||!store.routes||!store.blobs||typeof store.routes!=='object'||typeof store.blobs!=='object')throw Error('展示包格式不正确。');
  const entries=Object.entries(store.routes);
  if(!entries.length||entries.length>1024||!own(store.routes,'index.html'))throw Error('展示包路由不正确。');
  for(const [name,entry]of entries){
    if(name.startsWith('/')||/[\\%\u0000-\u001f\u007f]/.test(name)||name.split('/').some(p=>!p||p==='.'||p==='..')||
      !/^[a-f0-9]{64}$/.test(entry?.hash)||typeof entry.mime!=='string'||/[\r\n]/.test(entry.mime)||!own(store.blobs,entry.hash))throw Error('展示包含无效资源。');
  }
  for(const [hash,blob]of Object.entries(store.blobs)){
    if(!/^[a-f0-9]{64}$/.test(hash)||typeof blob?.gzip!=='boolean'||typeof blob.data!=='string'||blob.data.length>20*1024*1024||!/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(blob.data))throw Error('展示包含无效内容。');
  }
  return store;
}

export async function openArchive(bytes,masterKey,expectedBase){
  const data=new Uint8Array(bytes);
  if(data.length<52||!MAGIC.every((value,index)=>data[index]===value))throw Error('展示包格式不正确。');
  const header=data.slice(0,36),salt=data.slice(8,24),iv=data.slice(24,36);
  const key=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:KEY_CONTEXT},masterKey,{name:'AES-GCM',length:256},false,['decrypt']);
  const compressed=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:header,tagLength:128},key,data.slice(36));
  const stream=new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
  const plain=await new Response(stream).arrayBuffer();
  if(plain.byteLength>32*1024*1024)throw Error('展示包过大。');
  return validateStore(JSON.parse(decoder.decode(plain)),expectedBase);
}

export class PreviewLoadError extends Error {
  constructor(code,message){super(message);this.code=code;}
}

export async function fetchEncryptedArchive(root,onProgress=()=>{},onNotice=()=>{},{fetcher=fetch,retries=2,concurrency=4,timeoutMs=25000,delay=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
  const fail=(code,message)=>new PreviewLoadError(code,message);
  async function retry(task,label){
    let last;
    for(let attempt=0;attempt<=retries;attempt++){
      if(attempt){onNotice(`连接中断，正在自动重试${label}（${attempt}/${retries}）…`);await delay(attempt*350);}
      try{return await task(attempt);}catch(error){last=error;}
    }
    if(last instanceof PreviewLoadError)throw last;
    throw fail('NETWORK','展示包下载失败，请检查网络后重试。');
  }
  const release=await retry(async()=>{
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeoutMs);
    try{
      const url=new URL('release.json',root);url.searchParams.set('load',String(Date.now()));
      const response=await fetcher(url,{cache:'no-store',signal:controller.signal});
      if(!response.ok)throw fail('CONFIG_DOWNLOAD','无法下载预览配置，请检查网络后重试。');
      return await response.json();
    }finally{clearTimeout(timer);}
  },'预览配置');
  if(release?.format!=='jmos-encrypted-v1'||!/^payload-[a-f0-9]{16}\.bin$/.test(release.payload)||!/^[a-f0-9]{64}$/.test(release.sha256)||!Number.isSafeInteger(release.bytes)||release.bytes<52||release.bytes>32*1024*1024)throw fail('CONFIG_INVALID','预览配置无效，请刷新后重试。');
  const parts=release.parts||[{name:release.payload,bytes:release.bytes,sha256:release.sha256}];
  if(!Array.isArray(parts)||!parts.length||parts.length>32||parts.reduce((total,part)=>total+(part?.bytes||0),0)!==release.bytes||parts.some(part=>!/^payload-[a-f0-9]{16}(?:-\d{2})?\.bin$/.test(part?.name)||!Number.isSafeInteger(part.bytes)||part.bytes<=0||!/^[a-f0-9]{64}$/.test(part.sha256)))throw fail('CONFIG_INVALID','预览配置无效，请刷新后重试。');
  const received=parts.map(()=>0),chunks=parts.map(()=>null);let next=0;
  const progress=()=>onProgress(received.reduce((sum,value)=>sum+value,0),release.bytes);
  const checksum=async bytes=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join('');
  progress();
  await Promise.all(Array.from({length:Math.min(concurrency,parts.length)},async()=>{
    while(next<parts.length){
      const index=next++,part=parts[index];
      chunks[index]=await retry(async attempt=>{
        received[index]=0;progress();
        const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeoutMs);
        try{
          const response=await fetcher(new URL(part.name,root),{cache:attempt?'reload':'force-cache',signal:controller.signal});
          if(!response.ok||!response.body)throw fail('NETWORK','展示包下载失败，请检查网络后重试。');
          const reader=response.body.getReader(),buffers=[];
          while(true){const {value,done}=await reader.read();if(done)break;buffers.push(value);received[index]+=value.byteLength;if(received[index]>part.bytes)throw fail('INTEGRITY','展示包校验失败，请刷新后重试。');progress();}
          const bytes=new Uint8Array(received[index]);let offset=0;for(const buffer of buffers){bytes.set(buffer,offset);offset+=buffer.byteLength;}
          if(bytes.length!==part.bytes||await checksum(bytes)!==part.sha256)throw fail('INTEGRITY','展示包校验失败，请刷新后重试。');
          return bytes;
        }finally{clearTimeout(timer);}
      },'展示内容');
    }
  }));
  const bytes=new Uint8Array(release.bytes);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
  onNotice('正在校验加密展示包…');
  if(await checksum(bytes)!==release.sha256)throw fail('INTEGRITY','展示包校验失败，请刷新后重试。');
  return bytes;
}

export async function responseFromStore(request,store){
  const url=new URL(request.url);
  let pathname;
  try{pathname=decodeURIComponent(url.pathname);}catch{return new Response('Not found.',{status:404});}
  if(/[\\%\u0000-\u001f\u007f]/.test(pathname)||pathname.split('/').some(p=>p==='.'||p==='..')||!pathname.startsWith(store.basePath))return new Response('Not found.',{status:404});
  let relative=pathname.slice(store.basePath.length);
  if(!relative||relative.endsWith('/'))relative+='index.html';
  if(!own(store.routes,relative)){
    if(own(store.routes,relative+'/index.html'))return new Response(null,{status:301,headers:{Location:encodeURI(pathname+'/')+url.search}});
    return new Response('Not found.',{status:404});
  }
  const entry=store.routes[relative],blob=store.blobs[entry.hash];
  const headers={'Content-Type':entry.mime,'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"frame-ancestors 'self'"};
  if(request.method==='HEAD')return new Response(null,{status:200,headers});
  const data=Uint8Array.from(atob(blob.data),c=>c.charCodeAt(0));
  const body=blob.gzip?new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip')):data;
  return new Response(body,{status:200,headers});
}
