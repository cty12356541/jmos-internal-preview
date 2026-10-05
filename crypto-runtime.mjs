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
