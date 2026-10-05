import {importAccessKey} from './crypto-runtime.mjs';
const root=new URL(document.documentElement.dataset.siteRoot,location.origin);
const appBase=root.pathname+'app/';
const $=id=>document.getElementById(id);
let registration,masterKey=null;
function safeTarget(){
  const next=new URL(location.href).searchParams.get('next');
  if(!next)return appBase;
  try{const url=new URL(next,root);if(url.origin===root.origin&&url.pathname.startsWith(appBase)&&!url.username&&!url.password)return url.pathname+url.search+url.hash;}catch{}
  return appBase;
}
function message(worker,value){
  return new Promise((resolve,reject)=>{
    const channel=new MessageChannel();
    const timer=setTimeout(()=>{channel.port1.close();reject(Error('解锁超时，请刷新页面后重试。'));},25000);
    channel.port1.onmessage=event=>{clearTimeout(timer);channel.port1.close();resolve(event.data);};
    worker.postMessage(value,[channel.port2]);
  });
}
function status(text,error=false){$('status').textContent=text;$('status').dataset.error=String(error);}
function showLocked(text='请输入访问密钥。'){
  masterKey=null;$('preview').src='about:blank';$('viewer').hidden=true;$('gate').hidden=false;$('access-key').value='';status(text);
}
function showViewer(){
  $('preview').src=safeTarget();$('viewer').hidden=false;$('gate').hidden=true;$('access-key').value='';
}

// A first visit to a deep virtual path can receive the generic 404 shell from
// GitHub before the Service Worker exists. Normalize to the real unlock page.
if(location.pathname!==root.pathname&&location.pathname!==root.pathname+'index.html'){
  const url=new URL(root);if(location.pathname.startsWith(appBase))url.searchParams.set('next',location.pathname+location.search+location.hash);location.replace(url.href);
}else{
  try{
    if(!isSecureContext||!crypto.subtle||!navigator.serviceWorker||typeof DecompressionStream==='undefined')throw Error('请使用新版 Chrome、Edge 或 Safari 打开此预览。');
    registration=await navigator.serviceWorker.register(new URL('service-worker.js',root),{scope:root.pathname,type:'module',updateViaCache:'none'});
    await navigator.serviceWorker.ready;
    if(!navigator.serviceWorker.controller)await new Promise(resolve=>navigator.serviceWorker.addEventListener('controllerchange',resolve,{once:true}));
    navigator.serviceWorker.addEventListener('message',event=>{
      if(event.source!==navigator.serviceWorker.controller||event.source?.scriptURL!==new URL('service-worker.js',root).href)return;
      if(event.data?.type==='JMOS_SESSION_REQUEST'&&event.ports[0])event.ports[0].postMessage({key:masterKey});
      if(event.data?.type==='JMOS_SESSION_LOCKED')showLocked('预览已锁定。请重新输入密钥。');
    });
    const existing=await message(navigator.serviceWorker.controller,{type:'JMOS_STATUS'});
    if(existing.ok&&existing.key){masterKey=existing.key;showViewer();}else status('请输入访问密钥。');
    $('unlock').disabled=false;
    $('unlock-form').addEventListener('submit',async event=>{
      event.preventDefault();$('unlock').disabled=true;status('正在解锁展示包…');
      try{
        const key=await importAccessKey($('access-key').value);
        const result=await message(navigator.serviceWorker.controller,{type:'JMOS_UNLOCK',key});
        if(!result.ok)throw Error(result.error||'密钥不正确，请重新输入。');
        masterKey=key;showViewer();
      }catch(error){masterKey=null;status(error.message,true);$('access-key').focus();}
      finally{$('unlock').disabled=false;}
    });
    $('lock').addEventListener('click',async()=>{masterKey=null;await message(navigator.serviceWorker.controller,{type:'JMOS_LOCK'});showLocked('预览已锁定。请重新输入密钥。');});
  }catch(error){status(error.message,true);$('unlock').disabled=true;}
}
