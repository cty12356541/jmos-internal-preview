import {importAccessKey} from './crypto-runtime.mjs?v=00203b2340ca1bd6';
const root=new URL(document.documentElement.dataset.siteRoot,location.origin);
const workerURL=new URL('service-worker.js?v='+document.documentElement.dataset.runtimeRevision,root);
const appBase=root.pathname+'app/';
const $=id=>document.getElementById(id);
let registration,masterKey=null;
function safeTarget(){
  const next=new URL(location.href).searchParams.get('next');
  if(!next)return appBase;
  try{const url=new URL(next,root);if(url.origin===root.origin&&url.pathname.startsWith(appBase)&&!url.username&&!url.password)return url.pathname+url.search+url.hash;}catch{}
  return appBase;
}
function message(worker,value,onProgress=()=>{}){
  return new Promise((resolve,reject)=>{
    const channel=new MessageChannel();
    let timer;
    const arm=()=>{clearTimeout(timer);timer=setTimeout(()=>{channel.port1.close();reject(Error('下载长时间没有响应，请检查网络后重试。'));},90000);};
    arm();
    channel.port1.onmessage=event=>{
      if(event.data?.notice){arm();status(event.data.notice);return;}
      if(event.data?.progress){arm();onProgress(event.data.progress);return;}
      clearTimeout(timer);channel.port1.close();resolve(event.data);
    };
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
    let setupTimer;
    try{
      await Promise.race([(async()=>{
        registration=await navigator.serviceWorker.register(workerURL,{scope:root.pathname,type:'module',updateViaCache:'none'});
        await navigator.serviceWorker.ready;
        while(navigator.serviceWorker.controller?.scriptURL!==workerURL.href)await new Promise(resolve=>navigator.serviceWorker.addEventListener('controllerchange',resolve,{once:true}));
      })(),new Promise((_,reject)=>{setupTimer=setTimeout(()=>reject(Error('解锁程序连接超时，请点击“重新连接”重试。')),45000);})]);
    }finally{clearTimeout(setupTimer);}
    navigator.serviceWorker.addEventListener('message',event=>{
      if(event.source!==navigator.serviceWorker.controller||event.source?.scriptURL!==workerURL.href)return;
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
        const result=await message(navigator.serviceWorker.controller,{type:'JMOS_UNLOCK',key},({loaded,total})=>{
          status(loaded===total?'正在解密展示内容…':`正在下载加密展示包… ${(loaded/1048576).toFixed(2)} / ${(total/1048576).toFixed(2)} MB`);
        });
        if(!result.ok){const error=Error(result.error||'解锁失败，请重试。');error.code=result.code;throw error;}
        masterKey=key;showViewer();
      }catch(error){masterKey=null;$('status').dataset.errorCode=error.code||'CLIENT';status(error.message,true);$('access-key').focus();}
      finally{$('unlock').disabled=false;}
    });
    $('lock').addEventListener('click',async()=>{masterKey=null;await message(navigator.serviceWorker.controller,{type:'JMOS_LOCK'});showLocked('预览已锁定。请重新输入密钥。');});
  }catch(error){status(error.message,true);$('status').dataset.errorCode='SETUP';$('unlock').disabled=false;$('unlock').textContent='重新连接';$('unlock').addEventListener('click',event=>{event.preventDefault();const url=new URL(location.href);url.searchParams.set('retry',String(Date.now()));location.replace(url.href);});}
}
