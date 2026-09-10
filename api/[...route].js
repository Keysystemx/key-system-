const crypto=require('crypto');
const admin=require('firebase-admin');
const REQUIREMENTS={6:1,12:2,24:3,30:4};
const SESSION_TTL=15*60*1000;
const VERIFY_LOCK_TTL=7000;
const VERIFY_RETRIES=45;
const VERIFY_RETRY_DELAY=300;
const KEY_PREFIX='ZNEXUS-';
const AD_PROVIDER_BASE_URL=process.env.AD_PROVIDER_BASE_URL||'https://link-hub.net/6768455/qSE1FKce4SS7';
const recentRequests=new Map();
function json(res,status,payload){res.status(status);res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store, no-cache, must-revalidate');res.setHeader('X-Content-Type-Options','nosniff');res.end(JSON.stringify(payload));}
function routeOf(req){return new URL(req.url||'/','https://placeholder.local').pathname.replace(/^\/api\/?/,'').replace(/^\/+|\/+$/g,'');}
function queryOf(req){return new URL(req.url||'/','https://placeholder.local').searchParams;}
function ipOf(req){return String(req.headers?.['x-forwarded-for']||req.headers?.['x-real-ip']||'unknown').split(',')[0].trim().slice(0,80);}
function rateLimit(req,key,max=40,windowMs=60000){const now=Date.now(),id=`${key}:${ipOf(req)}`,x=recentRequests.get(id)||{count:0,reset:now+windowMs};if(now>x.reset){x.count=0;x.reset=now+windowMs}x.count++;recentRequests.set(id,x);if(recentRequests.size>5000)for(const[k,v]of recentRequests)if(v.reset<now)recentRequests.delete(k);return x.count<=max;}
function app(){if(admin.apps.length)return admin.app();const raw=process.env.FIREBASE_SERVICE_ACCOUNT_JSON,url=process.env.FIREBASE_DATABASE_URL;if(!raw||!url)throw new Error('Firebase del servidor no está configurado.');return admin.initializeApp({credential:admin.credential.cert(JSON.parse(raw)),databaseURL:url});}
function validDevice(id){return /^HWID-[A-Z0-9]{24}$/.test(String(id||''));}
function pub(s){return{id:s.id,dur:Number(s.dur),link:Number(s.link),state:s.state,createdAt:Number(s.createdAt),expiresAt:Number(s.expiresAt)};}
async function body(req){return req.body&&typeof req.body==='object'?req.body:{};}
async function session(db,id){if(!/^[a-f0-9-]{20,100}$/i.test(String(id||''))){const e=new Error('Sesión inválida.');e.status=400;throw e}const ref=db.ref(`sessions/${id}`),snap=await ref.get();if(!snap.exists()){const e=new Error('Sesión no encontrada.');e.status=404;throw e}const s=snap.val();if(Number(s.expiresAt)<=Date.now()){await ref.remove();const e=new Error('La sesión expiró.');e.status=410;throw e}return s;}
function sameDevice(s,id){return validDevice(id)&&s.deviceId===id;}
function deterministicKey(id){return KEY_PREFIX+crypto.createHash('sha256').update(String(id)).digest('hex').toUpperCase().slice(0,9);}
async function cleanupExpired(db){const now=Date.now(),updates={};const keys=await db.ref('keys').orderByChild('expiresAt').endAt(now).limitToFirst(500).get();keys.forEach(x=>updates[`keys/${x.key}`]=null);const sessions=await db.ref('sessions').orderByChild('expiresAt').endAt(now).limitToFirst(500).get();sessions.forEach(x=>updates[`sessions/${x.key}`]=null);if(Object.keys(updates).length)await db.ref().update(updates);return Object.keys(updates).length;}
async function waitVerify(db,id,deviceId,timeout=9000){const ref=db.ref(`sessions/${id}`),end=Date.now()+timeout;while(Date.now()<end){const x=await ref.get();if(!x.exists())return null;const s=x.val();if(s.deviceId!==deviceId)return null;if(s.state!=='verifying')return s;await new Promise(r=>setTimeout(r,200));}const x=await ref.get();return x.exists()?x.val():null;}
module.exports=async(req,res)=>{try{
const origin=String(req.headers?.origin||'');if(origin==='https://keyzsystem.vercel.app'||origin==='null'){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin')}res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type, Accept');
const method=String(req.method||'GET').toUpperCase();if(method==='OPTIONS'){res.status(204).end();return}const route=routeOf(req);if(method==='GET'&&route==='health')return json(res,200,{ok:true,service:'znexus-api',version:'2026.9'});if(!rateLimit(req,route||'root',route==='linkvertise/verify'?12:40))return json(res,429,{error:'Demasiadas solicitudes. Espera un momento.'});
const db=app().database(),data=await body(req);
if(route==='cron/cleanup'){if(method!=='GET')return json(res,405,{error:'Método no permitido.'});const secret=process.env.CRON_SECRET;if(!secret||String(req.headers?.authorization||'')!==`Bearer ${secret}`)return json(res,401,{error:'No autorizado.'});return json(res,200,{ok:true,removed:await cleanupExpired(db)});}
if(method==='POST'&&route==='session/start'){const hours=Number(data.hours),deviceId=String(data.deviceId||'');if(!REQUIREMENTS[hours])return json(res,400,{error:'Duración inválida.'});if(!validDevice(deviceId))return json(res,400,{error:'Device ID inválido.'});await cleanupExpired(db);const now=Date.now(),id=crypto.randomUUID(),s={id,dur:hours,link:1,state:'ready',createdAt:now,expiresAt:now+SESSION_TTL,deviceId,completedLinks:0,attempts:0,returnToken:crypto.randomBytes(24).toString('hex')};await db.ref(`sessions/${id}`).set(s);return json(res,200,{session:pub(s)});}
if(method==='GET'&&route==='session/get'){const q=queryOf(req),s=await session(db,q.get('sessionId')),deviceId=String(q.get('deviceId')||'');if(!sameDevice(s,deviceId))return json(res,403,{error:'El dispositivo no coincide con la sesión.'});return json(res,200,{session:pub(s)});}
if(method==='POST'&&route==='session/prepare-link'){const s=await session(db,data.sessionId),link=Number(data.link),deviceId=String(data.deviceId||'');if(!sameDevice(s,deviceId))return json(res,403,{error:'El dispositivo no coincide con la sesión.'});if(!['ready','awaiting_external_return'].includes(s.state)||link!==Number(s.link))return json(res,409,{error:'El enlace no está autorizado en este estado.'});await db.ref(`sessions/${s.id}`).update({state:'awaiting_external_return',externalStartedAt:Date.now(),attempts:Number(s.attempts||0)+1});return json(res,200,{session:pub({...s,state:'awaiting_external_return'}),redirectUrl:AD_PROVIDER_BASE_URL});}
if(method==='POST'&&route==='session/return')return json(res,410,{error:'Este retorno requiere comprobante Anti-Bypassing de Linkvertise.'});
if(method==='POST'&&route==='linkvertise/verify'){
 const sessionId=String(data.sessionId||''),hash=String(data.hash||'').trim(),link=Number(data.link),deviceId=String(data.deviceId||'');
 if(!/^[A-Za-z0-9]{64}$/.test(hash))return json(res,400,{error:'Comprobante inválido.'});
 let current=await session(db,sessionId);if(!sameDevice(current,deviceId))return json(res,403,{error:'El dispositivo no coincide con la sesión.'});
 if(current.lastVerifiedHash===hash)return json(res,200,{session:pub(current),deduplicated:true});
 const ref=db.ref(`sessions/${sessionId}`);
 let verifyId=null,locked=null;
 for(let attempt=0;attempt<VERIFY_RETRIES;attempt++){
   current=await session(db,sessionId);if(!sameDevice(current,deviceId))return json(res,403,{error:'El dispositivo no coincide con la sesión.'});
   if(current.lastVerifiedHash===hash)return json(res,200,{session:pub(current),deduplicated:true});
   if(current.state==='complete')return json(res,200,{session:pub(current),deduplicated:true});
   if(current.state==='verifying'){
     if(current.verifyHash===hash){const w=await waitVerify(db,sessionId,deviceId,1200);if(w&&w.lastVerifiedHash===hash)return json(res,200,{session:pub(w),deduplicated:true});if(w&&w.state==='complete')return json(res,200,{session:pub(w),deduplicated:true});}
     const age=Date.now()-Number(current.verifyStartedAt||0);
     if(age<VERIFY_LOCK_TTL){await new Promise(r=>setTimeout(r,VERIFY_RETRY_DELAY));continue;}
   }
   if(current.state!=='awaiting_external_return'&&current.state!=='verifying'){return json(res,409,{error:'Ese paso ya fue procesado o no está pendiente.'});}
   if(current.state==='awaiting_external_return'&&link!==Number(current.link))return json(res,409,{error:'Ese paso ya fue procesado o no está pendiente.'});
   if(Date.now()-Number(current.externalStartedAt||0)>SESSION_TTL)return json(res,410,{error:'El tiempo del paso expiró.'});
   verifyId=crypto.randomUUID();
   const tx=await ref.transaction(cur=>{
     if(!cur)return;
     if(cur.state==='complete')return cur;
     if(cur.state==='verifying'){
       const age=Date.now()-Number(cur.verifyStartedAt||0);
       if(age<VERIFY_LOCK_TTL)return;
     }else if(cur.state!=='awaiting_external_return'||Number(cur.link)!==link)return;
     return{...cur,state:'verifying',verifyStartedAt:Date.now(),verifyHash:hash,verifyId};
   });
   if(tx.committed){locked=tx.snapshot.val();break;}
   await new Promise(r=>setTimeout(r,VERIFY_RETRY_DELAY));
 }
 if(!locked){current=await session(db,sessionId);if(current.lastVerifiedHash===hash||current.state==='complete')return json(res,200,{session:pub(current),deduplicated:true});return json(res,409,{error:'No se pudo tomar el turno de verificación. Inténtalo una sola vez de nuevo.'});}
 if(locked.state==='complete')return json(res,200,{session:pub(locked),deduplicated:true});
 const token=process.env.LINKVERTISE_ANTI_BYPASS_TOKEN;if(!token){await ref.transaction(cur=>cur&&cur.verifyId===verifyId?{...cur,state:'awaiting_external_return',verifyStartedAt:null,verifyHash:null,verifyId:null}:cur);return json(res,500,{error:'Falta la configuración de Linkvertise en el servidor.'});}
 try{
   const u=new URL('https://publisher.linkvertise.com/api/v1/anti_bypassing');u.searchParams.set('token',token);u.searchParams.set('hash',hash);
   const ac=new AbortController(),tm=setTimeout(()=>ac.abort(),6000);let lv,result;try{lv=await fetch(u,{method:'POST',headers:{Accept:'text/plain'},signal:ac.signal});result=(await lv.text()).trim();}finally{clearTimeout(tm)}
   if(!lv.ok||result!=='TRUE'){
     const latest=await ref.get();
     if(latest.exists()&&latest.val().lastVerifiedHash===hash)return json(res,200,{session:pub(latest.val()),deduplicated:true});
     await ref.transaction(cur=>cur&&cur.verifyId===verifyId?{...cur,state:'awaiting_external_return',verifyStartedAt:null,verifyHash:null,verifyId:null}:cur);
     return json(res,403,{error:'Linkvertise no confirmó este comprobante. Regresa una vez más desde Linkvertise para obtener un comprobante nuevo.'});
   }
   const total=REQUIREMENTS[Number(locked.dur)],completed=Math.min(total,Number(locked.completedLinks||0)+1),next=Number(locked.link)<total?Number(locked.link)+1:Number(locked.link),state=completed>=total?'complete':'ready';
   const done=await ref.transaction(cur=>{if(!cur||cur.verifyId!==verifyId)return;return{...cur,link:next,completedLinks:completed,state,lastVerifiedAt:Date.now(),lastVerifiedHash:hash,verifyStartedAt:null,verifyHash:null,verifyId:null};});
   if(!done.committed){const latest=await ref.get();if(latest.exists()&&(latest.val().lastVerifiedHash===hash||latest.val().state==='complete'))return json(res,200,{session:pub(latest.val()),deduplicated:true});return json(res,409,{error:'La verificación terminó, pero la sesión cambió. Recarga la página una vez.'});}
   const out=done.snapshot.val();return json(res,200,{session:pub(out)});
 }catch(e){
   await ref.transaction(cur=>cur&&cur.verifyId===verifyId?{...cur,state:'awaiting_external_return',verifyStartedAt:null,verifyHash:null,verifyId:null}:cur);
   throw e;
 }
}
if(method==='POST'&&route==='key/generate'){const s=await session(db,data.sessionId),deviceId=String(data.deviceId||''),total=REQUIREMENTS[Number(s.dur)];if(!sameDevice(s,deviceId))return json(res,403,{error:'El dispositivo no coincide con la sesión.'});if(s.state!=='complete'||Number(s.completedLinks)!==total)return json(res,409,{error:'La sesión no completó todos los pasos.'});await cleanupExpired(db);const key=deterministicKey(deviceId),ref=db.ref(`keys/${key}`),old=await ref.get();if(old.exists()){const k=old.val();if(k.status==='active'&&Number(k.expiresAt)>Date.now()){await db.ref(`sessions/${s.id}`).remove();return json(res,200,{key,expiresAt:Number(k.expiresAt),existing:true});}await ref.remove();}const createdAt=Date.now(),expiresAt=createdAt+Number(s.dur)*3600000;await ref.set({createdAt,expiresAt,hwid:s.deviceId,hours_duration:Number(s.dur),sessionId:s.id,status:'active'});await db.ref(`sessions/${s.id}`).remove();return json(res,200,{key,expiresAt});}
if(method==='GET'&&route==='key/validate'){const q=queryOf(req),key=String(q.get('key')||''),deviceId=String(q.get('deviceId')||'');if(!/^ZNEXUS-[A-Z0-9]{9}$/.test(key)||!validDevice(deviceId))return json(res,200,{valid:false});const ref=db.ref(`keys/${key}`),x=await ref.get();if(!x.exists())return json(res,200,{valid:false});const k=x.val(),expired=Number(k.expiresAt)<=Date.now(),valid=!expired&&k.status!=='revoked'&&k.hwid===deviceId;if(expired){await ref.remove();return json(res,200,{valid:false,expired:true});}return valid?json(res,200,{valid:true,expiresAt:Number(k.expiresAt)}):json(res,200,{valid:false});}
return json(res,404,{error:'Ruta API no encontrada.'});
}catch(e){console.error(e);return json(res,Number(e.status)||500,{error:typeof e?.message==='string'?e.message:'Error interno del servidor.'});}};
