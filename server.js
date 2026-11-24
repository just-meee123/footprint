// HarborPay backend. Run: node server.js   (Node 18+, no dependencies required)
// Email: BREVO_API_KEY or RESEND_API_KEY (both over HTTPS, recommended; Railway blocks SMTP ports on most plans) or SMTP_*; MAIL_FROM (an address on your verified domain), MAIL_REPLY_TO (your support inbox), APP_URL (https://yourdomain.com)
//        RESEND_WEBHOOK_SECRET turns on replies by email into Support (Resend inbound, webhook to /api/inbound/resend)
// Env: NODE_ENV=production (live mode: needs SECRET, turns off the demo 2-step code, listens on 127.0.0.1 behind Caddy unless HOST is set), PORT, SECRET (keeps sessions across restarts), DEMO_2FA (fixed code for demo accounts that have no authenticator app), SMTP_HOST/PORT/USER/PASS, MAIL_FROM (real email needs `npm i nodemailer`)
//      Phone checks by text message (optional, Twilio): TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM (a Twilio number like +15551234567) or TWILIO_MESSAGING_SERVICE_SID
//      Support assistant and Ben use AI when OPENAI_API_KEY, GROQ_API_KEY (free), GEMINI_API_KEY (free) or ANTHROPIC_API_KEY is set (optional: AI_MODEL). Without a key it uses built-in answers.
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
let nodemailer;try{nodemailer=require('nodemailer')}catch{}
const PORT=process.env.PORT||3000,DIR=path.join(__dirname,'data'),FILE=path.join(DIR,'db.json'),KYCDIR=path.join(DIR,'kyc');
const LIVE=process.env.NODE_ENV==='production'; // live mode: no demo shortcuts, and a fixed SECRET is required
if(LIVE&&!(process.env.SECRET&&process.env.SECRET.length>=32)){console.error('\nNODE_ENV=production needs a SECRET of at least 32 random characters, so sign-ins survive restarts. Set SECRET and start again.\n');process.exit(1)}
const SECRET=process.env.SECRET||crypto.randomBytes(32).toString('hex');
fs.mkdirSync(KYCDIR,{recursive:true});

/* ---- constants ---- */
const ELIGIBLE=['United States','United Kingdom','Thailand','Poland','Mexico','Argentina','Morocco','Monaco','Philippines'];
const FIAT=['USD','EUR','GBP','MXN','COP'],CRYPTO=['BTC','ETH','USDT','USDC'],ALLC=[...FIAT,...CRYPTO],FIAT_RATES={USD:1,EUR:1.08,GBP:1.27,MXN:0.0556,COP:0.00031}; // fiat rates are indicative: update them (or wire in a rates feed) before going live
const MIN_DEP={USD:10,EUR:10,GBP:10,MXN:200,COP:40000},ZERO=()=>Object.fromEntries(ALLC.map(c=>[c,0]));
const RE={evm:/^0x[a-fA-F0-9]{40}$/,tron:/^T[1-9A-HJ-NP-Za-km-z]{33}$/,btc:/^(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/};
const NETS={BTC:[{name:'Bitcoin',fee:0.00015,re:RE.btc}],ETH:[{name:'Ethereum',fee:0.002,re:RE.evm}],
  USDT:[{name:'Tron (TRC20)',fee:1,re:RE.tron},{name:'Ethereum (ERC20)',fee:6,re:RE.evm}],USDC:[{name:'Ethereum (ERC20)',fee:6,re:RE.evm},{name:'Polygon',fee:0.5,re:RE.evm}]};
const CMIN={BTC:0.0001,ETH:0.002,USDT:10,USDC:10}; // default minimum crypto deposits (admins can change them)
const HASH_RE=/^((0x)?[a-fA-F0-9]{64}|[1-9A-HJ-NP-Za-km-z]{80,90})$/;
const SOL_RE=/^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
/* networks customers can DEPOSIT on (cheapest first). Withdrawals keep using NETS. */
const DNETS={BTC:[{name:'Bitcoin',re:RE.btc}],ETH:[{name:'Arbitrum',re:RE.evm},{name:'Ethereum',re:RE.evm}],
  USDT:[{name:'Tron (TRC20)',re:RE.tron},{name:'BNB Smart Chain (BEP20)',re:RE.evm},{name:'Polygon',re:RE.evm},{name:'Arbitrum',re:RE.evm},{name:'Ethereum (ERC20)',re:RE.evm}],
  USDC:[{name:'Polygon',re:RE.evm},{name:'Arbitrum',re:RE.evm},{name:'BNB Smart Chain (BEP20)',re:RE.evm},{name:'Ethereum (ERC20)',re:RE.evm}]};
const ID_TYPES=['ID card',"Driver's licence",'Passport'];
const SOCIAL=['x','instagram','facebook','tiktok','youtube','telegram','whatsapp','threads'];
const DEF={fee:0.005,registrations:true,withdrawalsPaused:false,emailCustomers:true,limits:{daily:15000,monthly:500000,thirdParty:4000},bot:true,adminAlerts:false,social:{},referral:'optional'};
/* What customers see under each currency's account details (Fees / Limits / Speed). Admins edit these; the minimum deposit is also enforced. */
const CREDIT=['When it is credited','After the transfer is confirmed'];
const DEF_INFO={
  USD:{fees:[['Deposit fee','Free'],['Bank fees','Your bank may also charge fees.']],limits:[],speed:[['ACH arrival time','Usually 1-3 business days'],['Wire arrival time',"Usually the same business day if sent before your bank's cut-off time"],CREDIT]},
  EUR:{fees:[['Deposit fee','Free'],['Bank fees','Your bank may also charge fees.']],limits:[],speed:[['SEPA arrival time','Usually 1 business day, or seconds with SEPA Instant where your bank offers it'],CREDIT]},
  GBP:{fees:[['Deposit fee','Free'],['Bank fees','Your bank may also charge fees.']],limits:[],speed:[['Faster Payments arrival time','Usually within 2 hours, often in seconds'],CREDIT]},
  MXN:{fees:[['Deposit fee','Free'],['Bank fees','Your bank may also charge fees.']],limits:[],speed:[['SPEI arrival time','Usually within minutes'],CREDIT]},
  COP:{fees:[['Deposit fee','Free'],['Bank fees','Your bank may also charge fees.']],limits:[],speed:[['ACH Colombia arrival time','Usually 1 business day'],CREDIT]}
};
/* Bank withdrawals: the bank details asked for in each supported country. re: what the number must look like once spaces and dashes are removed. */
const BANK_FIELDS={
  'United States':[['routingNumber','Routing number',/^\d{9}$/,'9 digits'],['accountNumber','Account number',/^\d{4,17}$/,'4 to 17 digits']],
  'United Kingdom':[['sortCode','Sort code',/^\d{6}$/,'6 digits'],['accountNumber','Account number',/^\d{8}$/,'8 digits']],
  'Thailand':[['accountNumber','Account number',/^\d{10,12}$/,'10 to 12 digits']],
  'Poland':[['iban','IBAN',/^PL\d{26}$/i,'PL followed by 26 digits']],
  'Mexico':[['clabe','CLABE',/^\d{18}$/,'18 digits']],
  'Argentina':[['cbu','CBU or CVU',/^\d{22}$/,'22 digits']],
  'Morocco':[['rib','RIB',/^\d{24}$/,'24 digits']],
  'Monaco':[['iban','IBAN',/^MC\d{2}[A-Z0-9]{23}$/i,'MC followed by 25 characters'],['bic','BIC / SWIFT',/^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/i,'8 or 11 characters']],
  'Philippines':[['accountNumber','Account number',/^\d{10,16}$/,'10 to 16 digits']]
};
/* Bank withdrawals by currency: an account in that currency, wherever it is. f: required details; x: optional extras; nb: bank name optional */
const CUR_BANK={
  USD:{label:'US dollar account (ACH / wire)',f:[['routingNumber','Routing number (ABA)',/^\d{9}$/,'9 digits'],['accountNumber','Account number',/^\d{4,17}$/,'4 to 17 digits']],x:['accountType','bankAddress']},
  EUR:{label:'Euro account (SEPA / IBAN)',f:[['iban','IBAN',/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/,'2 letters, 2 digits, then 11 to 30 letters or digits'],['bic','BIC / SWIFT',/^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/,'8 or 11 letters or digits']],x:['bankAddress']},
  GBP:{label:'British pound account (UK)',f:[['sortCode','Sort code',/^\d{6}$/,'6 digits'],['accountNumber','Account number',/^\d{8}$/,'8 digits']],x:['bankAddress']},
  MXN:{label:'Mexican peso account (SPEI)',f:[['clabe','CLABE',/^\d{18}$/,'18 digits']],x:[],nb:true},
  COP:{label:'Colombian peso account (Bre-B)',f:[['brebKey','Bre-B key',/^[A-Za-z0-9@._+-]{3,60}$/,'your Bre-B key: phone number, ID number, email or alphanumeric key']],x:[],nb:true,keep:true}};
const bankDest=d=>d&&d.payCur?`${d.payCur} account`:d&&d.country?'a bank in '+d.country:'a bank';
const SYM={USD:'$',EUR:'\u20AC',GBP:'\u00A3',MXN:'MX$',COP:'COL$'};
const money=(c,a)=>SYM[c]?SYM[c]+Number(a).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2}):Number(a)+' '+c;
const r8=n=>+Number(n).toFixed(8),str=(v,n)=>String(v==null?'':v).trim().slice(0,n);

/* ---- crypto helpers ---- */
const uid=p=>p+'_'+crypto.randomBytes(5).toString('hex'),hex=n=>crypto.randomBytes(n/2).toString('hex');
const hash=(p,s=crypto.randomBytes(16).toString('hex'))=>s+':'+crypto.scryptSync(p,s,32).toString('hex');
const check=(p,h)=>{const[s,x]=(h||':').split(':');return !!x&&crypto.timingSafeEqual(Buffer.from(hash(p,s).split(':')[1],'hex'),Buffer.from(x,'hex'))};
const hm=b=>crypto.createHmac('sha256',SECRET).update(b).digest('hex');
const sign=(id,ttl=6048e5)=>{const b=id+'.'+(Date.now()+ttl);return b+'.'+hm(b)};
const unsign=t=>{const p=String(t||'').split('.');if(p.length!==3||hm(p[0]+'.'+p[1])!==p[2]||+p[1]<Date.now())return;return p[0]};
const digits=n=>Array.from({length:n},()=>crypto.randomInt(10)).join('');
/* Account details per fiat currency. Customers request them; an admin types in the details from the partner bank and approves.
   main: the field shown in lists and audit logs. Required fields must be filled before details can be approved. */
const ACCT_FIELDS={
  USD:{method:'ACH or wire',main:'accountNumber',f:[['accountName','Account holder name',1],['accountNumber','Account number',1],['routingNumber','Routing number',1],['bankName','Bank name',1],['bankAddress','Bank address',0]]},
  EUR:{method:'SEPA transfer',main:'iban',f:[['accountName','Account holder name',1],['iban','IBAN',1],['bic','BIC',1],['bankName','Bank name',1],['bankAddress','Bank address',0]]},
  GBP:{method:'Faster Payments',main:'accountNumber',f:[['accountName','Account holder name',1],['accountNumber','Account number',1],['sortCode','Sort code',1],['bankName','Bank name',1],['bankAddress','Bank address',0]]},
  MXN:{method:'SPEI transfer',main:'clabe',f:[['accountName','Account holder name',1],['clabe','CLABE',1]]},
  COP:{method:'Bre-B transfer',main:'brebKey',f:[['accountName','Account holder name',1],['brebKey','Bre-B key',1]]}
};
const blankDetails=c=>({method:ACCT_FIELDS[c].method,...Object.fromEntries(ACCT_FIELDS[c].f.map(([k])=>[k,''])),accountName:'Harborpay Client Funds',instructions:''});
const acct=(u,c)=>{u.accts=u.accts||{};return u.accts[c]=u.accts[c]||{status:'none'}};

/* ---- authenticator app codes (TOTP, RFC 6238: works with Google Authenticator, Microsoft Authenticator, Authy) ---- */
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc=buf=>{let bits='',o='';for(const b of buf)bits+=b.toString(2).padStart(8,'0');for(let i=0;i<bits.length;i+=5)o+=B32[parseInt(bits.slice(i,i+5).padEnd(5,'0'),2)];return o};
const b32dec=t=>{let bits='';for(const c of String(t).toUpperCase()){const v=B32.indexOf(c);if(v>=0)bits+=v.toString(2).padStart(5,'0')}const out=[];for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(out)};
const totpAt=(secret,step)=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(step));const h=crypto.createHmac('sha1',b32dec(secret)).update(b).digest(),o=h[19]&15;return String((h.readUInt32BE(o)&0x7fffffff)%1e6).padStart(6,'0')};
const pinOk=(u,p)=>/^\d{4}$/.test(String(p||''))&&!!u.pinHash&&check(String(p),u.pinHash);
const safeEq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const totpOk=(secret,code)=>{const c=String(code||'').replace(/\s/g,''),now=Math.floor(Date.now()/30000);return /^\d{6}$/.test(c)&&[0,-1,1].some(d=>safeEq(totpAt(secret,now+d),c))}; // accepts the current code and the ones just before/after, for phone clocks that are slightly off
const pendingTotp=new Map();

/* ---- store ---- */
let db;
if(fs.existsSync(FILE))db=JSON.parse(fs.readFileSync(FILE,'utf8'));
else{db=require('./seed.js')(uid,hex);db.creds={};for(const u of db.users){db.creds[u.id]=hash(u.pass);delete u.pass}}
db.notifs=db.notifs||[];db.pushSubs=db.pushSubs||[];db.sessions=db.sessions||[];db.invites=db.invites||[];
/* referral codes: every account has one; the admin can change it. Letters and numbers only, 4-16 long, unique. */
const REF_RE=/^[A-Z0-9]{4,16}$/,REF_ABC='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const refTaken=(code,exceptId)=>db.users.some(u=>u.id!==exceptId&&u.refCode===code);
function newRefCode(name){const base=String(name||'').toUpperCase().replace(/[^A-Z]/g,'').slice(0,5)||'HP';
  for(let i=0;i<50;i++){const c=base+[...crypto.randomBytes(4)].map(b=>REF_ABC[b%REF_ABC.length]).join('');if(!refTaken(c))return c}return 'HP'+crypto.randomBytes(6).toString('hex').toUpperCase()}
const ageOn=(dob,d)=>{if(!dob)return 0;const[y,m,dd]=dob.split('-').map(Number);let a=d.getUTCFullYear()-y;if(d.getUTCMonth()+1<m||(d.getUTCMonth()+1===m&&d.getUTCDate()<dd))a--;return a};
/* invite codes: a customer asks, the admin approves, and the code works for ONE sign-up within ONE hour */
const INV_TTL=36e5,INV_PER_DAY=3;
const invState=i=>i.status==='active'&&i.exp<=Date.now()?'expired':i.status;
const newInvCode=()=>{for(let n=0;n<100;n++){const c='HP'+[...crypto.randomBytes(6)].map(b=>REF_ABC[b%REF_ABC.length]).join('');if(!db.invites.some(i=>i.code===c))return c}return 'HP'+crypto.randomBytes(5).toString('hex').toUpperCase()};
const findRef=code=>{const c=String(code||'').trim().toUpperCase(),i=c&&db.invites.find(x=>x.code===c);if(!i)return{why:'missing'};const st=invState(i),u=byId(i.userId);
  if(st==='used')return{why:'used'};if(st!=='active'||!u||u.status!=='active')return{why:'expired'};return{inv:i,user:u}};db.sent=db.sent||[];db.creds=db.creds||{};db.totp=db.totp||{}; // totp: authenticator secrets, kept out of everything sent to the browser
db.settings={...DEF,...(db.settings||{}),limits:{...DEF.limits,...((db.settings||{}).limits||{})}};
for(const u of db.users||[]){
  if(u.role==='admin'){if(!u.refCode)u.refCode=newRefCode(u.name);continue}
  if(u.refApproved)continue;
  if(u.refCode&&db.users.some(x=>x.referredBy===u.id))u.refApproved=true; // already brought someone in: keeps the code
  else delete u.refCode} // codes are now requested and approved by the admin
if(!['off','optional','required'].includes(db.settings.referral))db.settings.referral='optional';
const AUTO_DEF={bday:{on:true,email:true,title:'Happy birthday, {name}! 🎉',body:'Everyone at HarborPay wishes you a wonderful birthday and a great year ahead. Thank you for being with us.'},
  nudge:{on:true,email:false,every:3,msgs:[
    ['Deposit now','Your HarborPay account is ready. Deposit now by bank transfer and your money shows in your balance as soon as it arrives.'],
    ['Withdraw with no stress','Send your balance to your bank or a crypto wallet in a few taps. No stress, no queues.'],
    ['Get paid in 5 currencies','Receive USD, EUR, GBP, MXN and COP by bank transfer, all in one HarborPay account.'],
    ['Convert to crypto in seconds','Turn your balance into USDT, USDC, BTC or ETH whenever you like, at live prices.'],
    ['Refer a friend & get rewarded!','Share HarborPay with your friends and help them enjoy secure, fast and seamless payments. Get your invite code on your Referral page.'],
    ['Get paid in many currencies. Withdraw anytime.','Receive USD, EUR, GBP, MXN and COP in one HarborPay account, and withdraw to your bank or a crypto wallet whenever you want.']],who:'quiet'}};
db.settings.auto={bday:{...AUTO_DEF.bday,...((db.settings.auto||{}).bday||{})},nudge:{...AUTO_DEF.nudge,...((db.settings.auto||{}).nudge||{})},mig:(db.settings.auto||{}).mig||0};
if(db.settings.auto.mig<1){const N=db.settings.auto.nudge;N.email=true;if(!N.msgs.some(m=>/withdraw anytime/i.test(m[0]+m[1])))N.msgs.push(AUTO_DEF.nudge.msgs[AUTO_DEF.nudge.msgs.length-1].slice());db.settings.auto.mig=1}
if(db.settings.auto.mig<2){const N=db.settings.auto.nudge,i=N.msgs.findIndex(m=>m[0]==='Invite a friend'&&/one-time invite code/.test(m[1]));if(i>=0)N.msgs[i]=['Refer a friend & get rewarded!','Share HarborPay with your friends and help them enjoy secure, fast and seamless payments. Get your invite code on your Referral page.'];db.settings.auto.mig=2}
db.settings.social=Object.fromEntries(SOCIAL.map(k=>[k,str((db.settings.social||{})[k],120)]));
db.settings.minDep={...MIN_DEP,...(db.settings.minDep||{})};db.settings.cryptoIn=db.settings.cryptoIn||{};db.settings.cryptoMin={...CMIN,...(db.settings.cryptoMin||{})};db.settings.curLimits=db.settings.curLimits||{};db.settings.depositInfo={...JSON.parse(JSON.stringify(DEF_INFO)),...(db.settings.depositInfo||{})};
for(const u of db.users){delete u.tier;if(typeof u.pin==='string'&&u.pin){if(/^\d{4}$/.test(u.pin))u.pinHash=hash(u.pin);}delete u.pin;u.bal={...ZERO(),...(u.bal||{})};
  if(!u.ev)u.ev={status:u.role==='admin'||['u_demo','u_4'].includes(u.id)?'verified':u.id==='u_3'?'requested':'none'};
  if(!u.accts){u.accts={}; // older data kept USD details in u.usd
    if(u.usd)u.accts.USD=u.usd;
    else if(u.id==='u_demo')u.accts.USD={status:'approved',details:{...blankDetails('USD'),bankName:'Partner bank',routingNumber:'000000000',accountNumber:'0000000000'},approvedAt:Date.now()};
    else if(u.id==='u_2')u.accts.USD={status:'under_review',draft:blankDetails('USD'),requestedAt:Date.now()}}
  delete u.usd;for(const c of FIAT)acct(u,c)}
let st;const save=()=>{clearTimeout(st);st=setTimeout(()=>{fs.writeFileSync(FILE+'.tmp',JSON.stringify(db));fs.renameSync(FILE+'.tmp',FILE)},200)};
/* when Railway (or Ctrl+C) stops the server, write any change that is still waiting before exiting */
const flush=()=>{clearTimeout(st);try{fs.writeFileSync(FILE+'.tmp',JSON.stringify(db));fs.renameSync(FILE+'.tmp',FILE)}catch(e){console.error('save on exit',e.message)}};
for(const sig of['SIGTERM','SIGINT'])process.on(sig,()=>{flush();process.exit(0)});
/* Hosting without a terminal (Railway, Render...): set ADMIN_EMAIL + ADMIN_PASSWORD (and optionally ADMIN_PIN, REMOVE_DEMO=1) once, start, then remove them. */
{const E=String(process.env.ADMIN_EMAIL||'').trim().toLowerCase(),P=String(process.env.ADMIN_PASSWORD||''),N=String(process.env.ADMIN_PIN||'');
 if(E||P){const a=db.users.find(u=>u.role==='admin');
   if(!a)console.error('ADMIN_EMAIL: no admin account found.');
   else if(!/^\S+@\S+\.\S+$/.test(E)||P.length<12||!/[a-z]/i.test(P)||!/\d/.test(P))console.error('ADMIN_EMAIL / ADMIN_PASSWORD ignored: use a real email and a password of 12+ characters with letters and numbers.');
   else if(db.users.some(u=>u.id!==a.id&&u.email.toLowerCase()===E))console.error('ADMIN_EMAIL ignored: another account already uses that email.');
   else{a.email=E;a.ev={status:'verified',ts:Date.now()};db.creds[a.id]=hash(P);if(!db.totp[a.id])a.twofa=false;if(/^\d{4}$/.test(N))a.pinHash=hash(N);
     db.audit.unshift({ts:Date.now(),actor:E,action:'Admin sign-in set from server settings',detail:E,ip:'server'});
     console.log(`Admin sign-in set to ${E}. Remove ADMIN_EMAIL, ADMIN_PASSWORD and ADMIN_PIN from the server settings now.`)}}
 if(process.env.REMOVE_DEMO==='1'){const ids=new Set(db.users.filter(u=>u.role==='customer'&&(['u_demo','u_2','u_3','u_4'].includes(u.id)||['demo@harbor.demo','amara@example.com','liam@example.com','sofia@example.com'].includes(u.email))).map(u=>u.id));
   if(ids.size){db.users=db.users.filter(u=>!ids.has(u.id));for(const k of['txs','kycs','tickets','notifs'])db[k]=(db[k]||[]).filter(x=>!ids.has(x.userId));for(const id of ids){delete db.creds[id];delete db.totp[id]}
     db.ann=(db.ann||[]).filter(x=>!/demo|review times/i.test(x.title||''));console.log(`Removed ${ids.size} demo customers. You can remove REMOVE_DEMO now.`)}}}
save();
const addAudit=(actor,action,detail,ip)=>{db.audit.unshift({ts:Date.now(),actor,action,detail:detail||'',ip:ip||''});if(db.audit.length>3000)db.audit.length=3000;try{secCool(actor,action)}catch{}};
const ipOf=req=>String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim().replace('::ffff:','');
const byId=id=>db.users.find(u=>u.id===id);

/* ---- realtime (SSE) + live prices ---- */
const clients=new Map();
const push=(userId,ev,data)=>{for(const[res,c]of clients)if(!userId||c.uid===userId)res.write(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`)};
/* ---- signed-in devices: every sign-in is its own session, so a person can see and sign out their other devices ---- */
const uaName=a=>{a=String(a||'');const os=/iPhone/.test(a)?'iPhone':/iPad/.test(a)?'iPad':/Android/.test(a)?'Android phone':/Macintosh|Mac OS X/.test(a)?'Mac':/Windows/.test(a)?'Windows computer':/CrOS/.test(a)?'Chromebook':/Linux/.test(a)?'Linux computer':'Unknown device';
  const br=/Edg\//.test(a)?'Edge':/OPR\//.test(a)?'Opera':/SamsungBrowser/.test(a)?'Samsung Internet':/Firefox\/|FxiOS/.test(a)?'Firefox':/CriOS|Chrome\//.test(a)?'Chrome':/Safari\//.test(a)?'Safari':'browser';return `${os}, ${br}`};
function newSession(u,req){
  adminGate(u,req,req.viaPk);
  const s={id:crypto.randomBytes(9).toString('hex'),userId:u.id,created:Date.now(),lastSeen:Date.now(),ip:ipOf(req),device:uaName(req.headers['user-agent']),dev:devOf(req)||undefined};
  const mine=db.sessions.filter(x=>x.userId===u.id);
  if(mine.length&&!mine.some(x=>x.device===s.device&&x.ip===s.ip))notify(u.id,'New sign-in',`Your account was just signed in on ${s.device}. If this wasn't you, change your password and sign out that device in Security.`,{noMail:u.role==='admin',details:[['Device',s.device],['IP address',s.ip],['Time',new Date().toUTCString().replace('GMT','UTC')]]});
  db.sessions.push(s);if(mine.length>=20)db.sessions=db.sessions.filter(x=>x!==mine.sort((a,b)=>a.lastSeen-b.lastSeen)[0]); // up to 20 devices per person
  save();return sign(u.id+'~'+s.id)}
function endSessions(userId,keep){ // sign out (all but `keep`), close their live connections and stop their alerts
  const gone=db.sessions.filter(x=>x.userId===userId&&x.id!==keep).map(x=>x.id);if(!gone.length)return 0;
  db.sessions=db.sessions.filter(x=>!gone.includes(x.id));db.pushSubs=(db.pushSubs||[]).filter(p=>!(p.userId===userId&&p.sid&&gone.includes(p.sid)));
  for(const[res,c]of clients)if(gone.includes(c.sid)){try{res.write(`event: signedout\ndata: {}\n\n`);res.end()}catch{}clients.delete(res)}
  save();return gone.length}

const pushAdmins=(ev,d)=>{for(const[res,c]of clients){const u=byId(c.uid);if(u&&u.role==='admin')res.write(`event: ${ev}\ndata: ${JSON.stringify(d)}\n\n`)}};

/* ---- phone / computer alerts (Web Push, RFC 8030 / 8291 / 8292) — no extra packages ----
   Keys are made once and kept in data/db.json (db.vapid, never sent to the browser). Each message is encrypted for the
   device it goes to, so Google / Apple / Mozilla only carry it and cannot read it. */
const b64u=b=>Buffer.from(b).toString('base64').replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
const ub64=s=>Buffer.from(String(s).replace(/-/g,'+').replace(/_/g,'/'),'base64');
function vapidKeys(){
  if(process.env.VAPID_PUBLIC_KEY&&process.env.VAPID_PRIVATE_KEY)return{pub:process.env.VAPID_PUBLIC_KEY,priv:process.env.VAPID_PRIVATE_KEY};
  if(!db.vapid){const k=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),j=k.privateKey.export({format:'jwk'});
    db.vapid={pub:b64u(Buffer.concat([Buffer.from([4]),ub64(j.x),ub64(j.y)])),priv:j.d};save()}
  return db.vapid}
const vapidPrivKey=()=>{const v=vapidKeys(),p=ub64(v.pub);return crypto.createPrivateKey({key:{kty:'EC',crv:'P-256',d:v.priv,x:b64u(p.subarray(1,33)),y:b64u(p.subarray(33,65))},format:'jwk'})};
const hkdf=(salt,ikm,info,len)=>{const prk=crypto.createHmac('sha256',salt).update(ikm).digest();return crypto.createHmac('sha256',prk).update(Buffer.concat([info,Buffer.from([1])])).digest().subarray(0,len)};
function encryptPush(sub,payload){
  const ua=ub64(sub.keys.p256dh),auth=ub64(sub.keys.auth),eph=crypto.createECDH('prime256v1');eph.generateKeys();
  const as=eph.getPublicKey(),secret=eph.computeSecret(ua),salt=crypto.randomBytes(16);
  const ikm=hkdf(auth,secret,Buffer.concat([Buffer.from('WebPush: info\0'),ua,as]),32);
  const cek=hkdf(salt,ikm,Buffer.from('Content-Encoding: aes128gcm\0'),16),nonce=hkdf(salt,ikm,Buffer.from('Content-Encoding: nonce\0'),12);
  const c=crypto.createCipheriv('aes-128-gcm',cek,nonce),body=Buffer.concat([c.update(Buffer.concat([Buffer.from(payload),Buffer.from([2])])),c.final(),c.getAuthTag()]);
  const head=Buffer.alloc(21);salt.copy(head,0);head.writeUInt32BE(4096,16);head[20]=as.length;
  return Buffer.concat([head,as,body])}
const vapidCache=new Map();
function vapidAuth(endpoint){
  const aud=new URL(endpoint).origin,hit=vapidCache.get(aud);if(hit&&hit.until>Date.now())return hit.v;
  const h=b64u(JSON.stringify({typ:'JWT',alg:'ES256'})),c=b64u(JSON.stringify({aud,exp:Math.floor(Date.now()/1e3)+12*3600,sub:'mailto:'+(String(process.env.MAIL_REPLY_TO||'').match(/[^\s<>]+@[^\s<>]+/)||['support@harborpay.us.com'])[0]}));
  const sig=crypto.sign('sha256',Buffer.from(h+'.'+c),{key:vapidPrivKey(),dsaEncoding:'ieee-p1363'});
  const v=`vapid t=${h}.${c}.${b64u(sig)}, k=${vapidKeys().pub}`;vapidCache.set(aud,{v,until:Date.now()+55*60e3});return v}
async function pushTo(userId,title,body,url){
  const subs=(db.pushSubs||[]).filter(s=>s.userId===userId);if(!subs.length)return[];
  const payload=JSON.stringify({title:String(title).slice(0,120),body:String(body||'').slice(0,240),url:url||'/',tag:'hp-'+Date.now()});
  return Promise.all(subs.map(async s=>{const dev=s.device||'a device';try{
    const r=await fetch(s.endpoint,{method:'POST',headers:{'Content-Encoding':'aes128gcm','Content-Type':'application/octet-stream',TTL:'86400',Urgency:'high',Authorization:vapidAuth(s.endpoint)},body:encryptPush(s,payload),signal:AbortSignal.timeout(10000)});
    if(r.status===404||r.status===410){db.pushSubs=db.pushSubs.filter(x=>x!==s);save();return{device:dev,ok:false,status:r.status,reason:'This device stopped accepting alerts. Turn them on again there.'}} // the device turned alerts off or the browser was reset
    if(!r.ok){const t=(await r.text().catch(()=>'')).slice(0,300);let reason=t;try{reason=JSON.parse(t).reason||t}catch{}
      if(r.status===403&&/VapidPkHashMismatch|BadJwt|BadVapid/i.test(reason)){db.pushSubs=db.pushSubs.filter(x=>x!==s);save()} // made with old keys: the device has to turn alerts on again
      console.error('push',r.status,reason,new URL(s.endpoint).host);return{device:dev,ok:false,status:r.status,reason}}
    s.lastOk=Date.now();return{device:dev,ok:true,status:r.status}
  }catch(e){console.error('push',e.message);return{device:dev,ok:false,reason:e.message}}}))}
const pushOk=s=>s&&typeof s.endpoint==='string'&&/^https:\/\/[^\s]+$/.test(s.endpoint)&&s.endpoint.length<1000&&s.keys&&/^[A-Za-z0-9_-]{80,100}$/.test(s.keys.p256dh||'')&&/^[A-Za-z0-9_-]{16,30}$/.test(s.keys.auth||'');
const mailRows=d=>(d||[]).filter(r=>r&&r[1]!=null&&String(r[1]).trim()).map(r=>`\n${r[0]}: ${String(r[1]).replace(/\s+/g,' ').slice(0,140)}`).join('').replace(/^/,m=>m?'\n':'');
function notify(userId,title,body,extra){const cu0=byId(userId);if(cu0&&cu0.role==='customer'&&db.settings&&db.settings.customerInApp===false&&!(extra&&extra.force)){if(!(extra&&extra.noMail)&&db.settings.emailCustomers!==false&&cu0.status!=='closed')mail(cu0.email,title,`Hi ${first(cu0)},\n\n${body}${mailRows(extra&&extra.details)}`).catch(()=>{});return{id:'',userId,title,body,ts:Date.now()}}
  const{noMail,details,force,...more}=extra||{},n={id:uid('n'),userId,title,body,ts:Date.now(),read:false,...more};more.details=details;db.notifs.unshift(n);if(db.notifs.length>5000)db.notifs.length=5000;push(userId,'notif',n);
  if(!more.noPush)pushTo(userId,title,body,more.view?'/?v='+encodeURIComponent(more.view):'/').catch(()=>{});
  const u=byId(userId);if(u&&u.role==='customer'&&u.status!=='closed'&&!noMail&&db.settings&&db.settings.emailCustomers!==false)mail(u.email,title,`Hi ${first(u)},\n\n${body}${mailRows(more.details)}`).catch(()=>{}); // every customer update also goes by email; details: [[label,value]] become a details box in the email only
  return n}
/* admin alerts: each kind can go in the app, by email, both, or nowhere (Controls → Notifications) */
const NCAT={geoalerts:'location',deposits:'money',withdrawals:'money',kyc:'checks',verifs:'checks',emailverify:'checks',usdaccounts:'checks',support:'support',security:'security',activity:'security',audit:'security',users:'customers',referrals:'customers',birthdays:'customers'};
const ncatOf=view=>NCAT[view]||'system';
const nPref=cat=>{const P=(db.settings&&db.settings.adminNotif)||{},d={app:true,mail:cat==='location'||cat==='security'?true:!!(db.settings&&db.settings.adminAlerts)};return{...d,...(P[cat]||{})}};
const notifyAdmins=(title,body,view,o={})=>{const pr=nPref(o.cat||ncatOf(view));db.users.filter(u=>u.role==='admin'&&u.status!=='closed').forEach(a=>{if(pr.app)notify(a.id,title,body,view?{view}:{});
  if(pr.mail&&!o.noMail)mail(a.email,o.mailSubject||'HarborPay: '+title,o.mailBody||`${body}\n\nOpen the admin panel to see more.\n\n— HarborPay`).catch(()=>{})})};
const IDS={BTC:'bitcoin',ETH:'ethereum',USDT:'tether',USDC:'usd-coin'};
const prices={BTC:{usd:68000,chg:0},ETH:{usd:3400,chg:0},USDT:{usd:1,chg:0},USDC:{usd:1,chg:0}},hist={BTC:[],ETH:[],USDT:[],USDC:[]};
let source='simulated',mts=Date.now();
const market=()=>({prices,hist,source,ts:mts});
const rate=c=>FIAT_RATES[c]||(prices[c]?prices[c].usd:1),toUsd=(c,a)=>a*rate(c);
/* platform fee: a percentage of the amount, or a fixed amount in USD per transaction (converted to the currency used) */
/* fees: each fiat currency has its own fee, a percentage or a fixed amount in that currency; crypto balances use the default percentage */
function feeSetup(){const s=db.settings;if(s.fees&&FIAT.every(c=>s.fees[c]))return;const flat=s.feeMode==='flat',usd=+s.feeFlat||0;s.fees=s.fees||{};
  for(const c of FIAT)if(!s.fees[c])s.fees[c]={mode:flat?'flat':'pct',pct:+s.fee||0,flat:flat?Math.round(usd/rate(c)*100)/100:0}}
const feeOf=cur=>{feeSetup();return FIAT.includes(cur)?db.settings.fees[cur]:{mode:'pct',pct:+db.settings.fee||0,flat:0}};
const srcFee=(amt,cur)=>{const f=feeOf(cur);return f.mode==='flat'?Math.min(+f.flat||0,amt):amt*(+f.pct||0)}; // in the currency being spent
const platFee=(amt,cur,src)=>src&&src!==cur?srcFee(amt*rate(cur)/rate(src),src)*rate(src)/rate(cur):srcFee(amt,cur);
const feeLabel=cur=>{const f=feeOf(cur);return f.mode==='flat'?money(cur,+f.flat||0):+((+f.pct||0)*100).toFixed(3)+'%'};
const feeText=()=>FIAT.map(c=>`${c} ${feeLabel(c)}${feeOf(c).mode==='flat'?' per transaction':''}`).join(', ');
feeSetup();
async function tick(){
  try{
    const r=await fetch('https://api.coingecko.com/api/v3/simple/price?ids='+Object.values(IDS)+'&vs_currencies=usd&include_24hr_change=true',{signal:AbortSignal.timeout(8000)});
    if(!r.ok)throw 0;const j=await r.json();
    for(const[k,id]of Object.entries(IDS))prices[k]={usd:j[id].usd,chg:j[id].usd_24h_change||0};source='coingecko';
  }catch{source='simulated';for(const k of['BTC','ETH'])prices[k].usd*=1+(Math.random()-.5)*.002}
  mts=Date.now();for(const k in prices){hist[k].push([mts,prices[k].usd]);if(hist[k].length>120)hist[k].shift()}
  push(null,'prices',market());
}
tick();setInterval(tick,15000);
/* ---- automatic messages: birthday wishes and friendly reminders ("Deposit now", "Withdraw with no stress") ----
   Checked every 10 minutes. Reminders go out between 09:00 and 19:00 UTC, at most once every N days per customer,
   only to customers who have not made a transaction in that time and have not turned reminders off. */
const nextBday=(u,d)=>{const[m,dd]=u.bday.split('-').map(Number);for(let y=d.getUTCFullYear();y<d.getUTCFullYear()+5;y++){const x=new Date(Date.UTC(y,m-1,m===2&&dd===29&&!(y%4===0&&(y%100!==0||y%400===0))?28:dd));if(x.getTime()>=Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate()))return x}};
const fillMsg=(t,u)=>String(t||'').replace(/\{name\}/g,first(u)).replace(/\{code\}/g,u.refCode||'');
const bdayToday=(u,d)=>{if(!u.bday)return false;const md=String(d.getUTCMonth()+1).padStart(2,'0')+'-'+String(d.getUTCDate()).padStart(2,'0');
  if(u.bday===md)return true;const leap=y=>y%4===0&&(y%100!==0||y%400===0);return u.bday==='02-29'&&md==='02-28'&&!leap(d.getUTCFullYear())};
function autoRun(){
  const A=db.settings.auto,now=new Date(),t=now.getTime(),hr=now.getUTCHours(),yr=now.getUTCFullYear();let changed=false;
  for(const u of db.users){if(u.role!=='customer'||u.status!=='active')continue;
    if(hr>=7&&u.bday){
      const tom=new Date(t+DAY_MS);
      if(bdayToday(u,tom)&&u.bdayPre!==tom.getUTCFullYear()){u.bdayPre=tom.getUTCFullYear();changed=true;notifyAdmins('🎂 Birthday tomorrow',`${u.name} turns ${ageOn(u.dob,tom)||'a year older'} tomorrow. Approve their birthday wish in Birthdays so it goes out on the day.`,'birthdays')}
      if(bdayToday(u,now)){const w=u.bdayWish;
        if(w&&w.status==='approved'&&w.year===yr){sendWish(u,w);changed=true}
        else if(u.bdayNotified!==yr&&!(w&&w.status==='sent'&&w.year===yr)){u.bdayNotified=yr;changed=true;notifyAdmins('🎂 Birthday today',`It's ${u.name}'s birthday today${u.dob?` (${ageOn(u.dob,now)})`:''}. Their wish is waiting for your approval in Birthdays.`,'birthdays')}}}
    if(stageRun(u,t,hr))changed=true;
    if(u.referredBy&&!u.refRewarded&&!u.refPending&&refHandle(u))changed=true;
    const msgs=(A.nudge.msgs||[]).filter(m=>m[0]&&m[1]&&!m[2]&&!/\{code\}/.test(m[0]+m[1]));if(u.reminders===false)continue;
    if(A.nudge.on&&msgs.length&&hr>=9&&hr<19&&u.reminders!==false&&t-u.created>DAY_MS){
      const gap=Math.max(1,+A.nudge.every||3)*DAY_MS,last=Math.max(u.lastNudge||0,u.created||0);
      if(t-last>=gap&&(A.nudge.who==='all'||!db.txs.some(x=>x.userId===u.id&&x.ts>t-gap))){const i=(u.nudgeIdx||0)%msgs.length,m=msgs[i];u.nudgeIdx=i+1;u.lastNudge=t;changed=true;
        notify(u.id,fillMsg(m[0],u),fillMsg(m[1],u),{noMail:!A.nudge.email,kind:'reminder'})}}}
  if(changed)save()}
const DAY_MS=864e5;
/* ---- getting-started messages: welcome at sign-up, then "finish your ID check" and "make your first deposit" ---- */
const STAGE_DEF={on:true,email:true,every:3,max:3,
  welcome:{on:true,title:'Welcome to HarborPay, {name}! 👋',body:'Your account is ready. Three steps to get paid: 1) verify your identity (about 2 minutes), 2) request your account details for the currency you are paid in, 3) share them with your client or platform. Your money shows in your balance as soon as it arrives.'},
  kyc:{on:true,after:1,title:'Finish your ID check, {name}',body:'It takes about 2 minutes: a photo of your ID and a quick selfie. Once you are verified you can get your account details and withdraw anytime.'},
  dep:{on:true,after:2,title:'Ready for your first payment?',body:'You are verified. Request your account details for USD, EUR, GBP, MXN or COP and share them with your client or platform. Your money shows in your balance as soon as it arrives.'}};
{const g=db.settings.auto.stage||{};db.settings.auto.stage={...STAGE_DEF,...g,welcome:{...STAGE_DEF.welcome,...(g.welcome||{})},kyc:{...STAGE_DEF.kyc,...(g.kyc||{})},dep:{...STAGE_DEF.dep,...(g.dep||{})}}}
function depApply(actor,b,ip){ // result: completed (credit the balance), failed, rejected (declined) or reversed
    const note=str(b.note,200),result=['failed','rejected','reversed','processing'].includes(b.result)?b.result:'completed',reason=str(b.reason,200),fee=Math.round((+b.fee||0)*1e8)/1e8;
    let t;
    if(b.txId){t=db.txs.find(x=>x.id===b.txId&&x.type==='deposit');if(!t)throw fail(404,'Deposit not found.');if(t.status!=='pending')throw fail(400,'This deposit was already '+t.status+'.')}
    const amt=b.amount==null&&t?t.amount:Math.round(Number(b.amount)*1e8)/1e8;
    if(!(amt>0)||!isFinite(amt)||amt>1e9)throw fail(400,'Enter the amount, more than zero.');
    if(!(fee>=0)||!isFinite(fee))throw fail(400,'The fee must be 0 or more.');if(result==='completed'&&fee>=amt)throw fail(400,'The fee must be less than the amount.');
    const WORD={failed:'failed',rejected:'was declined',reversed:'was reversed'};
    if(!['completed','processing'].includes(result)&&!reason)throw fail(400,`Write the reason the deposit ${WORD[result]}. The customer sees it.`);
    const arrives=/^\d{4}-\d{2}-\d{2}$/.test(String(b.arrives||''))?String(b.arrives):'';
    if(result==='processing'&&b.txId)throw fail(400,'This deposit is already waiting. Choose the final result.');
    const u=needUser(t?t.userId:b.userId),cur=t?t.currency:b.currency;
    if(u.status==='closed')throw fail(400,'This account has been deleted.');
    if(!ALLC.includes(cur))throw fail(400,'Choose a currency.');if(FIAT.includes(cur)&&Math.abs(Math.round(fee*100)-fee*100)>1e-6)throw fail(400,'The fee can have at most 2 decimals.');
    if(t){if(amt!==t.amount)t.d.reported=t.amount;t.amount=amt}
    else{t={id:uid('tx'),userId:u.id,type:'deposit',status:'pending',ts:Date.now(),currency:cur,amount:amt,d:{sender:'self',byAdmin:true}};db.txs.unshift(t)}
    depInfo(t,b);if(CRYPTO.includes(cur)){const nm=(DNETS[cur].find(n=>n.name===b.method)||{}).name;if(!t.d.method||t.d.method!=='crypto'){t.d.network=nm||t.d.network||Object.keys(db.settings.cryptoIn[cur]||{})[0]||DNETS[cur][0].name;t.d.method='crypto'}else if(nm)t.d.network=nm;
      if(!t.d.address)t.d.address=(db.settings.cryptoIn[cur]||{})[t.d.network]||'';const rh=str(b.ref,100).replace(/\s/g,'');if(HASH_RE.test(rh)){t.d.hash=rh;delete t.d.bankRef}}
    if(note)t.d.adminNote=note;if(fee>0)t.d.fee=fee;else delete t.d.fee;
    if(result==='processing'){t.d.processing=true;if(arrives)t.d.arrives=arrives;else delete t.d.arrives;
      const from=t.d.fromName?` from ${t.d.fromName}`:'',by=arrives?` It should arrive by ${new Date(arrives+'T12:00:00Z').toLocaleDateString('en-GB',{day:'numeric',month:'long',timeZone:'UTC'})}.`:'';
      notify(u.id,'Incoming deposit processing',`A deposit of ${money(cur,amt)}${from} is on its way.${by} We will add it to your balance as soon as it arrives.`,{view:'transactions',tx:t.id});
      addAudit(actor,'Deposit recorded as processing',`${money(cur,amt)} for ${u.email}${from}${arrives?' (arrives by '+arrives+')':''}`,ip);
      save();push(u.id,'sync',{});pushAdmins('sync',{});return{ok:true,status:'pending',txId:t.id}}
    delete t.d.processing;delete t.d.arrives;
    if(result!=='completed'){t.status=result;t.note=reason;t.settledAt=Date.now();
      const what=WORD[result],from=t.d.fromName?` from ${t.d.fromName}`:'';if(result==='reversed')t.d.recorded=true;
      notify(u.id,{failed:'Deposit failed',rejected:'Deposit declined',reversed:'Deposit reversed'}[result],`Your deposit of ${money(cur,amt)}${from} ${what}. Reason: ${reason.replace(/[.\s]+$/,'')}. Nothing was added to your balance. Tap the transaction for details.`,{view:'transactions',tx:t.id});
      addAudit(actor,{failed:'Deposit marked failed',rejected:'Deposit declined',reversed:'Deposit recorded as reversed'}[result],`${money(cur,amt)} for ${u.email}: ${reason}`,ip);
      save();push(u.id,'sync',{});pushAdmins('sync',{});return{ok:true,status:result,txId:t.id}}
    const net=r8(amt-fee);if(fee>0){t.d.gross=amt;t.amount=net}else delete t.d.gross;
    u.bal[cur]=r8((u.bal[cur]||0)+net);t.status='completed';t.creditedAt=Date.now();refRewardCheck(t);
    const from=t.d.fromName?` from ${t.d.fromName}${t.d.fromBank?' ('+t.d.fromBank+')':''}`:'';
    notify(u.id,'Deposit received',fee>0?`${money(cur,amt)}${from} arrived. A fee of ${money(cur,fee)} was deducted, so ${money(cur,net)} was added to your ${cur} balance.`:`${money(cur,amt)}${from} was deposited to your ${cur} balance.${t.d.reported&&t.d.reported!==amt?` You reported ${money(cur,t.d.reported)}; the amount credited is what arrived.`:''}`,{noMail:true,tx:t.id});
    addAudit(actor,'Deposit credited',`${money(cur,net)} to ${u.email}${fee>0?` (${money(cur,amt)} less ${money(cur,fee)} fee)`:''}${from}${t.d.reported?` (reported ${money(cur,t.d.reported)})`:''}${note?': '+note:''}`,ip);
    save();push(u.id,'sync',{});pushAdmins('sync',{});
    mail(u.email,`${money(cur,net)} deposited to your HarborPay account`,`Hi ${first(u)},\n\n${fee>0?`${money(cur,amt)}${from} arrived. A fee of ${money(cur,fee)} was deducted, so ${money(cur,net)} was added to your ${cur} balance.`:`${money(cur,amt)}${from} was deposited to your ${cur} balance.`} Your new ${cur} balance is ${money(cur,u.bal[cur])}.${mailRows([['Amount',money(cur,amt)],['Currency',cur],...(fee>0?[['Fee',money(cur,fee)],['Credited',money(cur,net)]]:[]),['From',t.d.fromName?t.d.fromName+(t.d.fromBank?' ('+t.d.fromBank+')':''):''],['Reference',t.d.bankRef||t.id]])}\n\n— HarborPay`).catch(()=>{});
    return{ok:true,balance:u.bal[cur],txId:t.id}}
function wdApply(actor,b,ip){ // you sent the money (or it failed): record the result
    const t=db.txs.find(x=>x.id===b.txId&&x.type==='withdrawal');if(!t)throw fail(404,'Withdrawal not found.');
    const result=['failed','rejected','reversed'].includes(b.result)?b.result:'completed',reason=str(b.reason,200),u=byId(t.userId);if(!u)throw fail(404,'Customer not found.');
    if(result==='reversed'){if(t.status!=='completed')throw fail(400,'Only a withdrawal that was sent can be reversed.')}
    else if(t.status!=='pending')throw fail(400,'This withdrawal was already '+t.status+'.');
    const dest=t.d.method==='bank'?(t.d.payCur?`your ${t.d.payCur} bank account`:`your bank account in ${t.d.country}`):`your ${t.d.asset} wallet`,amtTxt=t.d.method==='bank'?money(t.currency,t.d.receive):`${t.d.receive} ${t.d.asset}`;
    for(const[k,n]of[['payRef',80],['payMethod',60],['payBank',100]]){const v=str(b[k],n);if(v)t.d[k]=v}
    if(result==='completed'&&t.d.hold&&t.d.hold.until>Date.now()&&!b.override)throw fail(423,`This withdrawal is on a safety hold (${t.d.hold.why.join(', ')}) until ${new Date(t.d.hold.until).toUTCString().slice(5,22)} UTC. Wait, or tick "Send anyway" if you have confirmed it with the customer.`);
    if(result==='completed'&&t.d.hold&&t.d.hold.until>Date.now()&&b.override)addAudit(actor,'Safety hold overridden',`${money(t.currency,t.amount)} for ${u.email}`,ip);
    if(result==='completed'){t.status='completed';t.d.paidAt=Date.now();t.d.paidBy=actor;if(t.d.method!=='bank'&&b.payRef)t.d.hash=str(b.payRef,120);
      notify(u.id,'Withdrawal sent',`${amtTxt} was sent to ${dest}${t.d.payRef?`. Reference: ${t.d.payRef}`:''}. It can take 1 to 3 business days to show, depending on your bank.`,{view:'transactions',tx:t.id});
      addAudit(actor,'Withdrawal paid out',`${amtTxt} to ${u.email}${t.d.payRef?' (ref '+t.d.payRef+')':''}`,ip)}
    else{if(!reason)throw fail(400,'Write the reason. The customer sees it.');
      u.bal[t.currency]=r8((u.bal[t.currency]||0)+t.amount);t.status=result;t.note=reason;t.d.settledAt=Date.now();
      if(result==='reversed')t.d.returnedAt=Date.now();
      notify(u.id,{failed:'Withdrawal failed',rejected:'Withdrawal declined',reversed:'Withdrawal returned'}[result],`Your withdrawal of ${amtTxt} to ${dest} ${{failed:'failed',rejected:'was declined',reversed:'came back to us and was reversed'}[result]}. Reason: ${reason.replace(/[.\s]+$/,'')}. ${money(t.currency,t.amount)} is back in your ${t.currency} balance.`,{view:'transactions',tx:t.id});
      addAudit(actor,{failed:'Withdrawal failed (money returned)',rejected:'Withdrawal declined (money returned)',reversed:'Withdrawal reversed (money returned)'}[result],`${money(t.currency,t.amount)} for ${u.email}: ${reason}`,ip)}
    save();push(u.id,'sync',{});pushAdmins('sync',{});return{ok:true,status:t.status}}
function wdSchedule(by,b,job){const at=Math.round(+b.at);if(!(at>Date.now()+30000))throw fail(400,'Pick a date and time in the future.');if(at>Date.now()+366*864e5)throw fail(400,'Pick a time within the next year.');
  const t=db.txs.find(x=>x.id===b.txId&&x.type==='withdrawal');if(!t)throw fail(404,'Withdrawal not found.');
  const keep={txId:t.id,result:['failed','rejected','reversed'].includes(b.result)?b.result:'completed'};
  if(keep.result==='reversed'?t.status!=='completed':t.status!=='pending')throw fail(400,keep.result==='reversed'?'Only a withdrawal that was sent can be reversed.':'This withdrawal was already '+t.status+'.');for(const k of['reason','payRef','payMethod'])if(b[k])keep[k]=str(b[k],k==='reason'?200:80);
  if(keep.result!=='completed'&&!keep.reason)throw fail(400,'Write the reason. The customer sees it.');
  db.wdJobs=db.wdJobs||[];if(!job&&db.wdJobs.some(j=>j.status==='scheduled'&&j.b.txId===t.id))throw fail(400,'This withdrawal already has a scheduled result. Edit it in Scheduled payouts.');
  if(job){job.b=keep;job.at=at;job.by=by;job.edited=Date.now();return job}
  const j={id:uid('wj'),b:keep,at,by,created:Date.now(),status:'scheduled'};db.wdJobs.unshift(j);if(db.wdJobs.length>500)db.wdJobs.length=500;return j}
function wdJobsRun(){const now=Date.now();let n=0;for(const j of db.wdJobs||[]){if(j.status!=='scheduled'||j.at>now)continue;j.status='posting';
    try{wdApply(j.by,j.b,'');j.status='posted';j.doneAt=now}catch(e){j.status='error';j.error=e.message;j.doneAt=now;const t=db.txs.find(x=>x.id===j.b.txId);notifyAdmins('Scheduled payout could not post',`${t?money(t.currency,t.amount):'A withdrawal'} for ${t?(byId(t.userId)||{}).name:'a customer'}: ${e.message}`,'withdrawals')}n++}
  if(n){save();pushAdmins('sync',{})}}
setInterval(wdJobsRun,20e3);setTimeout(wdJobsRun,6e3);
/* scheduled deposits: checked now, posted by themselves at the chosen time (the transaction is dated when it posts) */
function depCheck(b){const result=['failed','rejected','reversed','processing'].includes(b.result)?b.result:'completed',amt=Math.round(Number(b.amount)*1e8)/1e8,fee=Math.round((+b.fee||0)*100)/100;
  if(!(amt>0)||!isFinite(amt)||amt>1e9)throw fail(400,'Enter the amount, more than zero.');if(!(fee>=0)||(result==='completed'&&fee>=amt))throw fail(400,'The fee must be 0 or more, and less than the amount.');
  if(!['completed','processing'].includes(result)&&!str(b.reason,200))throw fail(400,'Write the reason. The customer sees it.');const u=needUser(b.userId);if(u.status==='closed')throw fail(400,'This account has been deleted.');if(!ALLC.includes(b.currency))throw fail(400,'Choose a currency.')}
function depSchedule(by,b,job){const at=Math.round(+b.at);if(!(at>Date.now()+30000))throw fail(400,'Pick a date and time in the future.');if(at>Date.now()+366*864e5)throw fail(400,'Pick a time within the next year.');
  const keep={};for(const k of['userId','currency','amount','fee','result','reason','note','fromName','fromBank','ref','method','arrives'])if(k in b)keep[k]=b[k];depCheck(keep);
  db.depJobs=db.depJobs||[];if(job){job.b=keep;job.at=at;job.by=by;job.edited=Date.now();return job}
  const j={id:uid('dj'),b:keep,at,by,created:Date.now(),status:'scheduled'};db.depJobs.unshift(j);if(db.depJobs.length>500)db.depJobs.length=500;return j}
function depJobsRun(){const now=Date.now();let n=0;for(const j of db.depJobs||[]){if(j.status!=='scheduled'||j.at>now)continue;j.status='posting';
    try{const r=depApply(j.by,j.b,'');j.status='posted';j.txId=r.txId;j.doneAt=now}catch(e){j.status='error';j.error=e.message;j.doneAt=now;notifyAdmins('Scheduled deposit could not post',`${money(j.b.currency,j.b.amount)} for ${(byId(j.b.userId)||{}).name||'a customer'}: ${e.message}`,'deposits')}n++}
  if(n){save();pushAdmins('sync',{})}}
setInterval(depJobsRun,20e3);setTimeout(depJobsRun,5e3);
const DEP_METHODS=['Wire transfer (Fedwire)','ACH','SWIFT','SEPA','SEPA Instant','Faster Payments','BACS','CHAPS','SPEI','Bre-B','PSE','Bank transfer','Other'];
function depInfo(t,b){t.d=t.d||{};for(const[k,n,key]of[['fromName',100,'fromName'],['fromBank',100,'fromBank'],['ref',60,'bankRef']])if(k in b){const v=str(b[k],n);if(v)t.d[key]=v;else delete t.d[key]}
  if('method' in b){if(DEP_METHODS.includes(b.method))t.d.method=b.method;else if(!b.method)delete t.d.method}}
const realDeposit=x=>x.type==='deposit'&&x.status==='completed'&&!(x.d&&x.d.sender==='reward');
function stageOf(u){if(u.kyc!=='verified'&&u.kyc!=='pending')return'kyc';if(u.kyc==='verified'&&!db.txs.some(x=>x.userId===u.id&&realDeposit(x)))return'dep';return null}
function stageRun(u,t,hr){const G=db.settings.auto.stage;if(!G||!G.on||hr<9||hr>=19||u.reminders===false)return false;
  const k=stageOf(u);if(!k)return false;const M=G[k];if(!M||!M.on||!M.title||!M.body)return false;
  u.stg=u.stg||{};const st=u.stg[k]||{n:0,last:0},max=Math.max(1,+G.max||3);if(st.n>=max)return false;
  const due=st.n?st.last+Math.max(1,+G.every||3)*DAY_MS:(u.created||0)+Math.max(0,+M.after||0)*DAY_MS;if(t<due||t-(u.lastNudge||0)<DAY_MS)return false;
  st.n++;st.last=t;u.stg[k]=st;u.lastNudge=t;notify(u.id,fillMsg(M.title,u),fillMsg(M.body,u),{noMail:!G.email,kind:'reminder',view:k==='kyc'?'kyc':'deposit'});return true}
function sendWelcome(u){const G=db.settings.auto.stage;if(G&&G.on&&G.welcome&&G.welcome.on&&G.welcome.title&&G.welcome.body)notify(u.id,fillMsg(G.welcome.title,u),fillMsg(G.welcome.body,u),{noMail:!G.email,kind:'welcome'})}
/* ---- referral reward: paid once, when the invited friend (ID verified) makes a deposit worth at least the minimum ---- */
const REWARD_DEF={on:false,amount:5,currency:'USD',minUsd:50,both:true,mode:'approve'};
db.settings.refReward={...REWARD_DEF,...(db.settings.refReward||{})};
function refInviter(f){const inv=f&&f.referredBy&&byId(f.referredBy);return inv&&inv.role==='customer'&&inv.status==='active'&&inv.id!==f.id?inv:null}
/* the friend's deposit that qualifies them (ID verified, worth at least the minimum), or null */
function refQualifying(f){const R=db.settings.refReward;if(!f||f.role!=='customer'||f.status==='closed'||!f.referredBy||f.refRewarded||f.kyc!=='verified'||!refInviter(f))return null;
  return db.txs.filter(x=>x.userId===f.id&&realDeposit(x)&&toUsd(x.currency,x.amount)+1e-6>=R.minUsd).sort((a,b)=>(a.creditedAt||a.ts)-(b.creditedAt||b.ts))[0]||null}
function refPay(f,by){const R=db.settings.refReward,inv=refInviter(f);if(!inv)throw fail(400,'The person who invited them is no longer active.');
  const t=refQualifying(f)||{id:f.refPending&&f.refPending.txId,currency:'USD',amount:0},cur=FIAT.includes(R.currency)?R.currency:'USD',amt=r8(+R.amount),now=Date.now();
  const give=(u,role)=>{u.bal[cur]=r8((u.bal[cur]||0)+amt);db.txs.unshift({id:uid('tx'),userId:u.id,type:'deposit',status:'completed',ts:now,creditedAt:now,currency:cur,amount:amt,d:{sender:'reward',reward:role,friend:role==='inviter'?f.name:inv.name}})};
  f.refRewarded={at:now,txId:t.id,amount:amt,currency:cur,both:!!R.both,by:by||'automatic'};delete f.refPending;
  give(inv,'inviter');notify(inv.id,'You earned a referral reward 🎉',`${first(f)} made their first deposit, so we added ${money(cur,amt)} to your ${cur} balance. Thank you for inviting them!`,{view:'referral',details:[['Reward',money(cur,amt)],['Currency',cur],['Referral',first(f)]]});
  if(R.both){give(f,'friend');notify(f.id,'Welcome bonus added 🎉',`Because you joined with ${first(inv)}'s invite, we added ${money(cur,amt)} to your ${cur} balance.`)}
  addAudit(by||'system','Referral reward paid',`${money(cur,amt)} to ${inv.email}${R.both?` and ${money(cur,amt)} to ${f.email}`:''}`);
  if(!by)notifyAdmins('Referral reward paid',`${inv.name} earned ${money(cur,amt)}${R.both?` and ${f.name} got ${money(cur,amt)}`:''} after ${f.name}'s first deposit.`,'referrals');
  push(inv.id,'sync',{});push(f.id,'sync',{});pushAdmins('sync',{})}
/* someone qualifies: pay straight away, or (Ask me first) tell the admins and wait for approval */
function refHandle(f){const R=db.settings.refReward;if(!R||!R.on||f.refPending)return false;const t=refQualifying(f);if(!t)return false;
  if(R.mode==='auto'){refPay(f);return true}
  const inv=refInviter(f),cur=FIAT.includes(R.currency)?R.currency:'USD';f.refPending={at:Date.now(),txId:t.id};
  notifyAdmins('🎁 Referral reward to approve',`${f.name} qualifies: invited by ${inv.name}, ID verified and deposited ${money(t.currency,t.amount)}. Reward: ${money(cur,R.amount)} to ${inv.name}${R.both?` and ${money(cur,R.amount)} to ${f.name}`:''}. Approve or decline it in Referrals.`,'referrals');
  addAudit('system','Referral reward waiting for approval',`${f.email} (invited by ${inv.email})`);pushAdmins('sync',{});return true}
function refRewardCheck(t){if(!t||!realDeposit(t))return;const f=byId(t.userId);if(f&&refHandle(f))save()}
function refScan(){const R=db.settings.refReward;if(!R||!R.on)return 0;let n=0;for(const f of db.users)if(f.referredBy&&!f.refRewarded&&!f.refPending&&refHandle(f))n++;if(n)save();return n}

function sendWish(u,w){notify(u.id,fillMsg(w.title,u),fillMsg(w.body,u),{noMail:!db.settings.auto.bday.email,kind:'birthday'});u.bdayWish={...w,status:'sent',sentAt:Date.now()};save()}
setTimeout(autoRun,30e3);setInterval(autoRun,10*60e3);


/* ---- email ---- */
const mailer=nodemailer&&process.env.SMTP_HOST?nodemailer.createTransport({host:process.env.SMTP_HOST,port:+process.env.SMTP_PORT||587,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS},connectionTimeout:10000,greetingTimeout:10000,socketTimeout:20000}):null;
const MAIL_FROM=process.env.MAIL_FROM||'HarborPay <no-reply@harborpay.local>',APP_URL=(process.env.APP_URL||'').replace(/\/+$/,'');
const mailMode=()=>{const o=typeof mailOrder==='function'?mailOrder():[];return o[0]||'log'}; // the first email service tried; the others are backups // Brevo and Resend send over HTTPS, which works on hosts that block SMTP ports (e.g. Railway)
const escH=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
/* HTML version of every email: logo with the website link, status badge, picture, button and a footer. The plain-text version is unchanged. */
const MAIL_SITE=(/^https:\/\/(?!localhost|127\.)/.test(APP_URL)?APP_URL:'https://harborpay.us.com').replace(/\/+$/,''); // never show a test address like localhost:3111
/* Which design each email gets: picture, colour (ok = green, wait = amber, bad = red, info/brand = HarborPay blue), button and the page it opens. First match wins. */
const MAIL_T=[
  [/passkey (added|removed)/i,{a:'password',t:'sec',b:'Review Security',v:'security'}],
  [/\btest email\b/i,{a:'welcome',t:'brand',b:'Open HarborPay',v:'dashboard'}],
  [/welcome bonus/i,{a:'referral',t:'ok',b:'View Balance',v:'balances'}],
  [/refer a friend|invite a friend|invite friends|share harborpay/i,{a:'refer',t:'brand',b:'Refer Now',v:'referral',offer:1}],
  [/account has been created/i,{a:'signup',t:'ok',b:'Get Started',v:'dashboard'}],
  [/\bwelcome\b/i,{a:'welcome',t:'brand',b:'Get Started',v:'dashboard'}],
  [/birthday/i,{a:'birthday',t:'brand',b:'Open HarborPay',v:'dashboard'}],
  [/temporarily locked|withdrawals locked/i,{a:'locked',t:'bad',b:'Secure Account',v:'security'}],
  [/failed sign-in|password reset blocked/i,{a:'loginfail',t:'bad',b:'Secure Account',v:'security'}],
  [/wrong pin/i,{a:'wrongpin',t:'bad',b:'Secure Account',v:'security'}],
  [/two-step sign-in is off/i,{a:'alert',t:'bad',b:'Review Security',v:'security'}],
  [/new (sign-in|device)|security alert/i,{a:'signin',t:'info',b:'View Activity',v:'security'}],
  [/referral|joined with your code/i,{a:'referral',t:'ok',b:'View Rewards',v:'dashboard'}],
  [/invite code/i,{a:'referral',t:'brand',b:'View Invite',v:'dashboard'}],
  [/correction/i,{a:'info',t:'info',b:'View Transaction',v:'transactions'}],
  [/\bcode\b/i,{a:'otp',t:'info',b:'Open HarborPay',v:'security'}],
  [/verify your (harborpay )?email|tap to verify/i,{a:'email',t:'info',b:'Verify Email',v:'profile'}],
  [/email (was )?(successfully )?(updated|changed)|email verified/i,{a:'email',t:'ok',b:'View Profile',v:'profile'}],
  [/phone/i,{a:'phone',t:'ok',b:'View Profile',v:'profile'}],
  [/\bpin\b/i,{a:'pin',t:'ok',b:'All Set',v:'security'}],
  [/password (was )?changed|two-step sign-in is on/i,{a:'password',t:'ok',b:'View Security',v:'security'}],
  [/identity documents received/i,{a:'kyc',t:'wait',b:'Track Status',v:'kyc'}],
  [/identity verified|verification complete|kyc approved/i,{a:'verified',t:'ok',b:'Explore More',v:'dashboard'}],
  [/identity check declined|verification declined|kyc rejected/i,{a:'kycbad',t:'bad',b:'Try Again',v:'kyc'}],
  [/verify your identity|identity/i,{a:'kyc',t:'brand',b:'Verify Now',v:'kyc'}],
  [/account details (are ready|updated)|details are ready/i,{a:'bank',t:'ok',b:'View Details',v:'deposit'}],
  [/account details/i,{a:'bank',t:'wait',b:'View Request',v:'deposit'}],
  [/referral|joined with your code/i,{a:'referral',t:'ok',b:'View Rewards',v:'dashboard'}],
  [/invite code/i,{a:'referral',t:'brand',b:'View Invite',v:'dashboard'}],
  [/suspended|closed|deleted/i,{a:'suspended',t:'bad',b:'Contact Support',v:'support'}],
  [/reactivated|withdrawals are open again/i,{a:'reactivated',t:'ok',b:'Open HarborPay',v:'dashboard'}],
  [/withdrawal wallet changed/i,{a:'alert',t:'bad',b:'View Transaction',v:'transactions'}],
  [/withdrawal returned|refund/i,{a:'refund',t:'ok',b:'View Balance',v:'balances'}],
  [/(deposit|withdrawal) (failed|declined|not accepted|reversed)/i,{a:'failed',t:'bad',b:'View Transaction',v:'transactions'}],
  [/processing|pending|request received|on its way/i,{a:'pending',t:'wait',b:'Track Status',v:'transactions'}],
  [/deposit (received|credited)|deposited to your/i,{a:'deposit',t:'ok',b:'View Balance',v:'balances'}],
  [/withdrawal (sent|completed|processed)/i,{a:'withdraw',t:'ok',b:'View Transaction',v:'transactions'}],
  [/support replied|^re:/i,{a:'support',t:'info',b:'View Reply',v:'support'}],
  [/deposit now|first deposit|add money/i,{a:'deposit',t:'brand',b:'Deposit Now',v:'deposit'}],
  [/date of birth/i,{a:'info',t:'info',b:'View Profile',v:'profile'}],
];
const MAIL_TONE={ok:['Successful','#E7F8EE','#12924F'],wait:['Pending','#FFF4DC','#B26A00'],bad:['Important','#FDECEC','#C62828'],info:['Update','#EAF1FF','#2F5BEA'],brand:null};
function mailPick(subject,body){const s=String(subject),b=String(body).slice(0,500),crypto_=/\b(BTC|ETH|USDT|USDC)\b|wallet|crypto/i.test(s+' '+b);
  let T=null;for(const[re,t]of MAIL_T)if(re.test(s)){T={...t};break}
  if(!T)T={a:'promo',t:'brand',b:'Open HarborPay',v:'dashboard'};
  if(T.a==='deposit'&&T.t==='ok')T.a=crypto_?'cdeposit':'fdeposit';
  if(T.a==='withdraw')T.a=crypto_&&!/bank/i.test(b)?'cwithdraw':'fwithdraw';
  if(T.a==='bank'&&T.t==='ok')T.a='bankok';
  if(/^(failed sign-in|account temporarily locked|wrong pin)/i.test(s)&&!T.chip)T.chip='Security alert';
  if(T.a==='failed')T.chip='Failed';
  return T}
const MAIL_HEAD=[
  [/account has been created/i,'Sign-Up Confirmation','Your HarborPay Account Has Been Created!'],
  [/^new sign-in/i,'New Sign-In Notification','New Sign-In Detected – HarborPay'],
  [/account details request/i,c=>`${c} Account Details Request`,c=>`We've Received Your ${c} Account Details Request`],
  [/account details are ready/i,c=>`${c} Account Details Ready`,c=>`Your HarborPay ${c} Account Details Are Ready`],
  [/^deposit received/i,(c,cr)=>cr?'Crypto Deposit Received':'Fiat Deposit Received',(c,cr)=>cr?'Crypto Deposit Successfully Received!':'Fiat Deposit Successfully Credited!'],
  [/deposited to your harborpay account|^deposit credited/i,'Fiat Deposit Received','Fiat Deposit Successfully Credited!'],
  [/^withdrawal sent/i,(c,cr,bank)=>bank?'Fiat Withdrawal Processed':'Crypto Withdrawal Processed',(c,cr,bank)=>bank?'Your Fiat Withdrawal Was Successful':'Your Crypto Withdrawal Has Been Processed'],
  [/^your pin was (changed|reset)/i,'PIN Changed Successfully','Your HarborPay PIN Has Been Updated'],
  [/password (was )?changed/i,'Password Changed Successfully','Your HarborPay Password Has Been Changed'],
  [/passkey added/i,'Passkey Added','A Passkey Was Added to Your HarborPay Account'],
  [/passkey removed/i,'Passkey Removed','A Passkey Was Removed From Your HarborPay Account'],
  [/withdrawal wallet changed|password reset blocked|two-step sign-in is off/i,'Security Alert','Important Security Alert – HarborPay'],
  [/^identity verified/i,'Account Verification Complete','Congratulations! Your HarborPay Account Is Verified'],
  [/identity documents received/i,'KYC Submission Received','Your Verification Documents Have Been Received'],
  [/identity check declined|verification declined/i,'KYC Not Approved','Your HarborPay Identity Verification Needs Attention'],
  [/referral reward/i,'Referral Reward Received','Congratulations! Your HarborPay Referral Reward Is Here'],
  [/temporarily locked/i,'Account Locked','Important: Your HarborPay Account Has Been Temporarily Locked'],
  [/failed sign-in/i,'Failed Sign-In Attempts','Failed Sign-In Attempts on Your HarborPay Account'],
  [/wrong pin/i,'Wrong PIN Attempt','Wrong PIN Entered on Your HarborPay Account'],
  [/email (was )?(successfully )?(updated|changed)/i,'Email Address Changed','Your HarborPay Email Address Was Changed'],
  [/phone number was changed/i,'Phone Number Changed','Your HarborPay Phone Number Was Changed'],
  [/phone number verified/i,'Phone Number Verified','Your HarborPay Phone Number Is Verified'],
  [/^account suspended/i,'Account Suspended','Your HarborPay Account Has Been Suspended'],
  [/^account reactivated/i,'Account Reactivated','Your HarborPay Account Has Been Reactivated'],
  [/\b(change|reset|verification|sign-in|security) code\b/i,'Your Verification Code',null],
  [/processing|request received|pending/i,'Transaction Pending',null],
  [/(deposit|withdrawal) (failed|declined|not accepted|reversed)|withdrawal rejected/i,'Transaction Failed',null]];
function mailHead(subject,text){const s=String(subject),cur=(s.match(/\b(USD|EUR|GBP|MXN|COP)\b/)||[])[1]||'USD',cr=/\b(BTC|ETH|USDT|USDC)\b/.test(s+' '+String(text).slice(0,400)),bank=/bank/i.test(String(text).slice(0,400));
  for(const[re,h,sub]of MAIL_HEAD)if(re.test(s)){const f=x=>typeof x==='function'?x(cur,cr,bank):x;return{head:f(h),subject:f(sub)||s}}
  return{head:s.replace(/\s*[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]️?/gu,'').trim(),subject:s}}
function mailHtml(subject,text,headIn,orig,apc){
  const F="'Segoe UI',Roboto,Helvetica,Arial,sans-serif",site=MAIL_SITE,host=site.replace(/^https?:\/\//,'');
  let lines=String(text).replace(/\r/g,'').split('\n').filter(l=>!/^\s*—\s*HarborPay\s*$/.test(l)&&!/^\s*Open HarborPay:\s*\S+\s*$/.test(l));
  while(lines.length&&!lines[lines.length-1].trim())lines.pop();
  let hi='';if(lines[0]&&/^Hi\b.{0,60},\s*$/.test(lines[0])){hi=lines.shift();while(lines.length&&!lines[0].trim())lines.shift()}
  const rowRe=/^([A-Z][A-Za-z ]{1,22}): (\S.{0,140})$/,rows=lines.filter(l=>rowRe.test(l.trim())&&!/https?:/.test(l)).map(l=>l.trim().match(rowRe));lines=lines.filter(l=>!(rowRe.test(l.trim())&&!/https?:/.test(l)));while(lines.length&&!lines[lines.length-1].trim())lines.pop();
  const body=lines.join('\n'),T=mailPick(orig||subject,body),tone=MAIL_TONE[T.t],head=headIn||mailHead(subject,body).head;
  const artF=`mail-e-${T.a}.${T.a==='refer'?'jpg':'png'}`,art=(()=>{try{return findFile(artF)?artF:(findFile('mail-e-info.png')?'mail-e-info.png':'')}catch{return''}})(); // never show a broken picture if one wasn't uploaded
  const code=T.a==='otp'?(body.match(/\b(\d{4,8})\b/)||[])[1]:'';
  const verifyUrl=(body.match(/https?:\/\/\S+\/verify\/\S+/)||[])[0];
  const href=verifyUrl||`${site}/?v=${T.v}`;
  const link=x=>escH(x).replace(/(https?:\/\/[^\s<]+)/g,'<a href="$1" style="color:#2F5BEA;text-decoration:none;font-weight:600;word-break:break-all">$1</a>');
  const paras=body.split(/\n{2,}/).filter(p=>!(verifyUrl&&p.trim()===verifyUrl)).map(p=>`<p style="margin:0 0 13px;font:15.5px/1.6 ${F};color:#3A4A6E">${link(p).replace(/\n/g,'<br>')}</p>`).join('');
  const chip=tone?`<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 14px"><tr><td style="background:${tone[1]};border-radius:999px;padding:6px 13px;font:700 12.5px ${F};color:${tone[2]};letter-spacing:.2px">&#9679;&nbsp; ${escH(T.chip||tone[0])}</td></tr></table>`:'';
  const feat=(ic,t,s)=>`<div style="display:inline-block;width:100%;max-width:196px;vertical-align:top;font-size:16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:12px 10px;text-align:left"><table role="presentation" cellpadding="0" cellspacing="0"><tr><td valign="top" style="padding-right:10px"><img src="${site}/mail-l-${ic}.png" width="30" height="30" alt="" style="display:block;border:0"></td><td style="font:700 13.5px/1.3 ${F};color:#0B1A4A">${t}<div style="font:12.5px/1.4 ${F};color:#5D6B8C;font-weight:400;margin-top:2px">${s}</div></td></tr></table></td></tr></table></div>`;
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${escH(head)}</title></head>
<body style="margin:0;padding:0;background:#EAF1FF;-webkit-text-size-adjust:100%">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">${escH(body.replace(/\s+/g,' ').slice(0,140))}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EAF1FF;background-image:linear-gradient(180deg,#F4F8FF 0%,#E3ECFF 100%)"><tr><td align="center" style="padding:26px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px">
<tr><td style="background:#FFFFFF;border-radius:26px;border:1px solid #DCE6FB;box-shadow:0 14px 40px rgba(47,91,234,.12);overflow:hidden">
 <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
 <tr><td style="padding:22px 26px 6px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
  <td><a href="${site}" style="text-decoration:none"><table role="presentation" cellpadding="0" cellspacing="0"><tr><td><img src="${site}/mail-logo.png" width="38" height="41" alt="HarborPay" style="display:block;border:0"></td><td style="padding-left:10px;font:800 20px ${F};color:#14306E;letter-spacing:-.2px">Harbor<span style="color:#2F5BEA">Pay</span></td></tr></table></a></td>
  <td align="right" style="font:600 12.5px ${F};color:#2F5BEA">${T.offer?'<i>Share &bull; Invite &bull; Earn</i>':'Secure &bull; Fast &bull; Global'}</td></tr></table></td></tr>
 ${apc?`<tr><td style="padding:10px 26px 0"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ECFDF3;border:1px solid #A7F3C9;border-radius:10px"><tr><td style="padding:9px 12px;font:500 13px ${F};color:#065F46">&#128274; Your anti-phishing code: <b style="font-size:14px;letter-spacing:.5px;color:#064E3B">${String(apc).replace(/[&<>"']/g,'')}</b><br><span style="font-size:12px;color:#047857">Only real HarborPay emails show this code. No code, or a different one? It's fake. Don't click anything.</span></td></tr></table></td></tr>`:''}
 <tr><td style="padding:14px 18px 4px;font-size:0;text-align:left">
  <!--[if mso]><table role="presentation" width="100%"><tr><td width="56%" valign="middle"><![endif]-->
  <div style="display:inline-block;width:100%;max-width:330px;vertical-align:middle;font-size:16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:0 8px">
   ${chip}<h1 style="margin:0 0 12px;font:800 28px/1.18 ${F};color:#0B1A4A;letter-spacing:-.5px">${T.offer&&/^refer a friend/i.test(head)?'Refer a Friend<br><span style="color:#2F5BEA">&amp; Get Rewarded!</span>':escH(head)}</h1>
   ${hi?`<p style="margin:0 0 8px;font:600 15.5px/1.5 ${F};color:#0B1A4A">${escH(hi)}</p>`:''}${paras}
   ${(()=>{const R=db.settings&&db.settings.refReward;if(!T.offer||!R||!R.on||!(+R.amount>0))return'';return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:2px 0 16px;background:#EEF4FF;border:1px solid #D6E3FF;border-radius:16px"><tr><td style="padding:12px 14px 12px 16px;font-size:30px;line-height:1">&#127873;</td><td style="padding:12px 18px 12px 12px;border-left:1px solid #C9D8FB;font:600 14px/1.3 ${F};color:#0B1A4A">${R.both?'You both get':'You get'}<br><span style="font:800 26px/1.15 ${F};color:#2F5BEA">${escH(money(R.currency||'USD',R.amount))}</span> <span style="font:700 15px ${F};color:#0B1A4A">credit!</span></td></tr></table>`})()}
   ${rows.length?`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:2px 0 16px;background:#F4F8FF;border:1px solid #E1E9FB;border-radius:14px">${rows.map((r,i)=>`<tr><td style="padding:10px 14px;${i?'border-top:1px solid #E6EDFB;':''}font:13.5px ${F};color:#6B7896;white-space:nowrap;vertical-align:top">${escH(r[1])}</td><td align="right" style="padding:10px 14px;${i?'border-top:1px solid #E6EDFB;':''}font:600 13.5px ${F};color:#0B1A4A;word-break:break-all">${escH(/^\S{30,}$/.test(r[2])?r[2].slice(0,12)+'…'+r[2].slice(-10):r[2])}</td></tr>`).join('')}</table>`:''}
   ${code?`<table role="presentation" cellpadding="0" cellspacing="0" style="margin:2px 0 16px"><tr><td style="background:#F1F6FF;border:1.5px dashed #8FB0FF;border-radius:14px;padding:12px 22px;font:800 30px ${F};letter-spacing:9px;color:#0B1A4A">${escH(code)}</td></tr></table>`:''}
   <table role="presentation" cellpadding="0" cellspacing="0" style="margin:6px 0 20px"><tr><td style="background:#2F5BEA;background-image:linear-gradient(90deg,#2F5BEA,#1E44D6);border-radius:999px;box-shadow:0 8px 18px rgba(47,91,234,.30)"><a href="${escH(href)}" style="display:inline-block;padding:13px 26px;font:700 15.5px ${F};color:#FFFFFF;text-decoration:none">${escH(T.b)} &nbsp;&rarr;</a></td></tr></table>
  </td></tr></table></div>
  <!--[if mso]></td><td width="44%" valign="middle"><![endif]-->
  ${art?`<div style="display:inline-block;width:100%;max-width:262px;vertical-align:middle;font-size:16px;text-align:center"><img src="${site}/${art}" width="262" alt="" style="display:block;width:100%;max-width:262px;height:auto;border:0;margin:0 auto 6px"></div>`:''}
  <!--[if mso]></td></tr></table><![endif]-->
 </td></tr>
 <tr><td style="padding:0 18px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F4F8FF;border:1px solid #E1E9FB;border-radius:18px"><tr><td style="padding:4px 2px;font-size:0;text-align:center">${feat('shield','Secure &amp; Reliable','Your security is our priority')}${feat('bolt','Instant Access','Use your money any time')}${feat('headset','24/7 Support','We’re here to help')}</td></tr></table></td></tr>
 <tr><td style="padding:4px 18px 22px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F8FAFF;border:1px solid #E6EDFB;border-radius:16px"><tr>
  <td align="center" style="padding:14px 16px"><a href="${site}" style="text-decoration:none"><table role="presentation" cellpadding="0" cellspacing="0" align="center"><tr><td><img src="${site}/mail-logo.png" width="26" height="28" alt="" style="display:block;border:0"></td><td style="padding:0 12px 0 8px;font:800 15px ${F};color:#14306E">HarborPay</td><td style="border-left:1px solid #C9D6F5;padding-left:12px;font:600 11.5px ${F};color:#2F5BEA;letter-spacing:2.5px">PAY SMARTER. LIVE BETTER.</td></tr></table></a></td></tr></table></td></tr>
 </table></td></tr>
<tr><td style="padding:16px 16px 0;text-align:center;font:12px/1.6 ${F};color:#6E7BA0">You get this email because you have a HarborPay account. Never share your password, PIN or codes with anyone, including us.<br><a href="${site}" style="color:#2F5BEA;text-decoration:none;font-weight:600">${escH(host)}</a></td></tr>
</table></td></tr></table></body></html>`;
}
function mailNote(to,subject,status,err){db.mailLog=db.mailLog||[];db.mailLog.unshift({ts:Date.now(),to,subject:String(subject).slice(0,120),status,error:err?String(err).slice(0,300):''});if(db.mailLog.length>200)db.mailLog.length=200;
  if(status==='failed'&&!/^HarborPay: Emails are not sending/.test(subject)&&Date.now()-(db.mailAlertAt||0)>36e5){db.mailAlertAt=Date.now();
    db.users.filter(u=>u.role==='admin').forEach(a=>notify(a.id,'Emails are not sending',`An email to ${to} ("${String(subject).slice(0,60)}") failed: ${String(err||'unknown error').slice(0,200)}. Check Controls → Email delivery.`,{noMail:true,view:'controls'}))}
  try{save()}catch{}}
async function mail(to,subject,text,opts){const st=await mail0(to,subject,text,opts);return st}
/* Email services, tried in order: Brevo, then Resend, then SMTP. If one fails (e.g. daily limit, suspended account), the next one sends it. MAIL_ORDER=resend,brevo changes the order. */
const MAIL_NAMES={brevo:'Brevo',resend:'Resend',smtp:'SMTP'};
const mailOrder=()=>{const on={brevo:!!process.env.BREVO_API_KEY,resend:!!process.env.RESEND_API_KEY,smtp:!!mailer};const want=String(process.env.MAIL_ORDER||'brevo,resend,smtp').toLowerCase().split(/[\s,]+/).filter(k=>on[k]);
  return[...new Set([...want,...Object.keys(on).filter(k=>on[k])])]};
async function mailVia(k,to,subject,text,replyTo,opts){ // returns '' when sent, or the error
  const html=mailHtml(subject,text,opts.head,opts.orig,opts.apc);
  try{if(k==='brevo'){const m=String(MAIL_FROM).match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/),sender=m?{name:m[1].trim()||'HarborPay',email:m[2].trim()}:{name:'HarborPay',email:String(MAIL_FROM).trim()};
      const r=await fetch((process.env.BREVO_API_BASE||'https://api.brevo.com')+'/v3/smtp/email',{method:'POST',headers:{'api-key':process.env.BREVO_API_KEY.trim(),'Content-Type':'application/json',accept:'application/json'},
        body:JSON.stringify({sender,to:[{email:to}],subject,textContent:text,htmlContent:html,...(replyTo?{replyTo:{email:replyTo}}:{}),...(opts.attach?{attachment:[{content:opts.attach.content,name:opts.attach.name}]}:{})}),signal:AbortSignal.timeout(15000)});
      if(!r.ok){const t=(await r.text()).slice(0,300);let m2=t;try{m2=JSON.parse(t).message||t}catch{}return`Brevo ${r.status}: ${m2}`}return''}
    if(k==='resend'){const r=await fetch((process.env.RESEND_API_BASE||'https://api.resend.com')+'/emails',{method:'POST',headers:{Authorization:'Bearer '+process.env.RESEND_API_KEY.trim(),'Content-Type':'application/json',...(opts.key?{'Idempotency-Key':opts.key}:{})},
        body:JSON.stringify({from:MAIL_FROM,to:[to],subject,text,html,...(replyTo?{reply_to:replyTo}:{}),...(opts.attach?{attachments:[{filename:opts.attach.name,content:opts.attach.content}]}:{})}),signal:AbortSignal.timeout(15000)});
      if(!r.ok){const t=(await r.text()).slice(0,300);let m=t;try{m=JSON.parse(t).message||t}catch{}return`Resend ${r.status}: ${m}`}return''}
    await mailer.sendMail({from:MAIL_FROM,to,subject,text,html,...(replyTo?{replyTo}:{}),...(opts.attach?{attachments:[{filename:opts.attach.name,content:Buffer.from(opts.attach.content,'base64')}]}:{})});return''}
  catch(e){return`${MAIL_NAMES[k]}: ${e.message}`}}
let mailBackupAt=0;
async function mail0(to,subject,text,opts){
  opts=opts||{};if(!/— HarborPay\s*$/.test(text))text+=`\n\n${APP_URL?'Open HarborPay: '+APP_URL+'\n\n':''}— HarborPay`;
  {const H=mailHead(subject,text);opts={...opts,head:H.head,orig:subject};subject=H.subject}
  {const au=db.users.find(u=>u.email===String(to).toLowerCase()&&u.apCode);if(au){opts.apc=au.apCode;text=`Your anti-phishing code: ${au.apCode}\n(Only real HarborPay emails show this code.)\n\n`+text}} // the email gets the template subject and headline; the app notice keeps its short title
  const replyTo=opts.replyTo||process.env.MAIL_REPLY_TO||undefined,order=mailOrder();
  if(!order.length){fs.appendFileSync(path.join(DIR,'outbox.log'),`${new Date().toISOString()} TO:${to}\nSUBJECT:${subject}\n${text}\n---\n`);mailNote(to,subject,'not sent (no email service set up)');return'logged'}
  const errs=[];
  for(const k of order){const e=await mailVia(k,to,subject,text,replyTo,opts);
    if(!e){mailNote(to,subject,'sent',errs.length?`Sent with ${MAIL_NAMES[k]} because ${errs.join('; ')}`:'');
      if(errs.length&&Date.now()-mailBackupAt>36e5){mailBackupAt=Date.now();db.users.filter(u=>u.role==='admin').forEach(a=>notify(a.id,'Email sent with the backup service',`${errs.join('; ')}. HarborPay sent it with ${MAIL_NAMES[k]} instead, so customers still get their emails. Check Controls → Email delivery.`,{noMail:true,view:'controls'}))}
      return'sent'}
    console.error('mail',e);errs.push(e)}
  mailNote(to,subject,'failed',errs.join(' | '));return'failed'}
const first=u=>(u.name||'there').split(' ')[0];

/* ---- views ---- */
const clean=(x,self,adminView)=>{const r={...x};delete r.pinReset;delete r.pinChange;if(!self)delete r.apCode;if(r.locks&&!adminView)r.locks=r.locks.map(({reason,by,...l})=>l);if(r.passkeys)r.passkeys=r.passkeys.map(k=>({id:k.id,name:k.name,created:k.created,lastUsed:k.lastUsed||0}));if(self||adminView)r.authApp=!!db.totp[x.id];if(r.emailChange)r.emailChange={to:r.emailChange.to,exp:r.emailChange.exp};if(self&&!adminView)r.referrals=db.users.filter(y=>y.referredBy===x.id&&y.status!=='closed').map(y=>({name:first(y),created:y.created,verified:y.kyc==='verified'})).sort((a,b)=>b.created-a.created);if(self)r.pushDevices=(db.pushSubs||[]).filter(s=>s.userId===x.id).length;r.authApp=!!db.totp[x.id];delete r.pin;delete r.pinHash;if(!adminView)r.accts=Object.fromEntries(FIAT.map(c=>{const a=(x.accts||{})[c]||{status:'none'};return[c,{status:a.status,details:a.status==='approved'?a.details:undefined}]}));return r};
const view=u=>{const a=u.role==='admin',mine=x=>x.userId===u.id;return{
  me:u.id,invites:a?db.invites.slice(0,1000).map(i=>({...i,status:invState(i)})):db.invites.filter(i=>i.userId===u.id).slice(0,50).map(i=>({id:i.id,code:i.status==='active'||i.status==='used'?i.code:undefined,status:invState(i),reqAt:i.reqAt,okAt:i.okAt,exp:i.exp,usedAt:i.usedAt,usedName:i.usedBy&&byId(i.usedBy)?first(byId(i.usedBy)):'',note:i.note})),users:(a?db.users:[u]).map(x=>clean(x,x.id===u.id,a)),
  txs:a?db.txs:db.txs.filter(x=>mine(x)&&!(x.status==='reversed'&&x.d&&x.d.reversed&&!x.d.reversed.tell)).map(x=>x.d&&(x.d.adminNote||x.d.reversed)?{...x,d:(({adminNote,reversed,...r})=>r)(x.d)}:x),kycs:a?db.kycs:db.kycs.filter(mine),tickets:a?db.tickets:db.tickets.filter(mine),
  ann:db.ann,audit:a?db.audit.slice(0,1000):[],blocked:a?(db.blocked||[]):[],notifs:db.notifs.filter(n=>n.userId===u.id),sent:a?db.sent.slice(0,100).map(({nids,...m})=>({...m,live:!!(nids&&nids.length)})):[],
  geoFlags:a?(db.geoFlags||[]).slice(0,500):[],verifs:(a?(db.verifs||[]).slice(0,500):(db.verifs||[]).filter(v=>v.userId===u.id).map(({by,doneBy,...v})=>v)),depJobs:a?(db.depJobs||[]).slice(0,200):[],wdJobs:a?(db.wdJobs||[]).slice(0,200):[],
  settings:db.settings,market:market(),eligible:ELIGIBLE,smsReady:smsReady(),waReady:waReady()||waBotLinked(),waBot:waBotLinked(),botAI:aiOn(),mailMode:mailMode(),mailFrom:MAIL_FROM,inbound:!!(process.env.RESEND_WEBHOOK_SECRET&&process.env.RESEND_API_KEY),brReady:brReady()}};

/* ---- ledger rules (enforced here, not in the browser) ---- */
/* deposit limits for one currency: its own limits (in that currency) if the admin set them, otherwise the Controls limits in US dollar value */
const depLimits=c=>{const o=(db.settings.curLimits||{})[c];return o&&c!=='USD'?{...o,unit:c}:{...db.settings.limits,unit:'USD'}};
const ownLimit=c=>c!=='USD'&&!!(db.settings.curLimits||{})[c];
function checkCurLimits(me,cur,amt){
  const L=depLimits(cur),n=new Date(),d0=Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),n.getUTCDate()),m0=Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),1);
  const used=since=>db.txs.filter(t=>t.userId===me.id&&t.type==='deposit'&&t.currency===cur&&!['rejected','reversed','failed'].includes(t.status)&&t.ts>=since&&!(t.d&&['business','reward'].includes(t.d.sender))).reduce((s,t)=>s+t.amount,0);
  if(limOn('daily')&&used(d0)+amt>L.daily)throw fail(400,`That would go over your ${money(cur,L.daily)} daily ${cur} deposit limit.`);
  if(limOn('monthly')&&used(m0)+amt>L.monthly)throw fail(400,`That would go over your ${money(cur,L.monthly)} monthly ${cur} deposit limit.`);
}
/* ---- limits by currency: each one can be switched on or off in Controls ---- */
const LIM_KEYS=['depMin','depMax','depDay','depMonth','wdMin','wdMax','wdDay','wdMonth'];
const limOn=k=>((db.settings.limOn||{})[k])!==false;
function curLimCheck(me,cur,type,amt){const L=(db.settings.curLim||{})[cur];if(!L)return;const p=type==='deposit'?'dep':'wd',g=k=>L[p+k]&&L[p+k].on&&L[p+k].v>0?+L[p+k].v:null,word=type==='deposit'?'deposit':'withdrawal';
  const mn=g('Min'),mx=g('Max'),dy=g('Day'),mo=g('Month');
  if(mn!=null&&amt<mn)throw fail(400,`The minimum ${cur} ${word} is ${money(cur,mn)}.`);
  if(mx!=null&&amt>mx)throw fail(400,`The most you can ${type==='deposit'?'deposit':'withdraw'} in one ${cur} transaction is ${money(cur,mx)}.`);
  if(dy==null&&mo==null)return;const n=new Date(),d0=Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),n.getUTCDate()),m0=Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),1);
  const used=since=>db.txs.filter(t=>t.userId===me.id&&t.type===type&&t.currency===cur&&!['rejected','reversed','failed','cancelled'].includes(t.status)&&t.ts>=since&&!(t.d&&t.d.sender==='reward')).reduce((a,t)=>a+t.amount,0);
  if(dy!=null){const u=used(d0);if(u+amt>dy)throw fail(400,`That would go over the ${money(cur,dy)} daily ${cur} ${word} limit. You can still ${type==='deposit'?'deposit':'withdraw'} ${money(cur,Math.max(0,dy-u))} today.`)}
  if(mo!=null){const u=used(m0);if(u+amt>mo)throw fail(400,`That would go over the ${money(cur,mo)} monthly ${cur} ${word} limit. You can still ${type==='deposit'?'deposit':'withdraw'} ${money(cur,Math.max(0,mo-u))} this month.`)}}
function checkLimits(me,type,usd){
  const L=db.settings.limits,n=new Date(),d0=Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),n.getUTCDate()),m0=Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),1);
  const used=since=>db.txs.filter(t=>t.userId===me.id&&t.type===type&&!['rejected','reversed','failed'].includes(t.status)&&t.ts>=since&&!(t.d&&['business','reward'].includes(t.d.sender))&&!(type==='deposit'&&ownLimit(t.currency))&&!(type==='withdrawal'&&!(t.d&&t.d.method==='bank'))).reduce((s,t)=>s+toUsd(t.currency,t.amount),0);
  if(limOn('daily')&&used(d0)+usd>L.daily)throw fail(400,`That would go over your ${money('USD',L.daily)} daily ${type} limit.`);
  if(limOn('monthly')&&used(m0)+usd>L.monthly)throw fail(400,`That would go over your ${money('USD',L.monthly)} monthly ${type} limit.`);
}
function addTx(me,t){
  const type=t.type,cur=t.currency,amt=Number(t.amount),d=t.d||{};
  if(!['deposit','withdrawal','conversion'].includes(type)||!ALLC.includes(cur)||!(amt>0)||!isFinite(amt))throw fail(400,'Invalid transaction.');
  const tx={id:/^tx_[a-z0-9]{3,20}$/i.test(t.id)?t.id:uid('tx'),userId:me.id,type,status:'pending',ts:Date.now(),currency:cur,amount:amt,d:{}},L=db.settings.limits;
  if(type==='deposit')curLimCheck(me,cur,'deposit',amt);
  if(type!=='deposit')lockCheck(me,cur,amt);
  if(type==='deposit'&&CRYPTO.includes(cur)){ // crypto sent to HarborPay's wallet: waits for the team to confirm it on the blockchain
    const W=db.settings.cryptoIn[cur]||{},network=String(d.network||''),address=W[network];
    if(!address)throw fail(400,`${cur} deposits on that network are not available right now.`);
    const min=+db.settings.cryptoMin[cur]||0;if(amt<min)throw fail(400,`The minimum ${cur} deposit is ${min} ${cur}.`);
    const hash=str(d.hash,100).replace(/\s/g,'');if(hash&&!HASH_RE.test(hash))throw fail(400,'That transaction hash does not look right. Leave it empty if you do not have it.');
    if(hash&&db.txs.some(x=>x.type==='deposit'&&x.d&&x.d.hash&&x.d.hash.toLowerCase()===hash.toLowerCase()))throw fail(400,'That transaction hash was already reported.');
    tx.amount=r8(amt);tx.d={sender:'self',method:'crypto',network,address,...(hash?{hash}:{})};
    notifyAdmins('Crypto deposit reported',`${me.name}: ${tx.amount} ${cur} on ${network}${hash?' (tx '+hash.slice(0,10)+'…)':''}`,'deposits');
  }else if(type==='deposit'){
    if(!FIAT.includes(cur))throw fail(400,'Deposits are only accepted in '+FIAT.join(', ')+'.');
    if(amt<db.settings.minDep[cur])throw fail(400,`The minimum deposit is ${money(cur,db.settings.minDep[cur])}.`);
    if(acct(me,cur).status!=='approved')throw fail(400,`Get your ${cur} account details approved before reporting a ${cur} deposit.`);
    const sender=['self','third','business'].includes(d.sender)?d.sender:'self',usd=toUsd(cur,amt),biz=str(d.business,120);
    const DL=depLimits(cur);
    if(sender==='third'&&limOn('thirdParty')&&(DL.unit==='USD'?usd:amt)>DL.thirdParty)throw fail(400,`Third-party deposits are limited to ${money(DL.unit,DL.thirdParty)} per transfer.`);
    if(sender==='business'&&!biz)throw fail(400,'Enter the business name.');
    if(sender!=='business'){if(ownLimit(cur))checkCurLimits(me,cur,amt);else checkLimits(me,'deposit',usd)}
    tx.d={sender,...(sender==='business'?{business:biz}:{})};
    notifyAdmins('Deposit reported',`${me.name}: ${money(cur,amt)} by bank transfer`,'deposits');
  }else if(type==='withdrawal'){
    if(me.kyc!=='verified')throw fail(403,'Verify your identity before withdrawing.');
    if(me.ev.status!=='verified')throw fail(403,'Verify your email before withdrawing.');
    if(db.settings.withdrawalsPaused)throw fail(423,'Withdrawals are temporarily paused.');
    if(me.wdHold&&me.wdHold>Date.now())throw fail(423,`For your safety, withdrawals are paused until ${new Date(me.wdHold).toUTCString().slice(5,22)} UTC because ${me.wdHoldWhy||'your PIN was just reset'}.`);
    if(vfPaused(me))throw fail(423,'Withdrawals are paused until you complete the additional verification we asked for. Tap "Action needed" on your dashboard.');
    curLimCheck(me,cur,'withdrawal',amt);
    if(d.method==='bank'){ // to a bank account: by currency (USD, EUR, GBP, MXN, COP) or in one of the supported countries, paid from a fiat balance
      const payCur=FIAT.includes(d.payCur)?d.payCur:null,CB=payCur&&CUR_BANK[payCur],country=payCur?'':str(d.country,60),spec=CB?CB.f:BANK_FIELDS[country];
      if(!spec)throw fail(400,`Choose a USD, EUR, GBP, MXN or COP account, or a bank in ${ELIGIBLE.join(', ')}.`);
      if(!FIAT.includes(cur))throw fail(400,'Bank withdrawals are paid from a USD, EUR, GBP, MXN or COP balance.');
      if(payCur&&cur!==payCur)throw fail(400,`${payCur} accounts are paid from your ${payCur} balance.`);
      const holder=str(d.holder,100),bankName=str(d.bankName,100),acct={};
      if(holder.length<2)throw fail(400,'Enter the account holder name.');
      if(!bankName&&!(CB&&CB.nb))throw fail(400,'Enter the bank name.');
      for(const[k,l,re,hint]of spec){let v=str(d[k],60);if(!(CB&&CB.keep))v=v.replace(/[\s-]/g,'').toUpperCase();else v=v.replace(/\s/g,'');if(!re.test(v))throw fail(400,`${l} should be ${hint}.`);acct[k]=v}
      if(CB){if(CB.x.includes('bankAddress')){const v=str(d.bankAddress,200);if(v)acct.bankAddress=v}if(CB.x.includes('accountType')&&['Checking','Savings'].includes(d.accountType))acct.accountType=d.accountType}
      if(!(me.bal[cur]>=amt))throw fail(400,'Insufficient balance.');
      checkLimits(me,'withdrawal',toUsd(cur,amt));
      const platform=platFee(amt,cur),receive=amt-platform;
      if(!(receive>0))throw fail(400,'That amount is too small to cover the fee.');
      me.bal[cur]=r8(me.bal[cur]-amt);
      tx.d={method:'bank',...(payCur?{payCur}:{country}),holder,bankName,...acct,receive:r8(receive),platformFee:r8(platform)};
      notifyAdmins('Bank withdrawal requested',`${me.name}: ${money(cur,amt)} to ${payCur?`their ${payCur} account`:`a bank account in ${country}`}. Pay it out from Withdrawals.`,'withdrawals');
      db.txs.unshift(tx);return;
    }
    const asset=d.asset,net=(NETS[asset]||[]).find(n=>n.name===d.network),addr=str(d.address,120);
    if(!net||!net.re.test(addr))throw fail(400,'That wallet address does not match the selected network.');
    if(!FIAT.includes(cur)&&cur!==asset)throw fail(400,'Invalid source balance.');
    if(!(me.bal[cur]>=amt))throw fail(400,'Insufficient balance.');
    // crypto withdrawals have no daily or monthly limit (only the balance)
    const gross=amt*rate(cur)/rate(asset),platform=platFee(gross,asset,cur),receive=gross-platform-net.fee;
    if(!(receive>0))throw fail(400,'That amount is too small to cover the fees.');
    me.bal[cur]=r8(me.bal[cur]-amt);
    tx.d={asset,network:net.name,address:addr,receive:r8(receive),platformFee:r8(platform),networkFee:net.fee};
    notifyAdmins('Withdrawal requested',`${me.name}: ${money(cur,amt)} to ${asset} on ${net.name}`,'withdrawals');
  }else{
    const to=d.to;if(!FIAT.includes(cur)||!CRYPTO.includes(to))throw fail(400,'Invalid conversion.');
    if(!(me.bal[cur]>=amt))throw fail(400,'Insufficient balance.');
    const rec=r8((amt-srcFee(amt,cur))*rate(cur)/rate(to));if(!(rec>0))throw fail(400,'That amount is too small to cover the fee.');
    me.bal[cur]=r8(me.bal[cur]-amt);me.bal[to]=r8((me.bal[to]||0)+rec);tx.status='completed';tx.d={to,receive:rec};
  }
  db.txs.unshift(tx);
}
function settleTx(o,x){ // admin decision on a pending tx; the server applies the balance effect
  const tu=byId(o.userId);if(!tu)return;
  if(x.status==='completed'){
    if(o.type==='deposit')tu.bal[o.currency]=r8((tu.bal[o.currency]||0)+o.amount);
    
    o.status='completed';if(o.type==='deposit'){o.creditedAt=Date.now();refRewardCheck(o)}
    notify(tu.id,o.type==='deposit'?'Deposit credited':'Withdrawal sent',o.type==='deposit'?`Your deposit of ${money(o.currency,o.amount)} has been credited.`:o.d.method==='bank'?`Your withdrawal of ${money(o.currency,o.d.receive)} to ${o.d.payCur?'your '+o.d.payCur+' bank account':'your bank account in '+o.d.country} was approved and sent.`:`Your withdrawal of ${money(o.d.asset,o.d.receive)} on ${o.d.network} was approved and sent.`,o.type==='deposit'?{}:{details:o.d.method==='bank'?[['Amount',money(o.currency,o.d.receive)],['Currency',o.currency],['Destination',o.d.bankName||o.d.holder],['Reference',o.d.payRef||o.id]]:[['Asset',o.d.asset],['Amount',money(o.d.asset,o.d.receive)],['Network',o.d.network],['Destination',o.d.address]]});
  }else if(x.status==='rejected'){
    if(o.type==='withdrawal')tu.bal[o.currency]=r8((tu.bal[o.currency]||0)+o.amount);
    o.status='rejected';o.note=str(x.note,300)||'Rejected.';
    notify(tu.id,o.type==='deposit'?'Deposit not accepted':'Withdrawal rejected',`${o.type==='withdrawal'?'Your funds were returned to your balance. ':''}Reason: ${o.note}`);
  }
}
function adminMerge(inc){
  for(const x of inc.users||[]){const o=byId(x.id);if(!o||o.role==='admin'||o.status==='closed')continue;
    if(['active','suspended'].includes(x.status)&&x.status!==o.status){o.status=x.status;notify(o.id,o.status==='suspended'?'Account suspended':'Account reactivated',o.status==='suspended'?'Your account has been suspended. Contact support for help.':'Your account is active again.')}}
  for(const x of inc.kycs||[]){const o=db.kycs.find(y=>y.id===x.id);if(!o||o.status!=='pending'||!['verified','rejected'].includes(x.status))continue;
    o.status=x.status;o.note=str(x.note,300);const tu=byId(o.userId);
    if(tu){tu.kyc=o.status;notify(tu.id,o.status==='verified'?'Identity verified':'Identity check declined',o.status==='verified'?'Your documents were approved. You can now withdraw.':`Your documents were not approved. ${o.note||'Please check your details and submit again.'}`)}}
  for(const t of inc.tickets||[]){const o=db.tickets.find(y=>y.id===t.id);if(!o)continue;const have=new Set(o.msgs.map(m=>m.ts+m.text));
    for(const m of t.msgs||[])if(m.from==='admin'&&!have.has(m.ts+m.text)&&!o.msgs.some(x=>x.from==='admin'&&x.ts===+m.ts)&&!(o.delTs||[]).includes(+m.ts)){o.msgs.push({from:'admin',text:str(m.text,5000),ts:+m.ts||Date.now()});o.human=true;o.needsHuman=false;notify(o.userId,'Support replied',o.subject,{noMail:true});mailTicket(o,str(m.text,5000),'HarborPay Support')}
    if(t.status==='closed'&&o.status==='open')o.status='closed'}
  if(Array.isArray(inc.ann))db.ann=inc.ann.map(x=>({id:str(x.id,40),title:str(x.title,140),body:str(x.body,2000),active:!!x.active,ts:+x.ts||Date.now()}));
  for(const x of inc.txs||[]){const o=db.txs.find(y=>y.id===x.id);if(!o)continue;
    if(o.status==='pending'&&['completed','rejected'].includes(x.status))settleTx(o,x);
    else if(typeof x.note==='string'&&x.note!==o.note)o.note=str(x.note,300)}
}
function customerMerge(me,inc){
  if(me.status==='suspended')throw fail(403,'Account suspended');
  const x=(inc.users||[]).find(y=>y.id===me.id);
  if(x){
    if(typeof x.name==='string'&&x.name.trim())me.name=str(x.name,80);
    if(typeof x.phone==='string'&&str(x.phone,30)!==me.phone){const old=me.phone;me.phone=str(x.phone,30);delete me.pv;if(old)notify(me.id,'Your phone number was changed',`The phone number on your HarborPay account was changed. If you didn't make this change, contact support immediately.`,{view:'profile',details:[['New number',me.phone?me.phone.replace(/.(?=.{4})/g,'•'):'removed'],['Time',new Date().toUTCString().replace('GMT','UTC')]]})}
  }
  for(const t of(inc.txs||[]).filter(t=>t.userId===me.id&&t.type!=='withdrawal'&&!db.txs.some(y=>y.id===t.id)).reverse())addTx(me,t); // withdrawals go through POST /api/withdraw, which checks the PIN
  for(const t of inc.tickets||[]){const o=db.tickets.find(y=>y.id===t.id);
    if(!o){if(t.userId===me.id&&t.msgs&&t.msgs[0]){const nt={id:/^t_[a-z0-9]{3,20}$/.test(t.id)?t.id:uid('t'),userId:me.id,subject:str(t.subject,140)||str(t.msgs[0].text,60),status:'open',ts:Date.now(),msgs:[{from:'user',text:str(t.msgs[0].text,5000),ts:Date.now()}]};db.tickets.unshift(nt);
      if(botWillAnswer(nt))queueBot(nt);else notifyAdmins('New support conversation',`${me.name}: ${nt.subject}`,'support')}}
    else if(o.userId===me.id&&o.status==='open'){const have=new Set(o.msgs.map(m=>m.ts+m.text));let added=0;
      for(const m of t.msgs||[])if(m.from==='user'&&!have.has(m.ts+m.text)){o.msgs.push({from:'user',text:str(m.text,5000),ts:+m.ts||Date.now()});o.lastVia='app';added++}
      o.msgs.sort((p,q)=>p.ts-q.ts);
      if(added){if(botWillAnswer(o))queueBot(o);else notifyAdmins('Support message',`${me.name}: ${o.subject}\n"${str(o.msgs[o.msgs.length-1].text,300)}"`,'support')}}}
}
function merge(u,inc,req){
  const a=u.role==='admin',ip=ipOf(req);
  if(a)adminMerge(inc);else customerMerge(u,inc);
  const seen=new Set(db.audit.map(e=>e.ts+'|'+e.action+'|'+e.detail));
  for(const e of(inc.audit||[]).slice().reverse()){const k=e.ts+'|'+e.action+'|'+e.detail;
    if(!seen.has(k)&&typeof e.action==='string'&&(a||e.actor===u.email)){db.audit.unshift({ts:+e.ts||Date.now(),actor:str(e.actor,120),action:str(e.action,120),detail:str(e.detail,400),ip});seen.add(k)}}
  if(db.audit.length>3000)db.audit.length=3000;
}

/* ---- text messages (Twilio) ---- */
const SMS={sid:process.env.TWILIO_ACCOUNT_SID,tok:process.env.TWILIO_AUTH_TOKEN,from:process.env.TWILIO_FROM,ms:process.env.TWILIO_MESSAGING_SERVICE_SID,base:process.env.TWILIO_API_BASE||'https://api.twilio.com'};
const smsReady=()=>!!(SMS.sid&&SMS.tok&&(SMS.from||SMS.ms));
/* WhatsApp codes (Meta WhatsApp Business Cloud API, authentication template with a copy-code button) */
const WA={tok:process.env.WHATSAPP_TOKEN,phone:process.env.WHATSAPP_PHONE_NUMBER_ID,tpl:process.env.WHATSAPP_TEMPLATE||'harborpay_code',lang:process.env.WHATSAPP_TEMPLATE_LANG||'en_US',
  base:(process.env.WHATSAPP_API_BASE||'https://graph.facebook.com')+'/'+(process.env.WHATSAPP_API_VERSION||'v23.0'),button:process.env.WHATSAPP_TEMPLATE_BUTTON!=='none'};
const waReady=()=>!!(WA.tok&&WA.phone);
/* ============ WhatsApp bot: HarborPay's own linked WhatsApp number sends the codes (no Meta setup) ============
   Uses @whiskeysockets/baileys, which links like WhatsApp Web. Link it once from Admin → Controls → WhatsApp bot. */
const WB={state:'off',qr:null,pair:null,me:null,err:'',at:0,mode:'qr',phone:''};let waSock=null,waRetry=0,waTimer=null;
const WB_DIR=path.join(DIR,'wa-bot');
const waBotLinked=()=>{try{const c=JSON.parse(fs.readFileSync(path.join(WB_DIR,'creds.json'),'utf8'));return!!((c.me&&c.me.id)||c.registered)}catch{return false}};
let codeAlertAt=0;const codeTrouble=why=>{if(Date.now()-codeAlertAt<36e5)return;codeAlertAt=Date.now();notifyAdmins('A customer could not get their phone code',why+' Customers only saw "try again in a few minutes". Check Controls → WhatsApp bot.','controls')};
const waBotOpen=()=>WB.state==='open'&&!!waSock;
const WB_LOG={level:'silent',child(){return WB_LOG},trace(){},debug(){},info(){},warn(){},error(){},fatal(){}};
async function waBotStart(mode,phone){
  if(waSock){try{waSock.end&&waSock.end(undefined)}catch{}waSock=null}clearTimeout(waTimer);
  WB.mode=mode||WB.mode||'qr';WB.phone=phone||WB.phone||'';WB.state='starting';WB.qr=null;WB.pair=null;WB.err='';WB.at=Date.now();
  let B;try{B=await import('@whiskeysockets/baileys')}catch(e){WB.state='error';WB.err='The WhatsApp library is not installed. Make sure package.json was uploaded, then redeploy on Railway.';return}
  const M=B.useMultiFileAuthState?B:(B.default||{}),make=(M.default&&typeof M.default==='function')?M.default:(M.makeWASocket||B.default);
  if(typeof make!=='function'||!M.useMultiFileAuthState){WB.state='error';WB.err='The WhatsApp library did not load correctly.';return}
  fs.mkdirSync(WB_DIR,{recursive:true});
  const{state,saveCreds}=await M.useMultiFileAuthState(WB_DIR);let version;
  try{if(M.fetchLatestBaileysVersion)version=(await M.fetchLatestBaileysVersion()).version}catch{}
  const sock=make({auth:state,logger:WB_LOG,printQRInTerminal:false,markOnlineOnConnect:false,syncFullHistory:false,...(version?{version}:{}),...(M.Browsers?{browser:M.Browsers.ubuntu('Chrome')}:{})});
  waSock=sock;let asked=false;
  sock.ev.on('creds.update',saveCreds);
  sock.ev.on('connection.update',async u=>{if(sock!==waSock)return;
    if(u.qr){if(WB.mode==='code'&&WB.phone&&!asked&&!state.creds.registered){asked=true;try{WB.pair=await sock.requestPairingCode(WB.phone.replace(/\D/g,''));WB.state='pairing'}catch(e){WB.state='error';WB.err='Could not get a link code: '+e.message}}
      else if(WB.mode!=='code'){WB.state='qr';WB.qrRaw=u.qr;try{const Q=await import('qrcode');WB.qr=await(Q.toDataURL||Q.default.toDataURL)(u.qr,{margin:1,width:280})}catch{WB.qr=null}}}
    if(u.connection==='open'){WB.state='open';WB.qr=null;WB.qrRaw=null;WB.pair=null;WB.err='';waRetry=0;WB.me=String((sock.user&&sock.user.id)||'').split(':')[0].split('@')[0];WB.at=Date.now();
      addAudit('system','WhatsApp bot connected','+'+WB.me);save()}
    if(u.connection==='close'){const code=u.lastDisconnect&&u.lastDisconnect.error&&u.lastDisconnect.error.output&&u.lastDisconnect.error.output.statusCode,out=M.DisconnectReason?code===M.DisconnectReason.loggedOut:code===401;
      if(out){WB.state='off';WB.me=null;try{fs.rmSync(WB_DIR,{recursive:true,force:true})}catch{}waSock=null;notifyAdmins('WhatsApp bot was logged out','Phone codes cannot go out on WhatsApp until you link the number again in Controls → WhatsApp bot.','controls');addAudit('system','WhatsApp bot logged out','');save();return}
      if(WB.state==='qr'||WB.state==='pairing'){if(Date.now()-WB.at>5*6e4){WB.state='off';WB.err='Linking timed out. Start again.';waSock=null;return}}
      WB.state=waBotLinked()?'reconnecting':WB.state;const wait=Math.min(60e3,2e3*Math.pow(2,waRetry++));waTimer=setTimeout(()=>waBotStart(WB.mode,WB.phone).catch(e=>{WB.state='error';WB.err=e.message}),wait)}});
}
async function waBotSend(phone,text){if(!waBotOpen()){codeTrouble('The WhatsApp bot is not connected right now (status: '+WB.state+').');throw fail(503,"We couldn't send your code right now. Please try again in a few minutes.")}
  const jid=String(phone).replace(/\D/g,'')+'@s.whatsapp.net';let hit;
  try{const r=await waSock.onWhatsApp(jid);hit=Array.isArray(r)?r[0]:null}catch(e){codeTrouble('Checking a number on WhatsApp failed: '+e.message);throw fail(502,"We couldn't send your code right now. Please try again in a few minutes.")}
  if(!hit||!hit.exists)throw fail(400,'This number is not on WhatsApp. Enter the number you use on WhatsApp, with + and your country code.');
  try{await waSock.sendMessage(hit.jid||jid,{text})}catch(e){codeTrouble('Sending a WhatsApp message failed: '+e.message);throw fail(502,"We couldn't send your code right now. Please try again in a few minutes.")}}
if(waBotLinked())setTimeout(()=>waBotStart('qr').catch(e=>{WB.state='error';WB.err=e.message}),3000);
const phoneReady=()=>smsReady()||waReady()||waBotLinked();
async function sendWa(to,code){
  const components=[{type:'body',parameters:[{type:'text',text:code}]},...(WA.button?[{type:'button',sub_type:'url',index:'0',parameters:[{type:'text',text:code}]}]:[])];
  let r;try{r=await fetch(`${WA.base}/${encodeURIComponent(WA.phone)}/messages`,{method:'POST',headers:{Authorization:'Bearer '+WA.tok,'Content-Type':'application/json'},
    body:JSON.stringify({messaging_product:'whatsapp',recipient_type:'individual',to:to.replace(/^\+/,''),type:'template',template:{name:WA.tpl,language:{code:WA.lang},components}}),signal:AbortSignal.timeout(15000)})}
  catch(e){codeTrouble('Meta WhatsApp could not be reached.');throw fail(502,"We couldn't send your code right now. Please try again in a few minutes.")}
  if(!r.ok){const j=await r.json().catch(()=>({})),er=j.error||{},m=String(er.message||'')+' '+String((er.error_data||{}).details||'');console.error('whatsapp',r.status,er.code,m);
    try{mailNote('+'+to.replace(/^\+/,'').slice(0,-4).replace(/\d/g,'•')+to.slice(-4),'WhatsApp code','failed',`WhatsApp ${r.status} (${er.code||''}): ${m.trim()}`)}catch{}
    if([131026,131030,131009,100].includes(er.code)&&/recipient|not a valid|phone/i.test(m))throw fail(400,`This number is not on WhatsApp. Enter the number you use on WhatsApp, with + and your country code.`);
    codeTrouble('Meta WhatsApp refused the message: '+m.trim());throw fail(502,"We couldn't send your code right now. Please try again in a few minutes.")}
}
const phoneCodes=new Map(); // userId -> {phone, hash, exp, n, sent[]}; kept in memory only
async function sendSms(to,text){
  let r;try{r=await fetch(`${SMS.base}/2010-04-01/Accounts/${encodeURIComponent(SMS.sid)}/Messages.json`,{method:'POST',headers:{Authorization:'Basic '+Buffer.from(SMS.sid+':'+SMS.tok).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({To:to,Body:text,...(SMS.ms?{MessagingServiceSid:SMS.ms}:{From:SMS.from})}),signal:AbortSignal.timeout(15000)})}
  catch(e){codeTrouble('The text message service could not be reached.');throw fail(502,"We couldn't send your code right now. Please try again in a few minutes.")}
  if(!r.ok){const j=await r.json().catch(()=>({}));console.error('sms',r.status,j.message||'');throw fail(502,'We could not send a text to that number. Check it and try again.')}
}

/* ---- support assistant ----
   Answers customers in Support. With an AI key (Groq, Gemini or Claude) it uses AI; otherwise built-in answers.
   It can explain and look up the customer's own status, but it never changes anything. It hands over to a person
   when it cannot help or the customer asks, and every exchange is reported to the admins. */
const BOT_NAME='HarborPay Assistant';
const botWillAnswer=t=>!!db.settings.bot&&!t.human&&t.status==='open';
function queueBot(t){t.botPending=true;setTimeout(()=>botReply(t.id).catch(e=>console.error('assistant',e.message)),400)}
function botFacts(){
  const s=db.settings,L=s.limits,pct=feeText();
  const speed=FIAT.map(c=>`${c}: ${((s.depositInfo[c]||{}).speed||[]).filter(r=>!r[2]).map(r=>r[0]+': '+r[1]).join('; ')}`).join('\n');
  return `Fees: opening an account and receiving bank transfers are free. Converting fiat to crypto costs ${pct}. Crypto withdrawals cost ${pct} plus the network fee (${CRYPTO.map(c=>NETS[c].map(n=>`${c} on ${n.name}: ${n.fee} ${c}`).join(', ')).join('; ')}). Bank withdrawals cost ${pct}.
Minimum deposits: ${FIAT.map(c=>money(c,s.minDep[c])).join(', ')}.
Limits (US dollar value): ${money('USD',L.daily)} a day and ${money('USD',L.monthly)} a month for deposits, and separately for bank withdrawals. Crypto withdrawals have no limit. Deposits from someone else: up to ${money('USD',L.thirdParty)} per transfer.${FIAT.filter(ownLimit).map(c=>{const x=s.curLimits[c];return `\n${c} deposits have their own limits instead: ${money(c,x.daily)} a day, ${money(c,x.monthly)} a month, ${money(c,x.thirdParty)} per transfer from someone else.`}).join('')}
Deposit speed by currency:\n${speed}
Countries where HarborPay is available: ${ELIGIBLE.join(', ')}. Bank withdrawals go to bank accounts in those countries only.
How deposits work: the customer requests account details for a currency (USD, EUR, GBP, MXN or COP) on the Deposit page. The request is reviewed and the details appear when ready. The customer sends a bank transfer to those details, then taps "I have sent the transfer". The money is credited after it is confirmed.
How withdrawals work: identity check (KYC) approved and email verified first. Choose Crypto wallet (BTC, ETH, USDT, USDC on the listed networks) or Bank account, confirm with the 4-digit PIN. Every withdrawal is reviewed, most within a few hours. If rejected, the money goes back to the balance.
Identity check: on the KYC page, a photo of an ID card, driver's licence or passport plus a live selfie. It is reviewed.
Email verification: on the dashboard tap "Request verification"; a tap-to-verify button is then sent in the app.
Security: password, optional Google Authenticator two-step sign-in, and a 4-digit transaction PIN. Forgot password: "Forgot password?" on the sign-in page, using the PIN or an authenticator code.
Cards: coming soon; customers can join the waitlist on the Cards page.
Deleting an account: Profile page, "Delete account", once the balance is empty and nothing is pending.`;
}
function botSnapshot(u){
  const bal=ALLC.filter(c=>(u.bal[c]||0)>0).map(c=>money(c,u.bal[c])).join(', ')||'all zero';
  const tx=db.txs.filter(x=>x.userId===u.id).slice(0,6).map(x=>`${new Date(x.ts).toISOString().slice(0,10)} ${x.type} ${money(x.currency,x.amount)}${x.d&&x.d.method==='bank'?' to '+bankDest(x.d):x.d&&x.d.asset?' to '+x.d.asset+' on '+x.d.network:''}: ${x.status}${x.note?' ('+x.note+')':''}`).join('\n')||'none';
  return `Name: ${u.name}. Country: ${u.country}. Account: ${u.status}. Identity check: ${u.kyc}. Email: ${(u.ev||{}).status||'none'}. Two-step sign-in: ${u.twofa?'on':'off'}.
Account details: ${FIAT.map(c=>`${c} ${acct(u,c).status.replace('_',' ')}`).join(', ')}.
Balances: ${bal}. Card waitlist: ${u.cardWaitlist?'joined':'not joined'}.
Recent transactions:\n${tx}`;
}

/* AI for the support assistant and Ben. Set ONE of these in Railway Variables:
   OPENAI_API_KEY (paid, ChatGPT models), GROQ_API_KEY (free, no card, does not keep your data), GEMINI_API_KEY (free; Google may use free-tier data), or ANTHROPIC_API_KEY (paid).
   Optional AI_MODEL picks a different model. */
const aiProvider=()=>process.env.OPENAI_API_KEY?'openai':process.env.GROQ_API_KEY?'groq':process.env.GEMINI_API_KEY?'gemini':process.env.ANTHROPIC_API_KEY?'claude':'';
const aiOn=()=>!!aiProvider();
async function aiCall(system,messages,max,ms){const p=aiProvider();if(!p)return null;
  if(p==='claude'){const r=await fetch((process.env.ANTHROPIC_BASE_URL||'https://api.anthropic.com')+'/v1/messages',{method:'POST',headers:{'content-type':'application/json','x-api-key':process.env.ANTHROPIC_API_KEY,'anthropic-version':'2023-06-01'},
      body:JSON.stringify({model:process.env.AI_MODEL||process.env.ANTHROPIC_MODEL||'claude-haiku-5-5',max_tokens:max,system,messages}),signal:AbortSignal.timeout(ms)});
    if(!r.ok)throw new Error('AI service answered '+r.status);const j=await r.json();return(j.content||[]).filter(c=>c.type==='text').map(c=>c.text).join('').trim()}
  const g=p==='groq',o=p==='openai',url=process.env.AI_BASE_URL||(o?'https://api.openai.com/v1/chat/completions':g?'https://api.groq.com/openai/v1/chat/completions':'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions');
  const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+(o?process.env.OPENAI_API_KEY:g?process.env.GROQ_API_KEY:process.env.GEMINI_API_KEY)},
    body:JSON.stringify({model:process.env.AI_MODEL||(o?'gpt-4o-mini':g?'llama-3.3-70b-versatile':'gemini-flash-lite-latest'),...(o?{max_completion_tokens:max}:{max_tokens:max}),temperature:0.2,messages:[{role:'system',content:system},...messages]}),signal:AbortSignal.timeout(ms)});
  if(!r.ok)throw new Error('AI service answered '+r.status);const j=await r.json();return String(((j.choices||[])[0]||{}).message&&j.choices[0].message.content||'').trim()}
async function aiAnswer(t,u){
  if(!aiOn())return null;
  const system=`You are ${BOT_NAME}, the customer support assistant inside the HarborPay app. HarborPay lets people hold USD, EUR, GBP, MXN and COP received by bank transfer, convert to crypto and withdraw to a crypto wallet or a bank account. HarborPay is not a bank.
Answer the customer's question using only the facts below and their account summary. Be warm, brief (under 120 words), and plain. Use no markdown headings or tables.
Rules:
- Never ask for or accept a password, PIN, two-step code or full card or account number. If they share one, tell them not to and to change it.
- You cannot change anything: you cannot approve, speed up, cancel or reverse transactions, edit details or unlock accounts. Say what the customer can do in the app, or that it will be looked at.
- Do not give financial, legal or tax advice.
- If the question needs a person (missing money, a dispute, a complaint, a rejected item they disagree with, account changes, anything you are not sure about), or they ask for a person, say support will reply in this conversation, and end your message with the exact tag [HANDOFF].
FACTS:\n${botFacts()}\nCUSTOMER ACCOUNT SUMMARY:\n${botSnapshot(u)}`;
  const msgs=[];
  for(const m of t.msgs){const role=m.from==='user'?'user':'assistant',text=m.from==='admin'?'[Support team] '+m.text:m.text;
    if(msgs.length&&msgs[msgs.length-1].role===role)msgs[msgs.length-1].content+='\n\n'+text;else msgs.push({role,content:text})}
  if(msgs.length)msgs[0].content=`Subject: ${t.subject}\n\n`+msgs[0].content;
  while(msgs.length&&msgs[msgs.length-1].role!=='user')msgs.pop();if(!msgs.length)return null;
  const text=await aiCall(system,msgs,700,45000);
  return text?{text:text.replace(/\[HANDOFF\]/g,'').trim(),handoff:/\[HANDOFF\]/.test(text)}:null;
}
function ruleAnswer(t,u){ // built-in answers when no AI key is set (or the AI service fails)
  const q=t.msgs.filter(m=>m.from==='user').slice(-1)[0].text.toLowerCase(),s=db.settings,pct=feeText(),has=(...w)=>w.some(x=>q.includes(x));
  const pend=db.txs.filter(x=>x.userId===u.id&&x.status==='pending'),A=[];
  if(/\b(\d{4}|\d{6})\b/.test(q)&&has('pin','code','password'))A.push('Please do not share your PIN, password or codes with anyone, including us. If you just did, change it in Security.');
  if(has('human','a person','real person','agent','staff','manager','talk to','speak to','call me'))return{text:'Of course. I have passed this to support, and a person will reply in this conversation, usually within a few hours.',handoff:true};
  if(has('missing','not received',"haven't received",'not arrived','lost','stolen','fraud','scam','hacked','dispute','complain','refund','wrong address','wrong account'))return{text:'I am sorry about this. It needs a person to look at your account, so I have passed it to support. They will reply in this conversation, usually within a few hours. If you can, add the amount, the date and how you sent it.',handoff:true};
  if(has('pending','status','where is','how long','when will','processing')){
    A.push(pend.length?`You have ${pend.length} item${pend.length>1?'s':''} being processed: ${pend.slice(0,3).map(x=>`a ${x.type} of ${money(x.currency,x.amount)} from ${new Date(x.ts).toISOString().slice(0,10)}`).join('; ')}. Deposits are credited once the money is confirmed, and withdrawals are reviewed before they are sent, most within a few hours.`:'You have nothing being processed right now. Your full history is on the Transactions page.')}
  const asked=A.length>0;
  if(has('deposit','add money','account detail','iban','routing','clabe','sort code','receive')&&(!asked||has('how','request','minimum'))){const st=FIAT.map(c=>`${c}: ${acct(u,c).status.replace('_',' ')}`).join(', ');
    A.push(`To add money, open Deposit, pick the currency and request account details if you have not yet (yours: ${st}). Once approved, send a bank transfer to those details and tap "I have sent the transfer". The minimum is ${FIAT.map(c=>money(c,s.minDep[c])).join(', ')} depending on the currency. The Fees, Limits and Speed tabs on that page have the details.`)}
  if(has('withdraw','send crypto','cash out','payout','bank account','wallet')){const need=[];if(u.kyc!=='verified')need.push('your identity check approved');if((u.ev||{}).status!=='verified')need.push('your email verified');
    A.push(`${need.length?`Before you can withdraw, you need ${need.join(' and ')}. `:''}On the Withdraw page choose Crypto wallet or Bank account (for banks in ${ELIGIBLE.join(', ')}), then confirm with your PIN. The fee is ${pct}${has('crypto','wallet','btc','usdt','usdc','eth')?' plus the network fee':''}. Each withdrawal is reviewed before it is sent.`)}
  if(has('fee','cost','charge','price'))A.push(`Opening an account and receiving bank transfers are free. Converting to crypto, and each withdrawal, cost ${pct}. Crypto withdrawals also carry the network's own fee, shown before you confirm.`);
  if(has('limit','maximum','max ','how much can'))A.push(`Limits are ${money('USD',s.limits.daily)} a day and ${money('USD',s.limits.monthly)} a month for deposits, and separately for bank withdrawals. Crypto withdrawals have no limit (in US dollar value)${FIAT.filter(ownLimit).map(c=>`; ${c} deposits: ${money(c,s.curLimits[c].daily)} a day and ${money(c,s.curLimits[c].monthly)} a month`).join('')}. Transfers from someone else are limited to ${money('USD',s.limits.thirdParty)} each.`);
  if(has('kyc','verify','verification','identity','selfie','document','id card','passport')&&!has('email'))A.push(u.kyc==='verified'?'Your identity check is approved.':u.kyc==='pending'?'Your identity check is under review. You will get a notification as soon as it is decided.':u.kyc==='rejected'?'Your last identity check was not approved. Open KYC Status to see why and submit again.':'Open KYC Status, choose your document, add a photo of it and take a quick selfie. It will be reviewed, usually the same day.');
  if(has('email'))A.push((u.ev||{}).status==='verified'?'Your email is verified.':(u.ev||{}).status==='link_ready'?'Your email verification is ready: tap "Tap to verify your email" on your dashboard.':'Tap "Request verification" on your dashboard. A button to verify is then sent to you.');
  if(has('card','visa','mastercard'))A.push(u.cardWaitlist?'You are on the card waitlist. We will let you know when cards open.':'Cards are coming soon. You can join the waitlist on the Cards page.');
  if(has('password','forgot','2fa','authenticator','two-step','pin','locked'))A.push('You can change your password and PIN, and set up Google Authenticator, in Security. If you forgot your password, choose "Forgot password?" on the sign-in page and confirm with your PIN or an authenticator code.');
  if(has('country','countries','available in','support my'))A.push(`HarborPay is available in ${ELIGIBLE.join(', ')}.`);
  if(has('delete','close my account','remove my account'))A.push('You can delete your account on the Profile page, under "Delete account". Your balance needs to be empty and nothing can be pending.');
  if(has('convert','exchange','swap'))A.push(`Open Balances and use "Convert to crypto". The fee is ${pct} and you see the exact amount before you confirm.`);
  if(!A.length&&/^(hi|hello|hey|good (morning|afternoon|evening))\b/.test(q.trim())&&q.length<40)return{text:`Hello ${first(u)}! I am the HarborPay Assistant. I can help with deposits, withdrawals, fees, limits, identity checks and your account status. What would you like to know?`,handoff:false};
  if(!A.length)return{text:'Thanks for your message. I am not sure I can answer that one, so I have passed it to support. A person will reply here, usually within a few hours.',handoff:true};
  return{text:A.join('\n\n')+'\n\nIs there anything else I can help with?',handoff:false};
}
async function botReply(id){
  const t=db.tickets.find(x=>x.id===id);if(!t)return;const u=byId(t.userId);
  if(!u||!botWillAnswer(t)||t.msgs[t.msgs.length-1].from!=='user'){t.botPending=false;return}
  let a=null,via='built-in answers';
  try{a=await aiAnswer(t,u);if(a)via='AI'}catch(e){console.error('assistant:',e.message)}
  if(!a)a=ruleAnswer(t,u);
  if(!botWillAnswer(t)){t.botPending=false;return} // a person took over while it was thinking
  t.msgs.push({from:'bot',text:str(a.text,4000),ts:Date.now()});if(t.lastVia==='email')mailTicket(t,str(a.text,4000),'HarborPay Assistant (AI)');t.botPending=false;
  if(a.handoff){t.needsHuman=true;t.human=true}
  const q=t.msgs.filter(m=>m.from==='user').slice(-1)[0].text;
  notifyAdmins(a.handoff?'Support: a person is needed':'Support: assistant replied',`${u.name} (${u.email}) asked: "${str(q,240)}"\nAssistant (${via}): "${str(a.text,400)}"${a.handoff?'\nThe assistant handed this conversation to the team.':''}`,'support');
  addAudit(BOT_NAME,a.handoff?'Assistant handed over to the team':'Assistant replied',`${u.email}: ${str(t.subject,80)}`,'');
  save();push(u.id,'sync',{});pushAdmins('sync',{});
}

/* ---- account details: customer request + admin approval ---- */
const AV_PURPOSE=['Receiving salary or freelance income','Receiving payments from clients for my business','Receiving money from family','Saving and converting to crypto','Other'];
const AV_SOURCE=['Employment or salary','Freelance or contract work','Business income','Savings','Investments','Family support','Other'];
const AV_VOLUME=['Under $1,000','$1,000 to $5,000','$5,000 to $20,000','$20,000 to $100,000','Over $100,000'];
const avOf=u=>u.av||(FIAT.some(c=>acct(u,c).status==='approved')?{status:'approved',legacy:true}:{status:'none'}); // customers approved before this check existed are treated as verified
function takeVerification(u,v){
  v=v||{};const a={occupation:str(v.occupation,100),employer:str(v.employer,120),purpose:str(v.purpose,80),source:str(v.source,80),volume:str(v.volume,40),payers:str(v.payers,300),address:str(v.address,300)};
  if(a.occupation.length<2)throw fail(400,'Enter your occupation.');
  if(!AV_PURPOSE.includes(a.purpose))throw fail(400,'Choose what you will use the account for.');
  if(!AV_SOURCE.includes(a.source))throw fail(400,'Choose where your money comes from.');
  if(!AV_VOLUME.includes(a.volume))throw fail(400,'Choose how much you expect to receive each month.');
  if(a.payers.length<3)throw fail(400,'Tell us who will send you money.');
  if(a.address.length<8)throw fail(400,'Enter your home address.');
  if(!v.confirm)throw fail(400,'Confirm that the information is true.');
  u.av={status:'pending',answers:a,ts:Date.now()};
}
function requestAcct(u,c,req,b){
  if(!FIAT.includes(c))throw fail(400,'Choose a currency.');
  if(u.status==='suspended')throw fail(403,'Account suspended');
  if(acct(u,c).status!=='none')return;
  if(u.kyc!=='verified')throw fail(403,'Get your identity check approved before requesting account details.');
  if((u.ev||{}).status!=='verified')throw fail(403,'Verify your email before requesting account details.');
  if(phoneReady()&&!(u.pv&&u.pv.status==='verified'&&u.pv.phone===u.phone&&u.phone))throw fail(403,'Verify your phone number (in Profile) before requesting account details.');
  const av=avOf(u);
  if(av.status==='none'||av.status==='rejected'){
    if(!b||!b.verification)throw fail(428,'Complete the account verification form first.');
    takeVerification(u,b.verification);
    addAudit(u.email,'Account verification submitted',u.email,ipOf(req));
  }
  u.accts[c]={status:'under_review',draft:blankDetails(c),requestedAt:Date.now()};
  notify(u.id,`We've received your ${c} account details request`,`We've received your request for ${c} account details. It is being processed, and you'll get another notification as soon as your details are ready.`,{view:'deposit'});
  notifyAdmins(`${c} account details request`,`${u.name} (${u.email}) requested ${c} account details.${u.av&&u.av.status==='pending'?' Their account verification answers are waiting for review.':''}`,'usdaccounts');
  addAudit(u.email,`${c} account details requested`,u.email,ipOf(req));save();pushAdmins('sync',{});
  if(c==='USD'&&brReady())brStart(u).catch(e=>brErr(u,'Creating the identity link',e));
}
async function saveAcct(a,b,req){
  const u=needUser(b.userId),c=b.currency,d=b.details||{};
  if(!FIAT.includes(c))throw fail(400,'Unknown currency.');
  const spec=ACCT_FIELDS[c],det={method:str(d.method,60)||spec.method};
  for(const[k]of spec.f)det[k]=str(d[k],120);det.instructions=str(d.instructions,500);
  /* the admin can rename any heading and add extra lines; customers see exactly these headings */
  const lab=d.labels&&typeof d.labels==='object'?d.labels:{};det.labels={};
  for(const[k,l]of spec.f){const v=str(lab[k],40).trim();if(v&&v!==l)det.labels[k]=v}
  det.extra=(Array.isArray(d.extra)?d.extra:[]).slice(0,10).map(r=>[str(r&&r[0],40).trim(),str(r&&r[1],200).trim()]).filter(r=>r[0]&&r[1]);
  det.hidden=(Array.isArray(d.hidden)?d.hidden:[]).filter(k=>spec.f.some(f=>f[0]===k)); // lines the admin switched off: not shown and not required
  if(b.template){db.settings.acctTpl=db.settings.acctTpl||{};db.settings.acctTpl[c]={labels:det.labels,hidden:det.hidden,extra:(Array.isArray(d.extra)?d.extra:[]).slice(0,10).map(r=>str(r&&r[0],40).trim()).filter(Boolean)};addAudit(a.email,`${c} account headings set as default`,Object.values(det.labels).concat(db.settings.acctTpl[c].extra).join(', ')||'standard headings',ipOf(req))}
  const nameOf=([k,l])=>det.labels[k]||l;
  const x=acct(u,c),wasApproved=x.status==='approved',shown=spec.f.filter(f=>!det.hidden.includes(f[0])&&det[f[0]]).length+det.extra.length,missing=shown?[]:['at least one line'];
  if((b.approve||wasApproved)&&missing.length)throw fail(400,`Fill in ${missing.join(', ')} before approving.`);
  if(b.approve&&!wasApproved&&avOf(u).status==='rejected')throw fail(400,'This customer\'s account verification was declined. They need to send it again first.');
  if(b.approve&&!wasApproved&&u.av&&u.av.status==='pending'){u.av.status='approved';u.av.reviewedAt=Date.now();addAudit(a.email,'Account verification approved',u.email,ipOf(req))}
  if(b.approve||wasApproved){
    const old=wasApproved?String(x.details[spec.main]||''):'',now=det[spec.main];
    u.accts[c]={status:'approved',details:det,approvedAt:x.approvedAt||Date.now()};
    notify(u.id,wasApproved?`${c} account details updated`:`Your ${c} account details are ready`,wasApproved?`Your ${c} account details were updated. Check the Deposit page before sending your next transfer.`:`Your ${c} account details have been approved. Open the Deposit page to see them.`);
    addAudit(a.email,wasApproved?`${c} account details edited`:`${c} account details approved`,`${u.email}${old&&old!==now?' (ending '+old.slice(-4)+' → '+now.slice(-4)+')':''}`,ipOf(req));
  }else{u.accts[c]={...x,status:'under_review',draft:det};addAudit(a.email,`${c} account draft saved`,u.email,ipOf(req))}
  save();push(null,'sync',{});return u.accts[c].status;
}

/* ---- http plumbing ---- */
const RESET_MAX=5,RESET_LOCK=864e5; // forgot-password: wrong tries allowed per account, and how long the lock lasts (24 hours)
const tries=new Map(),fail=(c,m)=>Object.assign(Error(m),{code:c});
const body=(req,limit=2e6)=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>limit){no(fail(413,'Upload too large'));req.destroy()}});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{no(fail(400,'Bad JSON'))}})});
const send=(res,code,obj)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(obj))};
const authed=(req,url)=>{const t=(req.headers.authorization||'').replace('Bearer ','')||url.searchParams.get('t'),raw=unsign(t)||'',[id,sid]=raw.split('~');
  const ss=sid&&db.sessions.find(x=>x.id===sid&&x.userId===id);if(!ss)throw fail(401,raw.includes('~')?'You were signed out of this device.':'Please sign in again');
  if(Date.now()-ss.lastSeen>6e4){ss.lastSeen=Date.now();ss.ip=ipOf(req);save()}req.sid=sid;
  const u=byId(id);if(!u||u.status==='closed')throw fail(401,u?'This account has been deleted.':'Please sign in again');
  if(u.role==='admin'&&!LOCK_OFF&&db.sec&&db.sec.devLock&&!(ss.dev&&db.sec.devices.some(x=>x.id===ss.dev)))throw fail(401,'You were signed out of this device.');return u};
const admin=(req,url)=>{const u=authed(req,url);if(u.role!=='admin')throw fail(403,'Admins only');return u};
const origin=req=>(req.headers['x-forwarded-proto']||'http')+'://'+req.headers.host;
const code2fa=LIVE?null:(process.env.DEMO_2FA||'123456'); // demo only. In live mode accounts without an authenticator app skip this step until they set one up
const DATAURL=/^data:(image\/(jpeg|png|webp)|application\/pdf);base64,[A-Za-z0-9+/=]+$/;
const EXT={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','application/pdf':'pdf'},MIME=Object.fromEntries(Object.entries(EXT).map(([m,e])=>[e,m]));
const needUser=id=>{const u=byId(id);if(!u||u.role!=='customer')throw fail(404,'Customer not found');return u};

const routes={
  async 'POST /api/login'(req,res){
    const{email='',pass=''}=await body(req),em=String(email).trim().toLowerCase(),t=tries.get(em)||{n:0,at:0},ip=ipOf(req);
    if(t.n>=5&&Date.now()-t.at<6e5)throw fail(429,'Too many attempts. Try again in a few minutes.');
    const u=db.users.find(x=>x.email.toLowerCase()===em);
    if(!u||!check(String(pass),db.creds[u.id])){const n=t.n+1;tries.set(em,{n,at:Date.now()});addAudit(em,'Failed sign-in',em,ip);
      if(u&&n===3)notify(u.id,'Failed sign-in attempts','Someone entered the wrong password for your HarborPay account 3 times. If this was you, you can reset your password. If it was not, change your password now.',{view:'security'});
      if(u&&n===5)notify(u.id,'Account temporarily locked','Sign-in to your HarborPay account was locked for 10 minutes after 5 wrong passwords. If this was not you, reset your password as soon as you can.',{view:'security'});
      save();throw fail(401,'That email and password do not match. Check both and try again.')}
    tries.delete(em);adminGate(u,req,false);await geoGate(u,req,'sign-in');
    if(u.twofa&&(db.totp[u.id]||code2fa))return send(res,200,{need2fa:true,tmp:sign('2fa-'+u.id,3e5),demo:!db.totp[u.id]});
    addAudit(u.email,'Signed in',u.email,ip);save();send(res,200,{token:newSession(u,req)});
  },
  async 'POST /api/2fa'(req,res){
    const{tmp,code}=await body(req),raw=unsign(tmp)||'',u=byId(raw.replace(/^2fa-/,''));
    if(!u||!raw.startsWith('2fa-'))throw fail(401,'Session expired. Sign in again.');
    const k='2fa:'+u.id,t=tries.get(k)||{n:0,at:0};
    if(t.n>=5&&Date.now()-t.at<6e5)throw fail(429,'Too many wrong codes. Try again in a few minutes.');
    const secret=db.totp[u.id]; // accounts with an authenticator app use real codes; older demo accounts still use the fixed demo code
    if(secret?!totpOk(secret,code):!code2fa||String(code).trim()!==code2fa){tries.set(k,{n:t.n+1,at:Date.now()});throw fail(401,secret?'That code is not right. Enter the 6 digits your authenticator app shows now.':'That code is not right.')}
    tries.delete(k);addAudit(u.email,'Signed in',u.email,ipOf(req));save();send(res,200,{token:newSession(u,req)});
  },

  /* ---- two-step sign-in with an authenticator app ---- */
  async 'POST /api/2fa/setup'(req,res,url){
    const u=authed(req,url),secret=b32enc(crypto.randomBytes(20));pendingTotp.set(u.id,secret);
    send(res,200,{secret,uri:`otpauth://totp/HarborPay:${encodeURIComponent(u.email)}?secret=${secret}&issuer=HarborPay`});
  },
  async 'POST /api/2fa/enable'(req,res,url){
    const u=authed(req,url),{code}=await body(req),secret=pendingTotp.get(u.id);
    if(!secret)throw fail(400,'Start the setup again.');
    if(!totpOk(secret,code))throw fail(400,'That code is not right. Enter the 6 digits the app shows now, and check the time on your phone is set automatically.');
    pendingTotp.delete(u.id);db.totp[u.id]=secret;u.twofa=true;
    notify(u.id,'Two-step sign-in is on','Your authenticator app is now required each time you sign in.');
    addAudit(u.email,'Two-step sign-in on','authenticator app',ipOf(req));save();send(res,200,{ok:true});
  },
  async 'POST /api/2fa/disable'(req,res,url){
    const u=authed(req,url),{code}=await body(req);
    if(db.totp[u.id]&&!totpOk(db.totp[u.id],code))throw fail(400,'That code is not right. Enter the 6 digits your authenticator app shows now.');
    delete db.totp[u.id];u.twofa=false;
    notify(u.id,'Two-step sign-in is off','Your account is now protected by your password only.');
    addAudit(u.email,'Two-step sign-in off',u.email,ipOf(req));save();send(res,200,{ok:true});
  },

  /* ---- forgot password: prove it is you with the 4-digit transaction PIN or an authenticator code ---- */
  async 'POST /api/password-reset'(req,res){
    const b=await body(req),em=str(b.email,120).toLowerCase(),method=b.method==='totp'?'totp':'pin',code=String(b.code||'').replace(/\s/g,''),nw=String(b.new||''),ip=ipOf(req),now=Date.now();
    const what=method==='pin'?'4-digit PIN':'authenticator code';
    if(!/^\S+@\S+\.\S+$/.test(em))throw fail(400,'Enter the email address on your account.');
    if(nw.length<8)throw fail(400,'New password must be at least 8 characters.');
    // A 4-digit PIN has only 10,000 combinations, so wrong tries are tightly limited: 5 per account, then resetting is locked for 24 hours.
    const kE='reset:'+em,kI='resetip:'+ip,tE=tries.get(kE)||{n:0,at:0},tI=tries.get(kI)||{n:0,at:0},LOCKED='Too many wrong attempts. Password reset is locked for this account for 24 hours. Contact support if you need help.';
    if(tE.n>=RESET_MAX&&now-tE.at<RESET_LOCK)throw fail(429,LOCKED);
    if(tI.n>=20&&now-tI.at<36e5)throw fail(429,'Too many attempts. Try again in an hour.');
    const u=db.users.find(x=>x.email.toLowerCase()===em);
    // Admin accounts can never be reset with a PIN. The fixed demo 2-step code is never accepted here either: only a real authenticator app.
    const ok=!!u&&(method==='pin'?u.role!=='admin'&&/^\d{4}$/.test(code)&&pinOk(u,code):!!db.totp[u.id]&&totpOk(db.totp[u.id],code));
    if(!ok){
      const n=(now-tE.at<RESET_LOCK?tE.n:0)+1;tries.set(kE,{n,at:now});tries.set(kI,{n:(now-tI.at<36e5?tI.n:0)+1,at:now});
      addAudit(em,'Failed password reset',`${em} (${what})`,ip);
      if(u&&n===RESET_MAX){notify(u.id,'Password reset blocked',`Someone entered the wrong ${what} ${RESET_MAX} times while trying to reset your password. Resetting is locked for 24 hours. If this was not you, contact support.`);notifyAdmins('Password reset locked',`${u.name} (${u.email}): ${RESET_MAX} wrong attempts.`,'audit')}
      save();
      throw fail(n>=RESET_MAX?429:401,n>=RESET_MAX?LOCKED:`Those details do not match. Check your email and your ${what}, then try again. ${RESET_MAX-n} ${RESET_MAX-n===1?'try':'tries'} left.`);
    }
    tries.delete(kE);tries.delete(em);db.creds[u.id]=hash(nw);endSessions(u.id);
    notify(u.id,'Your password was changed',`Your password was reset from the sign-in page using your ${what}. If this was not you, contact support immediately.`,{noMail:true});
    await mail(u.email,'Your HarborPay password was changed',`Hi ${first(u)},\n\nYour password was just reset from the sign-in page using your ${what}.\n\nIf this was not you, contact support immediately.\n\n— HarborPay`);
    addAudit(u.email,'Password reset',`${u.email} (verified with ${what})`,ip);save();send(res,200,{ok:true});
  },
  async 'POST /api/register'(req,res){
    if(!db.settings.registrations)throw fail(403,'New sign-ups are currently closed.');
    const b=await body(req),em=str(b.email,120).toLowerCase(),country=str(b.country,60);
    if(!ELIGIBLE.includes(country))throw fail(400,`HarborPay is not available in ${country||'that country'} yet. Supported countries: ${ELIGIBLE.join(', ')}.`);
    if(!/^\S+@\S+\.\S+$/.test(em)||String(b.pass||'').length<8||!/^\d{4}$/.test(b.pin||''))throw fail(400,'Check your email, password (8+ characters) and 4-digit PIN.');
    if((db.blocked||[]).some(x=>x.email===em))throw fail(403,'We cannot open an account with this email. Contact support if you think this is a mistake.');
    if(db.users.some(u=>u.email.toLowerCase()===em))throw fail(409,'An account with that email already exists. Sign in instead.');
    const mode=db.settings.referral,code=str(b.ref,20).trim().toUpperCase(),found=mode!=='off'&&code?findRef(code):null,ref=found&&found.user,inv=found&&found.inv;
    if(mode==='required'&&!code)throw fail(400,'An invite code is needed to sign up. Ask the person who invited you for one.');
    if(mode!=='off'&&code&&!ref){const w=found.why;throw fail(400,w==='used'?'That invite code has already been used. Ask your friend for a new one.':w==='expired'?'That invite code has expired (codes last 1 hour). Ask your friend for a new one.':mode==='required'?'That invite code was not found. Check it with the person who invited you.':'That invite code was not found. Check it, or leave the box empty.')}
    const u={id:uid('u'),role:'customer',name:str(b.name,80),email:em,status:'active',kyc:'none',twofa:false,pinHash:hash(String(b.pin)),bal:ZERO(),country,phone:'',created:Date.now(),ev:{status:'none'},accts:Object.fromEntries(FIAT.map(c=>[c,{status:'none'}]))};
    if(ref){u.referredBy=ref.id;u.refUsed=inv.code;inv.status='used';inv.usedBy=u.id;inv.usedAt=Date.now()}
    db.users.push(u);db.creds[u.id]=hash(String(b.pass));db.sessions=db.sessions||[];addAudit(em,'Account created',ref?`${em} (invite code ${inv.code}, from ${ref.email})`:em,ipOf(req));save();
    if(ref&&ref.role==='customer')notify(ref.id,'Someone joined with your code',`${first(u)} just created a HarborPay account with your invite code ${inv.code}.`,{noMail:false});
    sendWelcome(u);notify(u.id,'Your HarborPay account has been created',`Congratulations! Your HarborPay account has been successfully registered. You're now one step closer to enjoying convenient and secure payments.`,{kind:'signup',view:'dashboard'});
    notifyAdmins('New sign-up',`${u.name} (${u.country})${ref?` joined with ${ref.name}'s invite code ${inv.code}`:' created an account'}.`,'users');
    geoGate(u,req,'sign-up').catch(()=>{});pushAdmins('sync',{});send(res,200,{token:newSession(u,req)});
  },
  async 'GET /api/db'(req,res,url){send(res,200,view(authed(req,url)))},
  async 'GET /api/public'(req,res){const s=db.settings;feeSetup();send(res,200,{fee:s.fee,fees:s.fees,feeMode:s.feeMode||'pct',feeFlat:s.feeFlat||0,minDep:s.minDep,limits:s.limits,curLimits:s.curLimits,depositInfo:s.depositInfo,eligible:ELIGIBLE,social:s.social,referral:s.referral})}, // for the public website
  async 'GET /api/referral/check'(req,res,url){const r=db.settings.referral!=='off'?findRef(url.searchParams.get('code')):{why:'missing'};send(res,200,{ok:!!(r&&r.user),name:r&&r.user?first(r.user):'',why:r&&r.why||''})},
  async 'PUT /api/db'(req,res,url){
    const u=authed(req,url);merge(u,await body(req),req);save();
    if(u.role==='admin')push(null,'sync',{});else pushAdmins('sync',{});send(res,200,{ok:true});
  },
  async 'POST /api/password'(req,res,url){
    const u=authed(req,url),{old,new:nw}=await body(req);
    if(!check(String(old),db.creds[u.id]))throw fail(400,'Your current password is not right.');
    if(String(nw||'').length<8)throw fail(400,'New password must be at least 8 characters.');
    db.creds[u.id]=hash(String(nw));const n=endSessions(u.id,req.sid);addAudit(u.email,'Password changed',u.email+(n?` (${n} other device${n>1?'s':''} signed out)`:''),ipOf(req));save();send(res,200,{ok:true,signedOut:n});
  },
  async 'POST /api/notifs/read'(req,res,url){const u=authed(req,url);db.notifs.forEach(n=>{if(n.userId===u.id)n.read=true});save();send(res,200,{ok:true})},
  async 'GET /api/events'(req,res,url){
    const u=authed(req,url);res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache',Connection:'keep-alive'});
    clients.set(res,{uid:u.id,sid:req.sid});res.write(`event: prices\ndata: ${JSON.stringify(market())}\n\n`);
    const ka=setInterval(()=>res.write(': ping\n\n'),25000);req.on('close',()=>{clearInterval(ka);clients.delete(res)});
  },

  /* ---- email verification ---- */
  async 'POST /api/email-verify/request'(req,res,url){
    const u=authed(req,url);if(u.ev.status==='verified')throw fail(400,'Your email is already verified.');
    if(u.ev.status==='none'){u.ev={status:'requested',ts:Date.now()};notifyAdmins('Email verification request',`${u.name} (${u.email}) asked to verify their email.`,'emailverify');addAudit(u.email,'Email verification requested',u.email,ipOf(req));save();pushAdmins('sync',{})}
    send(res,200,{status:u.ev.status});
  },
  async 'POST /api/verify-email'(req,res,url){
    const u=authed(req,url),{token}=await body(req);
    if(!u.ev.token||String(token)!==u.ev.token)throw fail(400,'This verification link is no longer valid. Ask for a new one.');
    u.ev={status:'verified',ts:Date.now()};addAudit(u.email,'Email verified',u.email,ipOf(req));save();pushAdmins('sync',{});send(res,200,{ok:true});
  },
  async 'POST /api/admin/email-verify'(req,res,url){
    const a=admin(req,url),b=await body(req),u=needUser(b.userId),link=()=>origin(req)+'/verify/'+u.ev.token;let emailed='';
    if(b.action==='verify'){u.ev={status:'verified',ts:Date.now()};notify(u.id,'Email verified','Your email address has been verified.');addAudit(a.email,'Email marked verified',u.email,ipOf(req))}
    else if(b.action==='link'||(b.action==='email'&&u.ev.token)){
      if(b.action==='link'){u.ev={status:'link_ready',token:crypto.randomBytes(16).toString('hex'),ts:Date.now()};
        notify(u.id,'Tap to verify your email','Your email verification link is ready.',{noMail:true,link:'/verify/'+u.ev.token,linkText:'Tap to verify your email'});addAudit(a.email,'Email verification link generated',u.email,ipOf(req))}
      if(b.email)emailed=await mail(u.email,'Verify your HarborPay email',`Hi ${first(u)},\n\nTap this link to verify your email:\n${link()}\n\n— HarborPay`);
    }else throw fail(400,'Nothing to do.');
    save();push(null,'sync',{});send(res,200,{link:u.ev.token?link():'',emailed});
  },

  /* ---- account details (USD, EUR, GBP, MXN, COP) ---- */
  async 'POST /api/accounts/request'(req,res,url){const u=authed(req,url),b=await body(req,9e6);requestAcct(u,b.currency,req,b);save();send(res,200,{status:u.accts[b.currency].status})},
  async 'POST /api/usd/request'(req,res,url){const u=authed(req,url);requestAcct(u,'USD',req);send(res,200,{status:u.accts.USD.status})}, // older pages
  async 'POST /api/admin/account-verification'(req,res,url){ // decline: the customer is told why and can send it again
    const a=admin(req,url),b=await body(req),u=needUser(b.userId),note=str(b.note,300);
    if(!u.av||u.av.status!=='pending')throw fail(400,'There is no verification waiting for review.');
    if(b.action!=='reject')throw fail(400,'Unknown action.');
    if(!note)throw fail(400,'Tell the customer why, so they can fix it.');
    u.av.status='rejected';u.av.note=note;u.av.reviewedAt=Date.now();
    for(const c of FIAT)if(acct(u,c).status==='under_review')u.accts[c]={status:'none'};
    notify(u.id,'Account verification declined',`We could not approve your account verification. Reason: ${note} You can send it again from the Deposit page.`);
    addAudit(a.email,'Account verification declined',`${u.email}: ${note}`,ipOf(req));save();push(u.id,'sync',{});pushAdmins('sync',{});send(res,200,{ok:true});
  },
  async 'GET /api/admin/wabot'(req,res,url){admin(req,url);send(res,200,{state:WB.state,qr:WB.qr,qrRaw:WB.qr?null:WB.qrRaw||null,pair:WB.pair,me:WB.me,err:WB.err,linked:waBotLinked()})},
  async 'POST /api/admin/wabot/connect'(req,res,url){const a=admin(req,url),b=await body(req),mode=b.mode==='code'?'code':'qr',phone=String(b.phone||'').replace(/[^\d+]/g,'');
    if(mode==='code'&&!/^\+?[1-9]\d{7,14}$/.test(phone))throw fail(400,'Enter the bot\'s WhatsApp number with country code, for example +2348012345678.');
    if(mode==='code'&&waBotLinked()&&!waBotOpen()){try{fs.rmSync(WB_DIR,{recursive:true,force:true})}catch{}}
    addAudit(a.email,'WhatsApp bot linking started',mode==='code'?'with a link code':'with a QR code',ipOf(req));await waBotStart(mode,phone);setTimeout(()=>send(res,200,{state:WB.state}),1500)},
  async 'POST /api/admin/wabot/logout'(req,res,url){const a=admin(req,url);try{if(waSock&&waSock.logout)await waSock.logout()}catch{}try{waSock&&waSock.end&&waSock.end(undefined)}catch{}waSock=null;clearTimeout(waTimer);
    try{fs.rmSync(WB_DIR,{recursive:true,force:true})}catch{}WB.state='off';WB.me=null;WB.qr=null;WB.pair=null;addAudit(a.email,'WhatsApp bot unlinked','',ipOf(req));save();send(res,200,{ok:true})},
  async 'POST /api/admin/wabot/test'(req,res,url){const a=admin(req,url),b=await body(req),to=String(b.to||'').replace(/[\s()-]/g,'');if(!/^\+[1-9]\d{7,14}$/.test(to))throw fail(400,'Enter the number with + and country code.');
    await waBotSend(to,'This is a test message from your HarborPay admin panel. WhatsApp codes are working. ✅');send(res,200,{ok:true})},
  async 'GET /api/admin/mail-log'(req,res,url){admin(req,url);send(res,200,{log:(db.mailLog||[]).slice(0,50),mode:mailMode(),order:mailOrder(),from:MAIL_FROM,resend:!!process.env.RESEND_API_KEY})},
  async 'POST /api/admin/mail-test'(req,res,url){const a=admin(req,url),b=await body(req),to=str(b.to,120)||a.email;if(!/^\S+@\S+\.\S+$/.test(to))throw fail(400,'Enter a valid email address.');
    const st=await mail(to,'HarborPay test email',`This is a test from your HarborPay admin panel, sent ${new Date().toUTCString()}.\n\nIf you can read this, emails (including PIN reset codes) are working.`);
    const last=(db.mailLog||[])[0]||{};send(res,200,{status:st,error:st==='sent'?'':last.error||''})},
  async 'POST /api/admin/acct-delete'(req,res,url){ // remove an account details request (or set-up details) quietly; the customer can ask again
    const a=admin(req,url),b=await body(req),u=byId(b.userId),c=b.currency;if(!u||u.role!=='customer')throw fail(404,'Customer not found.');if(!FIAT.includes(c))throw fail(400,'Choose a currency.');
    const x=(u.accts||{})[c];if(!x||x.status==='none')throw fail(400,'There is nothing to delete for this currency.');
    u.accts[c]={status:'none'};addAudit(a.email,'Account details request deleted',`${u.email} ${c} (was ${x.status})`,ipOf(req));save();push(u.id,'sync',{});pushAdmins('sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/accounts'(req,res,url){const a=admin(req,url),b=await body(req);send(res,200,{status:await saveAcct(a,b,req)})},
  async 'POST /api/admin/usd'(req,res,url){const a=admin(req,url),b=await body(req);send(res,200,{status:await saveAcct(a,{...b,currency:'USD'},req)})}, // older pages

  /* ---- admin edits ---- */
  async 'POST /api/admin/user'(req,res,url){
    const a=admin(req,url),b=await body(req),u=needUser(b.userId),ch=[];
    const name=str(b.name,80),email=str(b.email,120).toLowerCase(),country=str(b.country,60),phone=str(b.phone,30);
    if(!name)throw fail(400,'Name is required.');
    if(!/^\S+@\S+\.\S+$/.test(email))throw fail(400,'Enter a valid email.');
    if(db.users.some(x=>x.id!==u.id&&x.email.toLowerCase()===email))throw fail(409,'Another account already uses that email.');
    const oldEmail=u.email;
    if(name!==u.name){ch.push(`name: ${u.name} → ${name}`);u.name=name}
    if(country!==u.country){ch.push(`country: ${u.country} → ${country}`);u.country=country}
    if(phone!==u.phone){ch.push('phone');u.phone=phone;delete u.pv}
    if(email!==u.email){ch.push(`email: ${u.email} → ${email}`);u.email=email;u.ev={status:'none'}}
    if(!ch.length)return send(res,200,{changed:0});
    addAudit(a.email,'Customer details edited',`${oldEmail}: ${ch.join('; ')}`,ipOf(req));
    const other=ch.filter(c=>!/^email/.test(c));
    if(email!==oldEmail){
      notify(u.id,'Your email was successfully updated ✅',`Your HarborPay email is now ${email}. Use it to sign in from now on. Your password and PIN have not changed. You will be asked to verify the new email before your next withdrawal.`);
      await mail(oldEmail,'Your HarborPay email was changed',`Hi ${first(u)},\n\nThe email on your HarborPay account was successfully changed to ${email}. From now on, sign in with ${email}. Emails about your account will go there.\n\nIf you did not ask for this, contact support right away.\n\n— HarborPay`);u.ev={status:'none'}}
    if(other.length)notify(u.id,'Your account details were updated','We updated your '+other.map(c=>c.split(':')[0]).join(', ')+'. If you did not expect this, contact support.');
    save();push(null,'sync',{});send(res,200,{changed:ch.length});
  },
  async 'POST /api/admin/withdrawal-payout'(req,res,url){ // now, or (with "at") scheduled for a date and time
    const a=admin(req,url),b=await body(req);
    if(b.at){const j=wdSchedule(a.email,b,null),t=db.txs.find(x=>x.id===j.b.txId);addAudit(a.email,'Withdrawal result scheduled',`${money(t.currency,t.amount)} for ${(byId(t.userId)||{}).email} (${j.b.result||'completed'}) at ${new Date(j.at).toISOString().replace('T',' ').slice(0,16)} UTC`,ipOf(req));save();pushAdmins('sync',{});return send(res,200,{ok:true,scheduled:j.id,at:j.at})}
    if((db.wdJobs||[]).some(j=>j.status==='scheduled'&&j.b.txId===b.txId))throw fail(400,'This withdrawal already has a scheduled result. Edit, post or cancel that one in Scheduled payouts.');
    send(res,200,wdApply(a.email,b,ipOf(req)))},
  async 'POST /api/admin/withdrawal-schedule'(req,res,url){ // change, cancel or post now a scheduled withdrawal result
    const a=admin(req,url),b=await body(req),j=(db.wdJobs||[]).find(x=>x.id===b.id&&x.status==='scheduled');if(!j)throw fail(404,'That scheduled payout was already posted or cancelled.');
    const t=db.txs.find(x=>x.id===j.b.txId)||{currency:'USD',amount:0},who=(byId(t.userId)||{}).email;
    if(b.cancel){j.status='cancelled';j.doneAt=Date.now();addAudit(a.email,'Scheduled payout cancelled',`${money(t.currency,t.amount)} for ${who}`,ipOf(req));save();pushAdmins('sync',{});return send(res,200,{ok:true})}
    if(b.now){j.status='posting';try{wdApply(j.by,j.b,'');j.status='posted';j.doneAt=Date.now();addAudit(a.email,'Scheduled payout posted early',`${money(t.currency,t.amount)} for ${who}`,ipOf(req))}catch(e){j.status='scheduled';throw e}save();pushAdmins('sync',{});return send(res,200,{ok:true})}
    wdSchedule(a.email,{...(b.data||{}),txId:j.b.txId},j);addAudit(a.email,'Scheduled payout changed',`${money(t.currency,t.amount)} for ${who} at ${new Date(j.at).toISOString().replace('T',' ').slice(0,16)} UTC`,ipOf(req));save();pushAdmins('sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/withdrawal-wallet'(req,res,url){
    const a=admin(req,url),b=await body(req),t=db.txs.find(x=>x.id===b.txId),reason=str(b.reason,300);
    if(!t||t.type!=='withdrawal')throw fail(404,'Withdrawal not found.');
    if(t.status!=='pending')throw fail(400,'Only pending withdrawals can be edited.');
    if(t.d.method==='bank')throw fail(400,'This is a bank withdrawal; there is no wallet to edit.');
    if(reason.length<5)throw fail(400,'Give a reason. It is shown to the customer.');
    const net=(NETS[t.d.asset]||[]).find(n=>n.name===b.network),addr=str(b.address,120);
    if(!net||!net.re.test(addr))throw fail(400,'That address does not match the selected network.');
    const u=byId(t.userId),from={address:t.d.address,network:t.d.network};
    if(from.address===addr&&from.network===net.name)throw fail(400,'Nothing changed.');
    t.d.edits=[...(t.d.edits||[]),{ts:Date.now(),by:a.email,from,reason}];t.d.address=addr;t.d.network=net.name;
    const short=s=>s.length>14?s.slice(0,6)+'…'+s.slice(-4):s;
    notify(u.id,'Withdrawal wallet changed',`Support changed the wallet on your pending ${money(t.currency,t.amount)} withdrawal from ${short(from.address)} (${from.network}) to ${short(addr)} (${net.name}). Reason: ${reason}. If you did not expect this, contact support immediately.`,{noMail:true});
    await mail(u.email,'Withdrawal wallet changed',`Hi ${first(u)},\n\nSupport changed the wallet on your pending withdrawal.\nOld: ${from.address} (${from.network})\nNew: ${addr} (${net.name})\nReason: ${reason}\n\nIf you did not expect this, contact support immediately.\n\n— HarborPay`);
    addAudit(a.email,'Withdrawal wallet edited',`${u.email}: ${short(from.address)} → ${short(addr)} (${net.name}). ${reason}`,ipOf(req));
    save();push(null,'sync',{});send(res,200,{ok:true});
  },
  async 'POST /api/admin/ticket-msg'(req,res,url){ // fix or remove a reply you already sent in a support conversation
    const a=admin(req,url),b=await body(req),t=db.tickets.find(x=>x.id===b.ticketId);if(!t)throw fail(404,'Conversation not found.');
    const m=t.msgs.find(x=>x.from==='admin'&&x.ts===+b.ts);if(!m)throw fail(404,'That reply was not found. Only your own team replies can be changed.');
    if(b.delete){t.msgs=t.msgs.filter(x=>x!==m);t.delTs=[...(t.delTs||[]),m.ts].slice(-50);addAudit(a.email,'Support reply deleted',`${t.subject}: "${str(m.text,120)}"`,ipOf(req))}
    else{const text=str(b.text,5000);if(!text)throw fail(400,'The reply cannot be empty. Delete it instead.');if(text===m.text)return send(res,200,{ok:true,same:true});
      addAudit(a.email,'Support reply edited',`${t.subject}: "${str(m.text,80)}" → "${str(text,80)}"`,ipOf(req));m.orig=m.orig||m.text;m.text=text;m.edited=Date.now()}
    save();push(t.userId,'sync',{});pushAdmins('sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/message'(req,res,url){
    const a=admin(req,url),b=await body(req),title=str(b.title,140),text=str(b.body,5000);
    if(!title||!text)throw fail(400,'Add a subject and a message.');
    if(!b.inApp&&!b.email)throw fail(400,'Pick at least one channel.');
    const targets=b.to==='all'?db.users.filter(u=>u.role==='customer'):db.users.filter(u=>Array.isArray(b.to)&&b.to.includes(u.id));
    if(!targets.length)throw fail(400,'No recipients found.');
    let emailStatus='';const nids=[];
    for(const u of targets){
      if(b.inApp)nids.push(notify(u.id,title,text,{noMail:true}).id);
      if(b.email){const s=await mail(u.email,title,`Hi ${first(u)},\n\n${text}\n\n— HarborPay`);emailStatus=emailStatus==='failed'?'failed':s}
    }
    db.sent.unshift({id:uid('m'),nids,ts:Date.now(),by:a.email,to:b.to==='all'?`All customers (${targets.length})`:targets.map(u=>u.name).join(', '),title,body:text,inApp:!!b.inApp,email:!!b.email,emailStatus});
    addAudit(a.email,'Message sent',`${title} → ${targets.length} user(s)`,ipOf(req));save();send(res,200,{count:targets.length,emailStatus});
  },
  async 'POST /api/admin/deposit-info'(req,res,url){ // Fees / Limits / Speed shown under account details, and the minimum deposit
    const a=admin(req,url),b=await body(req),c=b.currency;
    if(!FIAT.includes(c))throw fail(400,'Unknown currency.');
    const rows=l=>(Array.isArray(l)?l:[]).slice(0,12).map(r=>r&&r[2]?[str(r[0],80),str(r[1],200),1]:[str(r&&r[0],80),str(r&&r[1],200)]).filter(r=>r[0]&&r[1]); // a third item 1 = hidden from customers
    const sh=b.show&&typeof b.show==='object'?b.show:{},show={};for(const k of['min','daily','monthly','third'])show[k]=sh[k]!==false;
    const min=Number(b.minDeposit);if(!(min>0&&isFinite(min)))throw fail(400,'The minimum deposit must be more than zero.');
    if(c!=='USD'&&b.curLimits!==undefined){
      const v=b.curLimits||{},num=k=>v[k]===''||v[k]==null?null:Number(v[k]),d=num('daily'),m=num('monthly'),t=num('thirdParty');
      if(d===null&&m===null&&t===null)delete db.settings.curLimits[c];
      else{
        if(![d,m,t].every(x=>x>0&&isFinite(x)))throw fail(400,`Fill in all three ${c} limits with amounts above zero, or leave all three empty to use the Controls limits.`);
        if(m<d)throw fail(400,'The monthly limit cannot be lower than the daily limit.');
        if(t>d)throw fail(400,'The someone-else limit cannot be higher than the daily limit.');
        db.settings.curLimits[c]={daily:d,monthly:m,thirdParty:t};
      }
    }
    db.settings.minDep[c]=min;db.settings.depositInfo[c]={fees:rows(b.fees),limits:rows(b.limits),speed:rows(b.speed),show};
    addAudit(a.email,'Deposit info changed',`${c}: minimum ${money(c,min)}${db.settings.curLimits[c]?`; limits ${money(c,db.settings.curLimits[c].daily)}/day, ${money(c,db.settings.curLimits[c].monthly)}/month, ${money(c,db.settings.curLimits[c].thirdParty)} someone else`:''}`,ipOf(req));save();push(null,'settings',db.settings);send(res,200,db.settings);
  },
  /* ---- social media links shown on the website ---- */
  async 'POST /api/admin/social'(req,res,url){
    const a=admin(req,url),b=await body(req),out={};
    for(const k of SOCIAL){const v=str(b[k],120);
      if(v&&!/^https:\/\/[^\s<>"']+$/i.test(v)&&!/^@?[\w.+-]{1,60}$/.test(v))throw fail(400,`The ${k==='x'?'X':k} link should be a full https:// address or just the handle.`);
      out[k]=v}
    db.settings.social=out;addAudit(a.email,'Social links changed',SOCIAL.filter(k=>out[k]).join(', ')||'all cleared',ipOf(req));save();push(null,'settings',db.settings);send(res,200,db.settings);
  },
  /* ---- customers can delete their own account ---- */
  async 'POST /api/account/delete'(req,res,url){
    const u=authed(req,url),b=await body(req),ip=ipOf(req);
    if(u.role!=='customer')throw fail(403,'Admin accounts cannot be deleted here.');
    const k='del:'+u.id,t=tries.get(k)||{n:0,at:0};
    if(t.n>=5&&Date.now()-t.at<36e5)throw fail(429,'Too many wrong attempts. Try again in an hour.');
    if(!check(String(b.pass||''),db.creds[u.id])||!pinOk(u,b.pin)){tries.set(k,{n:t.n+1,at:Date.now()});addAudit(u.email,'Failed account deletion','wrong password or PIN',ip);save();throw fail(400,'Your password or PIN is not right.')}
    tries.delete(k);
    if(db.txs.some(x=>x.userId===u.id&&x.status==='pending'))throw fail(400,'You have a deposit or withdrawal still being processed. Wait for it to finish, then try again.');
    const left=ALLC.filter(c=>toUsd(c,u.bal[c]||0)>=0.01);
    if(left.length)throw fail(400,`Your account still holds money (${left.map(c=>money(c,u.bal[c])).join(', ')}). Withdraw it first, then delete your account.`);
    const email=u.email,why=str(b.reason,300);
    u.status='closed';u.closedAt=Date.now();u.closedEmail=email;u.closeReason=why;u.email=`closed-${u.id}@deleted.invalid`;
    delete db.creds[u.id];delete db.totp[u.id];u.twofa=false;delete u.pinHash;delete u.pv;
    for(const x of db.tickets)if(x.userId===u.id)x.status='closed';db.pushSubs=db.pushSubs.filter(x=>x.userId!==u.id);endSessions(u.id);
    addAudit(email,'Account deleted by customer',`${email}${why?': '+why:''}`,ip);
    notifyAdmins('Account deleted',`${u.name} (${email}) deleted their account.${why?' Reason: '+why:''}`,'users');
    for(const[r,c]of clients)if(c.uid===u.id){r.write('event: closed\ndata: {}\n\n')}
    save();pushAdmins('sync',{});send(res,200,{ok:true});
    mail(email,'Your HarborPay account was deleted',`Hi ${first(u)},\n\nYour HarborPay account has been deleted and you can no longer sign in. We keep records of past transactions and identity checks for as long as the law requires.\n\nIf you did not do this, contact us right away.\n\n— HarborPay`).catch(()=>{});
  },
  /* ---- phone number check by text message (needs Twilio; switched off without it) ---- */
  async 'POST /api/phone/send'(req,res,url){
    const u=authed(req,url),b=await body(req),phone=String(b.phone||'').replace(/[\s()-]/g,'');
    const waAny=waBotLinked()||waReady(),ch=b.channel==='sms'?'sms':b.channel==='whatsapp'?'whatsapp':waAny?'whatsapp':'sms';
    if(ch==='whatsapp'&&!waAny){codeTrouble('A customer asked for a WhatsApp code but the WhatsApp bot is not linked.');throw fail(503,"We couldn't send your code right now. Please try again in a few minutes.")}
    if(ch==='sms'&&!smsReady()){codeTrouble('A customer asked for a text message code but text messages are not set up.');throw fail(503,"We couldn't send your code right now. Please try again in a few minutes.")}
    if(!/^\+[1-9]\d{7,14}$/.test(phone))throw fail(400,'Enter your number in international format, starting with + and your country code, for example +447700900123.');
    const now=Date.now(),p=phoneCodes.get(u.id)||{sent:[]};p.sent=(p.sent||[]).filter(x=>now-x<36e5);
    if(p.sent.length&&now-p.sent[p.sent.length-1]<60e3)throw fail(429,'Wait a minute before asking for another code.');
    if(p.sent.length>=5)throw fail(429,'Too many codes sent. Try again in an hour.');
    const code=String(crypto.randomInt(0,1e4)).padStart(4,'0');
    if(ch==='whatsapp'&&waBotLinked())await waBotSend(phone,`*HarborPay* verification code: *${code}*\n\nEnter it in the app to verify this number. It expires in 10 minutes. Never share it with anyone.`);
    else if(ch==='whatsapp')await sendWa(phone,code);else await sendSms(phone,`Your HarborPay code is ${code}. It expires in 10 minutes. Never share it with anyone.`);
    p.sent.push(now);phoneCodes.set(u.id,{...p,phone,hash:hash(code),exp:now+6e5,n:0,ch});
    addAudit(u.email,`Phone code sent by ${ch==='whatsapp'?'WhatsApp':'text message'}`,phone.slice(0,-4).replace(/\d/g,'•')+phone.slice(-4),ipOf(req));save();send(res,200,{ok:true,channel:ch});
  },
  async 'POST /api/phone/verify'(req,res,url){
    const u=authed(req,url),b=await body(req),p=phoneCodes.get(u.id);
    if(!p||!p.hash||Date.now()>p.exp)throw fail(400,'That code has expired. Ask for a new one.');
    if(p.n>=5)throw fail(429,'Too many wrong codes. Ask for a new one.');
    if(!/^\d{4,6}$/.test(String(b.code||''))||!check(String(b.code),p.hash)){p.n++;throw fail(400,`That code is not right. ${5-p.n} ${5-p.n===1?'try':'tries'} left.`)}
    phoneCodes.delete(u.id);u.phone=p.phone;u.pv={status:'verified',phone:p.phone,ts:Date.now(),via:p.ch==='whatsapp'?'whatsapp':'sms'};notify(u.id,'Phone number verified',`Your phone number ${p.phone} is now verified on your HarborPay account. If you did not do this, contact support.`,{view:'profile'});
    addAudit(u.email,'Phone verified',u.email,ipOf(req));save();pushAdmins('sync',{});send(res,200,{ok:true});
  },
  /* ---- support: ask for a person instead of the assistant ---- */
  async 'POST /api/support/human'(req,res,url){
    const u=authed(req,url),b=await body(req),t=db.tickets.find(x=>x.id===b.id&&x.userId===u.id);
    if(!t||t.status!=='open')throw fail(404,'Conversation not found.');
    if(!t.needsHuman){t.needsHuman=true;t.human=true;t.msgs.push({from:'bot',text:'I have passed this conversation to support. A person will reply here, usually within a few hours.',ts:Date.now()});
      notifyAdmins('Customer asked for a person',`${u.name}: ${t.subject}`,'support');addAudit(u.email,'Asked for a person in support',t.subject,ipOf(req));save();push(u.id,'sync',{});pushAdmins('sync',{})}
    send(res,200,{ok:true});
  },
  /* ---- admin credits a deposit that arrived (amount is what the bank statement shows) ---- */
  async 'POST /api/admin/user-delete'(req,res,url){ // close a customer's account, e.g. for suspicious activity; records are kept
    const a=admin(req,url),b=await body(req),u=byId(b.userId),ip=ipOf(req);
    if(!u||u.role!=='customer')throw fail(404,'Customer not found.');if(u.status==='closed')throw fail(400,'This account is already deleted.');
    const why=str(b.reason,300);if(!why)throw fail(400,'Write the reason. Only admins see it.');
    const email=u.email,now=Date.now(),cancelled=[];
    for(const t of db.txs)if(t.userId===u.id&&t.status==='pending'){ // stop anything in progress; withdrawal money goes back to the held balance
      if(t.type==='withdrawal')u.bal[t.currency]=r8((u.bal[t.currency]||0)+t.amount);t.status='rejected';t.note='Account closed';cancelled.push(`${t.type} ${money(t.currency,t.amount)}`)}
    for(const k of db.kycs)if(k.userId===u.id&&k.status==='pending'){k.status='rejected';k.note='Account closed'}
    for(const i of db.invites)if(i.userId===u.id&&['pending','active'].includes(i.status)){i.status='declined';i.note='Account closed'}
    const held=ALLC.filter(c=>(u.bal[c]||0)>0).map(c=>`${c} ${FIAT.includes(c)?money(c,u.bal[c]):+Number(u.bal[c]).toFixed(8)}`);
    u.status='closed';u.closedAt=now;u.closedEmail=email;u.closeReason=why;u.closedBy=a.email;u.heldBal={...u.bal};u.email=`closed-${u.id}@deleted.invalid`;
    delete db.creds[u.id];if(db.totp)delete db.totp[u.id];u.twofa=false;delete u.pinHash;delete u.pv;delete u.bdayWish;
    for(const x of db.tickets)if(x.userId===u.id)x.status='closed';db.pushSubs=db.pushSubs.filter(x=>x.userId!==u.id);
    for(const[r,c]of clients)if(c.uid===u.id){try{r.write('event: closed\ndata: {}\n\n')}catch{}}
    endSessions(u.id);
    if(b.block!==false){if(!db.blocked)db.blocked=[];if(!db.blocked.some(x=>x.email===email.toLowerCase()))db.blocked.unshift({email:email.toLowerCase(),userId:u.id,name:u.name,reason:why,by:a.email,at:now})}
    addAudit(a.email,'Account deleted by admin',`${email}: ${why}${held.length?' | held: '+held.join(', '):''}${cancelled.length?' | cancelled: '+cancelled.join(', '):''}${b.block!==false?' | email blocked':''}`,ip);
    save();push(null,'sync',{});
    if(b.tell!==false)mail(email,'Your HarborPay account has been closed',`Hi ${first(u)},\n\nYour HarborPay account has been closed and you can no longer sign in.\n\nIf you have questions, reply to this email or write to support.\n\n— HarborPay`).catch(()=>{});
    send(res,200,{ok:true,held,cancelled});
  },
  async 'POST /api/admin/unblock'(req,res,url){const a=admin(req,url),b=await body(req),em=str(b.email,120).toLowerCase(),n=(db.blocked||[]).length;
    db.blocked=(db.blocked||[]).filter(x=>x.email!==em);if(db.blocked.length===n)throw fail(404,'That email is not blocked.');
    addAudit(a.email,'Email unblocked',em,ipOf(req));save();push(null,'sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/deposit-reverse'(req,res,url){
    const a=admin(req,url),b=await body(req),t=db.txs.find(x=>x.id===b.txId&&x.type==='deposit');
    if(!t)throw fail(404,'Deposit not found.');
    if(t.status!=='completed')throw fail(400,t.status==='reversed'?'This deposit was already reversed.':'Only a credited (completed) deposit can be reversed.');
    const why=str(b.reason,200);if(!why)throw fail(400,'Write a note for the reversal.');
    const u=needUser(t.userId),cur=t.currency,have=u.bal[cur]||0;
    if(have+1e-9<t.amount)throw fail(400,`${u.name}'s ${cur} balance is only ${money(cur,have)}, less than the ${money(cur,t.amount)} to take back. They may have already spent or withdrawn it.`);
    u.bal[cur]=r8(Math.max(0,have-t.amount));t.status='reversed';t.note='Reversed: '+why;t.d.reversed={by:a.email,at:Date.now(),reason:why,tell:!!b.tell};
    if(!b.tell){const pre=money(cur,t.amount)+' was deposited',gone=n=>n.userId===u.id&&(n.tx===t.id||(!n.tx&&n.title==='Deposit received'&&String(n.body).startsWith(pre)&&Math.abs(n.ts-(t.creditedAt||0))<10000));
      db.notifs=db.notifs.filter(n=>!gone(n))}
    if(b.tell)notify(u.id,'Deposit correction',`A deposit of ${money(cur,t.amount)} on your account was reversed. Reason: ${why}. Your ${cur} balance is now ${money(cur,u.bal[cur])}. Contact support if you have questions.`,{view:'activity'});
    addAudit(a.email,'Deposit reversed',`${money(cur,t.amount)} taken back from ${u.email}${b.tell?' (customer told)':' (silent)'}: ${why}`);
    save();push(u.id,'sync',{});pushAdmins('sync',{});send(res,200,{ok:true,balance:u.bal[cur]});
  },
  async 'POST /api/admin/deposit-credit'(req,res,url){ // record a deposit now, or (with "at") schedule it for a date and time
    const a=admin(req,url),b=await body(req);
    if(b.at&&!b.txId){const j=depSchedule(a.email,b,null);addAudit(a.email,'Deposit scheduled',`${money(j.b.currency,j.b.amount)} for ${(byId(j.b.userId)||{}).email} (${j.b.result||'completed'}) at ${new Date(j.at).toISOString().replace('T',' ').slice(0,16)} UTC`,ipOf(req));save();pushAdmins('sync',{});return send(res,200,{ok:true,scheduled:j.id,at:j.at})}
    send(res,200,depApply(a.email,b,ipOf(req)))},
  async 'POST /api/admin/deposit-schedule'(req,res,url){ // change, cancel or post now a scheduled deposit
    const a=admin(req,url),b=await body(req),j=(db.depJobs||[]).find(x=>x.id===b.id&&x.status==='scheduled');if(!j)throw fail(404,'That scheduled deposit was already posted or cancelled.');
    if(b.cancel){j.status='cancelled';j.doneAt=Date.now();addAudit(a.email,'Scheduled deposit cancelled',`${money(j.b.currency,j.b.amount)} for ${(byId(j.b.userId)||{}).email}`,ipOf(req));save();pushAdmins('sync',{});return send(res,200,{ok:true})}
    if(b.now){j.status='posting';try{const r=depApply(j.by,j.b,'');j.status='posted';j.doneAt=Date.now();j.txId=r.txId;addAudit(a.email,'Scheduled deposit posted early',`${money(j.b.currency,j.b.amount)} for ${(byId(j.b.userId)||{}).email}`,ipOf(req))}catch(e){j.status='scheduled';throw e}save();pushAdmins('sync',{});return send(res,200,{ok:true})}
    depSchedule(a.email,b.data||{},j);addAudit(a.email,'Scheduled deposit changed',`${money(j.b.currency,j.b.amount)} for ${(byId(j.b.userId)||{}).email} at ${new Date(j.at).toISOString().replace('T',' ').slice(0,16)} UTC`,ipOf(req));save();pushAdmins('sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/deposit-details'(req,res,url){ // fix the sender, bank, reference or method on any deposit (and the reason on a failed or declined one)
    const a=admin(req,url),b=await body(req),t=db.txs.find(x=>x.id===b.txId&&x.type==='deposit');if(!t)throw fail(404,'Deposit not found.');
    depInfo(t,b);if(t.status!=='completed'&&'fee' in b){const f=Math.round((+b.fee||0)*100)/100;if(!(f>=0))throw fail(400,'The fee must be 0 or more.');if(f>0)t.d.fee=f;else delete t.d.fee}
    if(t.status==='pending'&&'arrives' in b){const v=String(b.arrives||'');if(/^\d{4}-\d{2}-\d{2}$/.test(v))t.d.arrives=v;else delete t.d.arrives}
    if(['failed','rejected','reversed'].includes(t.status)&&'reason' in b){const r=str(b.reason,200);if(!r)throw fail(400,'The reason cannot be empty.');t.note=r}
    addAudit(a.email,'Deposit details edited',`${money(t.currency,t.amount)} for ${(byId(t.userId)||{}).email}`,ipOf(req));save();push(t.userId,'sync',{});pushAdmins('sync',{});send(res,200,{ok:true})},
  /* ---- withdrawals: the PIN is checked here, on the server ---- */
  async 'POST /api/withdraw'(req,res,url){
    const u=authed(req,url),b=await body(req),ip=ipOf(req),k='pin:'+u.id,t=tries.get(k)||{n:0,at:0};
    if(u.role!=='customer')throw fail(403,'Customers only.');
    if(u.status!=='active')throw fail(403,'Your account cannot withdraw right now.');
    if(t.n>=5&&Date.now()-t.at<15*6e4)throw fail(429,'Too many wrong PINs. Withdrawals are locked for 15 minutes.');
    if(!pinOk(u,b.pin)){const n=(Date.now()-t.at<15*6e4?t.n:0)+1;tries.set(k,{n,at:Date.now()});addAudit(u.email,'Withdrawal blocked: wrong PIN',`${n} of 5`,ip);if(n===3)notify(u.id,'Wrong PIN entered','A wrong PIN was entered 3 times on your HarborPay account. After 5 wrong tries, withdrawals lock for 15 minutes. If this was not you, change your password and PIN now.',{view:'security'});
      if(n===5){notify(u.id,'Withdrawals locked','Someone entered the wrong PIN 5 times. Withdrawals are locked for 15 minutes. If this was not you, change your password and PIN now.');notifyAdmins('Wrong PIN 5 times',`${u.name} (${u.email}): withdrawals locked for 15 minutes.`,'activity')}
      save();throw fail(n>=5?429:400,n>=5?'Too many wrong PINs. Withdrawals are locked for 15 minutes.':`Wrong PIN. ${5-n} ${5-n===1?'try':'tries'} left.`)}
    tries.delete(k);
    const tx={...(b.tx||{}),type:'withdrawal'},before=db.txs.length;addTx(u,tx);
    if(db.txs.length===before)throw fail(400,'The withdrawal could not be created.');
    const nt=db.txs[0],hold=wdSafety(u,nt);addAudit(u.email,nt.d.method==='bank'?'Bank withdrawal requested':'Withdrawal requested',`${money(nt.currency,nt.amount)}${nt.d.method==='bank'?' to '+bankDest(nt.d):' to '+nt.d.asset+' on '+nt.d.network}`,ip);
    notify(u.id,'Withdrawal request received',`We received your withdrawal of ${money(nt.currency,nt.amount)}${nt.d.method==='bank'?' to '+bankDest(nt.d):' to your '+nt.d.asset+' wallet on '+nt.d.network}. It is pending and will be reviewed. You will be notified when it is sent.${hold?` For your safety, this ${hold.why.join(' and ')} has an extra ${hold.hours}-hour check before it is sent. If you did not ask for it, contact support straight away.`:''}`,{view:'transactions',tx:nt.id});
    if(hold)notifyAdmins('Withdrawal on safety hold',`${u.name}: ${money(nt.currency,nt.amount)} (${hold.why.join(', ')}). It can be sent after ${new Date(hold.until).toUTCString().slice(5,22)} UTC.`,'withdrawals');
    save();pushAdmins('sync',{});send(res,200,{ok:true,id:nt.id,hold:hold||undefined});
  },
  /* ---- invite codes ---- */
  async 'POST /api/referral/request'(req,res,url){const u=authed(req,url);if(u.role!=='customer'||u.status!=='active')throw fail(400,'Only for customers.');
    const d0=new Date();d0.setUTCHours(0,0,0,0);const mine=db.invites.filter(i=>i.userId===u.id);
    if(mine.some(i=>i.status==='pending'))throw fail(400,'Your last request is still waiting for approval.');
    if(mine.filter(i=>i.reqAt>=d0.getTime()).length>=INV_PER_DAY)throw fail(429,`You can ask for ${INV_PER_DAY} codes a day. Try again tomorrow.`);
    const i={id:uid('iv'),userId:u.id,status:'pending',reqAt:Date.now()};db.invites.unshift(i);if(db.invites.length>5000)db.invites.length=5000;
    addAudit(u.email,'Invite code requested',u.email,ipOf(req));notifyAdmins('Invite code request',`${u.name} asked for an invite code.`,'referrals');save();pushAdmins('sync',{});push(u.id,'sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/invite'(req,res,url){const a=admin(req,url),b=await body(req);let i;
    if(b.id){i=db.invites.find(x=>x.id===b.id);if(!i||i.status!=='pending')throw fail(404,'That request was already handled.')}
    else{const u=byId(b.userId);if(!u||u.role!=='customer'||u.status!=='active')throw fail(404,'Customer not found.');i={id:uid('iv'),userId:u.id,reqAt:Date.now(),byAdmin:true};db.invites.unshift(i)}
    const u=byId(i.userId);if(!u||u.status!=='active'){i.status='declined';save();throw fail(400,'That customer can no longer invite people.')}
    if(b.decline){i.status='declined';i.note=str(b.note,200);i.okAt=Date.now();i.by=a.email;
      notify(u.id,'Invite code request',`Your request for an invite code was not approved${i.note?': '+i.note:'.'}`,{noMail:true,view:'referral'});addAudit(a.email,'Invite code declined',u.email+(i.note?` (${i.note})`:''),ipOf(req))}
    else{i.code=newInvCode();i.status='active';i.okAt=Date.now();i.exp=i.okAt+INV_TTL;i.by=a.email;
      notify(u.id,'Your invite code is ready 🎉',`Your invite code is ${i.code}. It works for one sign-up and expires 1 hour from now. Share it straight away from your Referral page.`,{view:'referral'});
      addAudit(a.email,'Invite code approved',`${u.email}: ${i.code}`,ipOf(req))}
    save();push(null,'sync',{});send(res,200,{ok:true,code:i.code||''})},
  /* ---- notifications: delete one or clear all ---- */
  async 'POST /api/notifs/delete'(req,res,url){const u=authed(req,url),b=await body(req),n=db.notifs.length;
    db.notifs=db.notifs.filter(x=>!(x.userId===u.id&&(b.all||x.id===b.id)));save();send(res,200,{ok:true,removed:n-db.notifs.length})},
  /* ---- customers who verified before the date of birth question: they send it, the admin confirms it against the ID on file ---- */
  async 'POST /api/me/dob'(req,res,url){const u=authed(req,url),b=await body(req);if(u.role!=='customer')throw fail(400,'Only for customers.');
    if(u.dob)throw fail(400,'Your date of birth is already on your account. Contact support to change it.');
    const dob=String(b.dob||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(dob)||isNaN(Date.parse(dob+'T00:00:00Z'))||new Date(dob+'T00:00:00Z').toISOString().slice(0,10)!==dob)throw fail(400,'Enter your date of birth.');
    const age=ageOn(dob,new Date());if(age<18)throw fail(400,'You must be 18 or older to use HarborPay.');if(age>120)throw fail(400,'Check your date of birth.');
    u.dobPending={dob,ts:Date.now()};addAudit(u.email,'Date of birth sent for confirmation',dob,ipOf(req));
    notifyAdmins('Date of birth to confirm',`${u.name} added their date of birth. Check it against their ID in Birthdays.`,'birthdays');save();pushAdmins('sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/dob-review'(req,res,url){const a=admin(req,url),b=await body(req),u=byId(b.userId);if(!u||!u.dobPending)throw fail(404,'Nothing waiting for this customer.');
    const p=u.dobPending;delete u.dobPending;
    if(b.ok){u.dob=p.dob;u.bday=p.dob.slice(5);notify(u.id,'Date of birth confirmed','Thank you. Your date of birth is now on your account.',{noMail:true});addAudit(a.email,'Date of birth confirmed',`${u.email}: ${p.dob}`,ipOf(req))}
    else{const why=str(b.note,200);notify(u.id,'Please check your date of birth',`The date you sent does not match your ID${why?': '+why:''}. Please send it again from your dashboard.`,{noMail:true});addAudit(a.email,'Date of birth declined',`${u.email}: ${p.dob}${why?' ('+why+')':''}`,ipOf(req))}
    save();push(null,'sync',{});send(res,200,{ok:true})},
  /* ---- admin: birthdays and per-customer reminders ---- */
  async 'POST /api/admin/user-dob'(req,res,url){const a=admin(req,url),b=await body(req),u=byId(b.userId);if(!u||u.role!=='customer')throw fail(404,'Customer not found.');
    const dob=String(b.dob||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(dob)||isNaN(Date.parse(dob+'T00:00:00Z'))||new Date(dob+'T00:00:00Z').toISOString().slice(0,10)!==dob)throw fail(400,'Enter a valid date of birth.');
    const old=u.dob;u.dob=dob;u.bday=dob.slice(5);delete u.dobPending;addAudit(a.email,'Date of birth changed',`${u.email}: ${old||'none'} → ${dob}`,ipOf(req));save();push(null,'sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/user-reminders'(req,res,url){const a=admin(req,url),b=await body(req),u=byId(b.userId);if(!u||u.role!=='customer')throw fail(404,'Customer not found.');
    u.reminders=!!b.on;addAudit(a.email,`Reminders ${b.on?'on':'off'} for a customer`,u.email,ipOf(req));save();push(null,'sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/bday-wish'(req,res,url){const a=admin(req,url),b=await body(req),u=byId(b.userId);if(!u||u.role!=='customer'||u.status!=='active')throw fail(404,'Customer not found.');
    if(b.mode==='cancel'){delete u.bdayWish;addAudit(a.email,'Birthday wish cancelled',u.email,ipOf(req));save();push(null,'sync',{});return send(res,200,{ok:true})}
    const title=str(b.title,120),text=str(b.body,600);if(!title||!text)throw fail(400,'Write a title and a message.');
    if(!u.dob)throw fail(400,'Add this customer\'s date of birth first.');
    const now=new Date(),yr=now.getUTCFullYear();
    if(b.mode==='now'){sendWish(u,{year:yr,title,body:text});addAudit(a.email,'Birthday wish sent',u.email,ipOf(req))}
    else{const nb=nextBday(u,now);u.bdayWish={year:nb.getUTCFullYear(),title,body:text,status:'approved',by:a.email,ts:Date.now()};addAudit(a.email,'Birthday wish approved',`${u.email} for ${nb.toISOString().slice(0,10)}`,ipOf(req));
      if(bdayToday(u,now)&&now.getUTCHours()>=7)sendWish(u,u.bdayWish)}
    save();push(null,'sync',{});send(res,200,{ok:true,wish:u.bdayWish})},
  /* ---- admin: automatic messages ---- */
  async 'POST /api/admin/auto'(req,res,url){const a=admin(req,url),b=await body(req),A=db.settings.auto;
    if(b.bday){const x=b.bday;A.bday={on:true,email:!!x.email,title:str(x.title,120)||AUTO_DEF.bday.title,body:str(x.body,600)||AUTO_DEF.bday.body}}
    if(b.nudge){const x=b.nudge,ev=Math.round(+x.every);if(!(ev>=1&&ev<=60))throw fail(400,'Send reminders every 1 to 60 days.');
      const msgs=(Array.isArray(x.msgs)?x.msgs:[]).slice(0,20).map(m=>m&&m[2]?[str(m[0],120),str(m[1],600),1]:[str(m&&m[0],120),str(m&&m[1],600)]).filter(m=>m[0]&&m[1]);
      if(x.on&&!msgs.some(m=>!m[2]))throw fail(400,'Tick at least one reminder message, or switch reminders off.');
      A.nudge={on:!!x.on,email:!!x.email,every:ev,who:x.who==='all'?'all':'quiet',msgs}}
    addAudit(a.email,'Automatic messages changed',`reminders ${A.nudge.on?'on every '+A.nudge.every+' days':'off'}`,ipOf(req));save();push(null,'settings',db.settings);send(res,200,db.settings)},
  async 'POST /api/admin/stage'(req,res,url){const a=admin(req,url),b=await body(req),G=db.settings.auto.stage,num=(v,lo,hi,d)=>{v=Math.round(+v);return v>=lo&&v<=hi?v:d};
    const msg=(k,x)=>{x=x||{};const m={on:!!x.on,title:str(x.title,120),body:str(x.body,600)};if(k!=='welcome')m.after=num(x.after,0,60,G[k].after);if(m.on&&(!m.title||!m.body))throw fail(400,'Each message that is switched on needs a title and a message.');return m};
    db.settings.auto.stage={on:!!b.on,email:!!b.email,every:num(b.every,1,60,G.every),max:num(b.max,1,10,G.max),welcome:msg('welcome',b.welcome),kyc:msg('kyc',b.kyc),dep:msg('dep',b.dep)};
    addAudit(a.email,'Getting-started messages changed',b.on?'on':'off',ipOf(req));save();push(null,'settings',db.settings);send(res,200,db.settings)},
  async 'POST /api/admin/stage/test'(req,res,url){const a=admin(req,url),b=await body(req),M=db.settings.auto.stage[b.k];if(!M||!M.title)throw fail(400,'Write that message first.');
    notify(a.id,'[Test] '+fillMsg(M.title,a),fillMsg(M.body,a),{noMail:true});send(res,200,{ok:true})},
  async 'POST /api/admin/ref-reward'(req,res,url){const a=admin(req,url),b=await body(req),R=db.settings.refReward,amt=Math.round(+b.amount*100)/100,min=Math.round(+b.minUsd*100)/100;
    if(!(amt>0&&amt<=1000))throw fail(400,'The reward must be more than 0 and at most 1,000.');if(!(min>=0&&min<=1e6))throw fail(400,'Enter the minimum deposit in USD (0 for any amount).');
    if(!FIAT.includes(b.currency))throw fail(400,'Choose USD, EUR, GBP, MXN or COP.');
    db.settings.refReward={on:!!b.on,amount:amt,currency:b.currency,minUsd:min,both:!!b.both,mode:b.mode==='auto'?'auto':'approve'};
    addAudit(a.email,'Referral reward changed',b.on?`${money(b.currency,amt)} ${b.both?'each to both':'to the inviter'} after a deposit of $${min}+`:'off',ipOf(req));save();push(null,'settings',db.settings);const found=refScan();send(res,200,{...db.settings,found})},
  async 'POST /api/admin/ref-reward/decide'(req,res,url){const a=admin(req,url),b=await body(req),f=byId(b.userId);
    if(!f||!f.refPending)throw fail(400,'There is no reward waiting for this customer.');
    if(b.ok){refPay(f,a.email)}
    else{const why=str(b.note,200);delete f.refPending;f.refRewarded={declined:true,at:Date.now(),by:a.email,note:why};addAudit(a.email,'Referral reward declined',f.email+(why?': '+why:''),ipOf(req))}
    save();push(null,'sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/auto/send'(req,res,url){const a=admin(req,url),b=await body(req),A=db.settings.auto.nudge,m=(A.msgs||[])[+b.i];
    if(!m||!m[0]||!m[1])throw fail(400,'That reminder was not found. Save your changes first.');
    const email=typeof b.email==='boolean'?b.email:!!A.email,now=Date.now();
    let L=b.userId?[byId(b.userId)].filter(u=>u&&u.role==='customer'&&u.status==='active'):db.users.filter(u=>u.role==='customer'&&u.status==='active'&&u.reminders!==false);
    if(!L.length)throw fail(400,b.userId?'That customer is not active.':'No customers to send to.');
    for(const u of L){notify(u.id,fillMsg(m[0],u),fillMsg(m[1],u),{noMail:!email,kind:'reminder'});u.lastNudge=now}
    db.sent.unshift({id:uid('m'),ts:now,by:a.email,to:b.userId?L[0].name:`All customers (${L.length})`,title:m[0],body:m[1],inApp:true,email,emailStatus:''});
    addAudit(a.email,'Reminder sent now',`"${m[0]}" → ${L.length} customer${L.length>1?'s':''}${email?' (app and email)':' (app)'}`,ipOf(req));save();push(null,'sync',{});send(res,200,{count:L.length})},
  async 'POST /api/admin/auto/test'(req,res,url){const a=admin(req,url),b=await body(req),A=db.settings.auto;
    if(b.kind==='bday')notify(a.id,'[Test] '+fillMsg(A.bday.title,a),fillMsg(A.bday.body,a),{noMail:true});
    else{const m=(A.nudge.msgs||[]).filter(m=>!m[2])[+b.i||0]||A.nudge.msgs[0];if(!m)throw fail(400,'Add a reminder message first.');notify(a.id,'[Test] '+fillMsg(m[0],a),fillMsg(m[1],a),{noMail:true})}
    send(res,200,{ok:true})},
  /* ---- signed-in devices ---- */
  async 'GET /api/sessions'(req,res,url){const u=authed(req,url);send(res,200,{sessions:db.sessions.filter(x=>x.userId===u.id).sort((a,b)=>(b.id===req.sid)-(a.id===req.sid)||b.lastSeen-a.lastSeen).map(x=>({id:x.id,device:x.device,ip:x.ip,created:x.created,lastSeen:x.lastSeen,current:x.id===req.sid,alerts:(db.pushSubs||[]).some(p=>p.sid===x.id)}))})},
  async 'POST /api/sessions/revoke'(req,res,url){const u=authed(req,url),b=await body(req),s=db.sessions.find(x=>x.id===b.id&&x.userId===u.id);
    if(!s)throw fail(404,'That device is already signed out.');if(s.id===req.sid)throw fail(400,'Use Sign out to sign out of this device.');
    db.sessions=db.sessions.filter(x=>x!==s);db.pushSubs=(db.pushSubs||[]).filter(p=>p.sid!==s.id);
    for(const[r2,c]of clients)if(c.sid===s.id){try{r2.write(`event: signedout\ndata: {}\n\n`);r2.end()}catch{}clients.delete(r2)}
    addAudit(u.email,'Signed out a device',s.device+' · '+s.ip,ipOf(req));save();send(res,200,{ok:true})},
  async 'POST /api/sessions/revoke-others'(req,res,url){const u=authed(req,url),n=endSessions(u.id,req.sid);if(n)addAudit(u.email,'Signed out all other devices',`${n} device${n>1?'s':''}`,ipOf(req));send(res,200,{ok:true,count:n})},
  async 'POST /api/logout'(req,res,url){let u;try{u=authed(req,url)}catch{return send(res,200,{ok:true})}db.sessions=db.sessions.filter(x=>x.id!==req.sid);db.pushSubs=(db.pushSubs||[]).filter(p=>p.sid!==req.sid);save();send(res,200,{ok:true})},
  /* ---- phone / computer alerts ---- */
  async 'GET /api/push/key'(req,res){send(res,200,{key:vapidKeys().pub})},
  async 'POST /api/push/subscribe'(req,res,url){
    const u=authed(req,url),b=await body(req),s=b.sub;if(!pushOk(s))throw fail(400,'That device could not be set up for alerts.');
    db.pushSubs=db.pushSubs.filter(x=>x.endpoint!==s.endpoint);
    if(db.pushSubs.filter(x=>x.userId===u.id).length>=10)db.pushSubs.splice(db.pushSubs.findIndex(x=>x.userId===u.id),1); // up to 10 devices per person
    db.pushSubs.push({userId:u.id,sid:req.sid,endpoint:s.endpoint,keys:{p256dh:s.keys.p256dh,auth:s.keys.auth},device:str(b.device,60),ts:Date.now()});
    addAudit(u.email,'Phone / computer alerts turned on',str(b.device,60)||'a device',ipOf(req));save();
    let result=null;if(b.test!==false){const r=await pushTo(u.id,'Alerts are on','You will get a pop-up here for deposits, withdrawals, ID checks and messages.','/').catch(()=>[]);result=r.find(x=>x.device===(str(b.device,60)||'a device'))||r[r.length-1]||null}
    send(res,200,{ok:true,devices:db.pushSubs.filter(x=>x.userId===u.id).length,result})},
  async 'POST /api/push/unsubscribe'(req,res,url){
    const u=authed(req,url),b=await body(req),n=db.pushSubs.length;
    db.pushSubs=db.pushSubs.filter(x=>!(x.userId===u.id&&(b.all||x.endpoint===b.endpoint)));
    if(db.pushSubs.length!==n){addAudit(u.email,'Phone / computer alerts turned off',b.all?'all devices':'this device',ipOf(req));save()}
    send(res,200,{ok:true,devices:db.pushSubs.filter(x=>x.userId===u.id).length})},
  async 'POST /api/push/test'(req,res,url){const u=authed(req,url);if(!db.pushSubs.some(x=>x.userId===u.id))throw fail(400,'Turn on alerts on this device first.');const r=await pushTo(u.id,'Test alert','This is how HarborPay alerts look on this device.','/');send(res,200,{ok:r.some(x=>x.ok),results:r})},
  /* ---- forgot PIN: password + a code by email (or Google Authenticator), then a new PIN; withdrawals pause for 24 hours ---- */
  /* ---- customers change their own email: password, then a 4-digit code sent to the NEW address ---- */
  async 'POST /api/email/change/start'(req,res,url){const u=authed(req,url),b=await body(req),k='emchg:'+u.id,t=tries.get(k)||{n:0,at:0};
    if(u.role!=='customer')throw fail(403,'Customers only.');
    if(t.n>=5&&Date.now()-t.at<36e5)throw fail(429,'Too many wrong attempts. Try again in an hour.');
    if(!check(String(b.pass||''),db.creds[u.id])){tries.set(k,{n:t.n+1,at:Date.now()});addAudit(u.email,'Failed email change','wrong password',ipOf(req));save();throw fail(400,'That password is not right.')}
    const to=str(b.email,120).toLowerCase();if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(to))throw fail(400,'Enter a valid email address.');
    if(to===u.email.toLowerCase())throw fail(400,'That is already your email.');
    if(db.users.some(x=>x.id!==u.id&&x.email.toLowerCase()===to)||(db.blocked||[]).some(x=>x.email===to))throw fail(409,'That email cannot be used. Try another one.');
    if(u.emailChange&&u.emailChange.sent>Date.now()-6e4)throw fail(429,'A code was just sent. Wait a minute before asking for another.');
    const code=String(crypto.randomInt(0,1e4)).padStart(4,'0');u.emailChange={to,h:hash(code),exp:Date.now()+6e5,n:0,sent:Date.now()};save();
    const st=await mail(to,'Your HarborPay email change code',`Hi ${first(u)},\n\nYour code to change your HarborPay email to this address is ${code}. It expires in 10 minutes.\n\nIf you did not ask for this, ignore this email.\n\n— HarborPay`).catch(()=>'failed');
    if(st!=='sent'&&st!=='logged'){delete u.emailChange;save();throw fail(502,'We could not send the code to that address right now. Check it and try again later.')}
    addAudit(u.email,'Email change code sent',`to ${to}`,ipOf(req));send(res,200,{to})},
  async 'POST /api/email/change/finish'(req,res,url){const u=authed(req,url),b=await body(req),r=u.emailChange;
    if(!r||r.exp<Date.now()){delete u.emailChange;save();throw fail(400,'That code has expired. Ask for a new one.')}
    if(!check(String(b.code||'').trim(),r.h)){r.n=(r.n||0)+1;if(r.n>=5)delete u.emailChange;save();throw fail(400,r.n>=5?'Too many wrong codes. Start again.':'That code is not right.')}
    if(db.users.some(x=>x.id!==u.id&&x.email.toLowerCase()===r.to)){delete u.emailChange;save();throw fail(409,'That email cannot be used. Try another one.')}
    const old=u.email;u.email=r.to;u.ev={status:'verified',ts:Date.now()};delete u.emailChange;
    addAudit(u.email,'Email changed by customer',`${old} → ${u.email}`,ipOf(req));
    notify(u.id,'Your email was successfully updated ✅',`Your HarborPay email is now ${u.email}. Use it to sign in from now on. Your password and PIN have not changed.`);
    mail(old,'Your HarborPay email was changed',`Hi ${first(u)},\n\nThe email on your HarborPay account was successfully changed to ${u.email}. From now on, sign in with it. Emails about your account will go there.\n\nIf you did not do this, contact support right away.\n\n— HarborPay`).catch(()=>{});
    notifyAdmins('Customer changed their email',`${u.name}: ${old} → ${u.email}`,'users');
    save();push(u.id,'sync',{});pushAdmins('sync',{});send(res,200,{ok:true,email:u.email})},
  async 'POST /api/pin/forgot/start'(req,res,url){const u=authed(req,url),b=await body(req),k='pinfg:'+u.id,t=tries.get(k)||{n:0,at:0};
    if(t.n>=5&&Date.now()-t.at<36e5)throw fail(429,'Too many wrong attempts. Try again in an hour.');
    if(!check(String(b.pass||''),db.creds[u.id])){tries.set(k,{n:t.n+1,at:Date.now()});addAudit(u.email,'Failed PIN reset','wrong password',ipOf(req));save();throw fail(400,'That password is not right.')}
    if(b.method==='totp'&&db.totp[u.id])return send(res,200,{method:'totp'});
    if(u.pinReset&&u.pinReset.sent>Date.now()-6e4)throw fail(429,'A code was just sent. Wait a minute before asking for another.');
    const code=String(crypto.randomInt(0,1e4)).padStart(4,'0');u.pinReset={h:hash(code),exp:Date.now()+6e5,n:0,sent:Date.now()};save();
    const st=await mail(u.email,'Your HarborPay PIN reset code',`Hi ${first(u)},\n\nYour code to reset your transaction PIN is ${code}. It expires in 10 minutes.\n\nIf you did not ask for this, change your password straight away and contact support.\n\n— HarborPay`).catch(()=>'failed');
    if(st!=='sent'&&st!=='logged'){delete u.pinReset;save();addAudit(u.email,'PIN reset code email failed',`${u.email}: ${st}`,ipOf(req));notifyAdmins('PIN reset email failed',`${u.name} (${u.email}) asked for a PIN reset code but the email could not be sent (${st}). Check Controls → Email delivery, or change their PIN for them from Users.`,'controls');
      throw fail(502,db.totp[u.id]?'We could not send the code email right now. Use your Google Authenticator code instead, or try again later.':'We could not send the code email right now. Please try again later or contact support, and we can reset your PIN for you.')}
    addAudit(u.email,'PIN reset code sent',u.email,ipOf(req));
    const [nm,dom]=u.email.split('@');send(res,200,{method:'email',to:nm.slice(0,2)+'•••@'+dom,authApp:!!db.totp[u.id],mail:st})},
  async 'POST /api/pin/forgot/finish'(req,res,url){const u=authed(req,url),b=await body(req),k='pinfg:'+u.id,t=tries.get(k)||{n:0,at:0};
    if(t.n>=5&&Date.now()-t.at<36e5)throw fail(429,'Too many wrong attempts. Try again in an hour.');
    const bad=m=>{tries.set(k,{n:t.n+1,at:Date.now()});addAudit(u.email,'Failed PIN reset',m,ipOf(req));save();return fail(400,m)};
    if(!check(String(b.pass||''),db.creds[u.id]))throw bad('That password is not right.');
    if(b.method==='totp'){if(!db.totp[u.id]||!totpOk(db.totp[u.id],b.code))throw bad('That authenticator code is not right.')}
    else{const r=u.pinReset;if(!r||r.exp<Date.now())throw fail(400,'That code has expired. Ask for a new one.');
      if(!check(String(b.code||'').trim(),r.h)){r.n=(r.n||0)+1;if(r.n>=5)delete u.pinReset;throw bad(r.n>=5?'Too many wrong codes. Ask for a new one.':'That code is not right.')}}
    const p=String(b.new||'');if(!/^\d{4}$/.test(p))throw fail(400,'The new PIN must be exactly 4 digits.');if(['0000','1111','1234','4321'].includes(p))throw fail(400,'That PIN is too easy to guess. Choose another.');
    tries.delete(k);delete u.pinReset;u.pinHash=hash(p);u.wdHold=Date.now()+864e5;
    addAudit(u.email,'Transaction PIN reset (forgot PIN)',`${b.method==='totp'?'authenticator':'email code'}; withdrawals paused 24 hours`,ipOf(req));
    notify(u.id,'Your PIN was reset',`Your transaction PIN was reset. For your safety, withdrawals are paused for 24 hours. If this wasn't you, contact support straight away.`);
    notifyAdmins('PIN reset by customer',`${u.name} reset their transaction PIN. Withdrawals are paused for 24 hours.`,'users');save();push(u.id,'sync',{});send(res,200,{ok:true,hold:u.wdHold})},
  /* ---- admin: change a customer's PIN when they ask support ---- */
  async 'POST /api/admin/user-pin'(req,res,url){const a=admin(req,url),b=await body(req),u=byId(b.userId);if(!u||u.role!=='customer'||u.status==='closed')throw fail(404,'Customer not found.');
    const p=String(b.pin||'');if(!/^\d{4}$/.test(p))throw fail(400,'The PIN must be exactly 4 digits.');if(['0000','1111','1234','4321'].includes(p))throw fail(400,'That PIN is too easy to guess. Choose another.');
    u.pinHash=hash(p);delete u.pinReset;if(b.hold!==false)u.wdHold=Date.now()+864e5;
    addAudit(a.email,'Transaction PIN changed by admin',`${u.email}${b.hold!==false?'; withdrawals paused 24 hours':''}`,ipOf(req));
    notify(u.id,'Your PIN was changed by support',`Support changed your transaction PIN as you asked.${b.hold!==false?' For your safety, withdrawals are paused for 24 hours.':''} If you did not ask for this, contact support straight away.`);
    save();push(null,'sync',{});send(res,200,{ok:true})},
  async 'POST /api/admin/user-hold'(req,res,url){const a=admin(req,url),b=await body(req),u=byId(b.userId);if(!u)throw fail(404,'Customer not found.');
    delete u.wdHold;addAudit(a.email,'Withdrawal pause lifted',u.email,ipOf(req));notify(u.id,'Withdrawals are open again','You can withdraw again.',{noMail:true});save();push(null,'sync',{});send(res,200,{ok:true})},
  async 'POST /api/pin/change/start'(req,res,url){const u=authed(req,url),b=await body(req);if(u.role!=='customer')throw fail(403,'Customers only.');
    if(b.method==='totp'){if(!db.totp[u.id])throw fail(400,'Google Authenticator is not set up on your account. Use the email code instead.');return send(res,200,{method:'totp'})}
    if(u.pinChange&&u.pinChange.sent>Date.now()-6e4)throw fail(429,'A code was just sent. Wait a minute before asking for another.');
    const code=String(crypto.randomInt(0,1e4)).padStart(4,'0');u.pinChange={h:hash(code),exp:Date.now()+6e5,n:0,sent:Date.now()};save();
    const st=await mail(u.email,'Your HarborPay PIN change code',`Hi ${first(u)},\n\nYour code to change your transaction PIN is ${code}. It expires in 10 minutes.\n\nIf you did not ask for this, change your password straight away and contact support.\n\n— HarborPay`).catch(()=>'failed');
    if(st!=='sent'&&st!=='logged'){delete u.pinChange;save();throw fail(502,db.totp[u.id]?'We could not send the code email right now. Use Google Authenticator instead, or try again later.':'We could not send the code email right now. Please try again later or contact support.')}
    const [nm,dom]=u.email.split('@');addAudit(u.email,'PIN change code sent',u.email,ipOf(req));send(res,200,{method:'email',to:nm.slice(0,2)+'•••@'+dom,authApp:!!db.totp[u.id]})},
  async 'POST /api/pin'(req,res,url){
    const u=authed(req,url),b=await body(req),k='pinchg:'+u.id,t=tries.get(k)||{n:0,at:0};
    if(t.n>=5&&Date.now()-t.at<36e5)throw fail(429,'Too many wrong attempts. Try again in an hour.');
    if(!pinOk(u,b.old)){tries.set(k,{n:t.n+1,at:Date.now()});throw fail(400,'Your current PIN is not right.')}
    if(!/^\d{4}$/.test(String(b.new||'')))throw fail(400,'The new PIN must be exactly 4 digits.');
    if(u.role==='customer'){ // confirm with the 4-digit email code or Google Authenticator
      if(b.method==='totp'){if(!db.totp[u.id]||!totpOk(db.totp[u.id],b.code)){tries.set(k,{n:t.n+1,at:Date.now()});throw fail(400,'That authenticator code is not right. Enter the 6 digits the app shows now.')}}
      else{const r=u.pinChange;if(!r||r.exp<Date.now()){delete u.pinChange;throw fail(400,'Ask for a code first, or the code has expired. Tap "Send code" again.')}
        if(!check(String(b.code||'').trim(),r.h)){r.n=(r.n||0)+1;if(r.n>=5)delete u.pinChange;save();throw fail(400,r.n>=5?'Too many wrong codes. Ask for a new one.':'That code is not right.')}}
      delete u.pinChange}
    tries.delete(k);u.pinHash=hash(String(b.new));addAudit(u.email,'Transaction PIN changed',u.email,ipOf(req));
    notify(u.id,'Your PIN was changed','Your transaction PIN was just changed. If this was not you, contact support right away.');save();send(res,200,{ok:true});
  },
  async 'POST /api/inbound/resend'(req,res){
    const raw=await rawBody(req);
    if(!process.env.RESEND_WEBHOOK_SECRET||!process.env.RESEND_API_KEY)throw fail(503,'Email replies are not set up.');
    if(!svixOk(raw,req.headers,process.env.RESEND_WEBHOOK_SECRET))throw fail(401,'Invalid signature');
    const ev=JSON.parse(raw||'{}'),id=ev.data&&ev.data.email_id;send(res,200,{ok:true});
    if(ev.type!=='email.received'||!id||seenInbound.has(id))return;seenInbound.add(id);if(seenInbound.size>2000)seenInbound.clear();
    takeInbound(id).catch(e=>console.error('inbound email:',e.message));
  },
  /* ---- card waitlist ---- */
  async 'POST /api/cards/waitlist'(req,res,url){
    const u=authed(req,url);
    if(!u.cardWaitlist){u.cardWaitlist=Date.now();addAudit(u.email,'Joined the card waitlist',u.email,ipOf(req));notifyAdmins('Card waitlist',`${u.name} (${u.email}) joined the card waitlist.`,'users');save();pushAdmins('sync',{})}
    send(res,200,{joined:u.cardWaitlist});
  },
  async 'POST /api/admin/settings'(req,res,url){
    const a=admin(req,url),b=await body(req),s=db.settings,pos=v=>typeof v==='number'&&isFinite(v)&&v>0;
    if(typeof b.fee==='number'&&b.fee>=0&&b.fee<=0.05)s.fee=b.fee;
    if(['pct','flat'].includes(b.feeMode))s.feeMode=b.feeMode;
    if('feeFlat' in b){const f=Math.round(+b.feeFlat*100)/100;if(!(f>=0&&f<=1000))throw fail(400,'The fixed fee must be from $0 to $1,000.');s.feeFlat=f}
    if(b.fees&&typeof b.fees==='object'){feeSetup();const nf={};for(const c of FIAT){const x=b.fees[c]||s.fees[c],mode=x.mode==='flat'?'flat':'pct',pct=Math.round(+x.pct*1e6)/1e6,flat=Math.round(+x.flat*100)/100;
        if(!(pct>=0&&pct<=0.1))throw fail(400,`The ${c} percentage must be from 0% to 10%.`);if(!(flat>=0&&toUsd(c,flat)<=1000))throw fail(400,`The ${c} fixed fee must be from 0 to the same as $1,000.`);nf[c]={mode,pct,flat}}
      s.fees=nf}
    else if(typeof b.fee==='number'||b.feeMode||'feeFlat' in b){feeSetup();for(const c of FIAT){const f=s.fees[c];if(typeof b.fee==='number'&&b.fee>=0&&b.fee<=0.05)f.pct=b.fee;if(b.feeMode==='pct'||b.feeMode==='flat')f.mode=b.feeMode;if(b.feeMode==='flat'&&'feeFlat' in b)f.flat=Math.round(s.feeFlat/rate(c)*100)/100}}
    if('registrations' in b)s.registrations=!!b.registrations;if('withdrawalsPaused' in b)s.withdrawalsPaused=!!b.withdrawalsPaused;
    if('bot' in b)s.bot=!!b.bot;if('emailCustomers' in b)s.emailCustomers=!!b.emailCustomers;if('adminAlerts' in b)s.adminAlerts=!!b.adminAlerts;if('customerInApp' in b)s.customerInApp=!!b.customerInApp;if(b.adminNotif&&typeof b.adminNotif==='object'){const o={};for(const k of['location','security','money','checks','support','customers','system']){const x=b.adminNotif[k];if(x)o[k]={app:!!x.app,mail:!!x.mail}}s.adminNotif=o}
    for(const k of['daily','monthly','thirdParty'])if(b.limits&&pos(b.limits[k]))s.limits[k]=b.limits[k];
    if(b.limOn&&typeof b.limOn==='object'){s.limOn=s.limOn||{};for(const k of['daily','monthly','thirdParty'])if(k in b.limOn)s.limOn[k]=!!b.limOn[k]}
    if(b.curLim&&typeof b.curLim==='object'){const nl={};for(const c of ALLC){const x=b.curLim[c];if(!x)continue;const o={};
        for(const k of LIM_KEYS){const y=x[k]||{},v=y.v===''||y.v==null?null:+y.v;if(v!=null&&!(v>=0&&isFinite(v)))throw fail(400,`Check the ${c} limits: use numbers of 0 or more.`);if(y.on&&!(v>0))throw fail(400,`Enter an amount for every ${c} limit that is switched on.`);if(v!=null||y.on)o[k]={on:!!y.on,v:v==null?null:(CRYPTO.includes(c)?r8(v):Math.round(v*100)/100)}}
        const chk=(a,b2,msg)=>{if(o[a]&&o[b2]&&o[a].on&&o[b2].on&&o[a].v>o[b2].v)throw fail(400,`${c}: ${msg}`)};
        chk('depMin','depMax','the deposit minimum is above the per-transaction maximum.');chk('depMax','depDay','the deposit per-transaction maximum is above the daily limit.');chk('depDay','depMonth','the daily deposit limit is above the monthly limit.');
        chk('wdMin','wdMax','the withdrawal minimum is above the per-transaction maximum.');chk('wdMax','wdDay','the withdrawal per-transaction maximum is above the daily limit.');chk('wdDay','wdMonth','the daily withdrawal limit is above the monthly limit.');
        if(Object.keys(o).length)nl[c]=o}
      s.curLim=nl}
    if(['off','optional','required'].includes(b.referral))s.referral=b.referral;
    addAudit(a.email,'Controls changed',JSON.stringify(s),ipOf(req));save();push(null,'settings',s);send(res,200,s);
  },

  /* ---- KYC ---- */
  async 'POST /api/kyc'(req,res,url){
    const u=authed(req,url),b=await body(req,9e6);
    if(u.kyc==='pending'||u.kyc==='verified')throw fail(400,u.kyc==='pending'?'Your documents are already under review.':'You are already verified.');
    if(!ID_TYPES.includes(b.idType))throw fail(400,'Choose a document type.');
    const fullName=str(b.fullName,100),idNumber=str(b.idNumber,40);
    if(!fullName||!idNumber)throw fail(400,'Enter your legal name and document number.');
    const dob=String(b.dob||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(dob)||isNaN(Date.parse(dob+'T00:00:00Z'))||new Date(dob+'T00:00:00Z').toISOString().slice(0,10)!==dob)throw fail(400,'Enter your date of birth.');
    const age=ageOn(dob,new Date());if(age<18)throw fail(400,'You must be 18 or older to use HarborPay.');if(age>120)throw fail(400,'Check your date of birth.');
    for(const k of['doc','selfie'])if(!DATAURL.test(b[k]||''))throw fail(400,k==='doc'?'Add a photo of your document.':'Add a selfie.');
    if(b.back&&!DATAURL.test(b.back))throw fail(400,'The back photo could not be read.');
    const id=uid('k');
    for(const k of['doc','back','selfie']){const v=b[k];if(!v)continue;const m=v.match(/^data:([^;]+);base64,(.*)$/);const buf=Buffer.from(m[2],'base64');if(buf.length>4e6)throw fail(413,'That file is too large.');fs.writeFileSync(path.join(KYCDIR,`${id}-${k}.${EXT[m[1]]}`),buf)}
    u.dob=dob;u.bday=dob.slice(5);
    db.kycs.push({id,userId:u.id,fullName,dob,country:u.country,idType:b.idType,idNumber,docName:'uploaded',selfieName:'uploaded',hasBack:!!b.back,status:'pending',ts:Date.now(),note:''});
    u.kyc='pending';notify(u.id,'Identity documents received',`We received your ${b.idType} and selfie. They will be reviewed, usually within 1 business day, and we will tell you as soon as it is done.`,{view:'kyc'});notifyAdmins('Identity check submitted',`${u.name} submitted a ${b.idType} for review.`,'kyc');
    addAudit(u.email,'KYC submitted',b.idType,ipOf(req));save();pushAdmins('sync',{});send(res,200,{ok:true});
  },
  async 'GET /api/admin/kyc-file'(req,res,url){
    admin(req,url);const id=url.searchParams.get('id')||'',k=url.searchParams.get('k')||'';
    if(!/^k_[a-f0-9]+$/.test(id)||!['doc','back','selfie'].includes(k))throw fail(400,'Bad request');
    const f=fs.readdirSync(KYCDIR).find(n=>n.startsWith(`${id}-${k}.`));if(!f)throw fail(404,'No file on record');
    res.writeHead(200,{'Content-Type':MIME[f.split('.').pop()],'Cache-Control':'private, no-store'});res.end(fs.readFileSync(path.join(KYCDIR,f)));
  }
};

// looks in "public" and next to server.js; if a file exists in both places the most recently changed copy wins
const findFile=n=>[path.join(__dirname,'public',n),path.join(__dirname,n)].filter(p=>fs.existsSync(p)).sort((a,b)=>fs.statSync(b).mtimeMs-fs.statSync(a).mtimeMs)[0];
if(!findFile('index.html'))console.warn('WARNING: index.html not found. Put it in a "public" folder next to server.js.');
else if(fs.existsSync(path.join(__dirname,'public','index.html'))&&fs.existsSync(path.join(__dirname,'index.html')))console.warn('NOTE: there are two copies of index.html. Serving the newer one: '+path.relative(__dirname,findFile('index.html'))+'. Delete the other so you do not edit the wrong file.');

/* ---- support by email: replies go into the customer's support conversation (Resend inbound) ---- */
const rawBody=(req,limit=1e6)=>new Promise((ok,no)=>{let b='';req.setEncoding('utf8');req.on('data',c=>{b+=c;if(b.length>limit){no(fail(413,'Too large'));req.destroy()}});req.on('end',()=>ok(b))});
function svixOk(raw,h,secret){ // Resend signs webhooks the Svix way: HMAC-SHA256 over "id.timestamp.body"
  const id=h['svix-id'],ts=h['svix-timestamp'],sig=h['svix-signature'];if(!id||!ts||!sig||!secret)return false;
  if(!(Math.abs(Date.now()/1000-Number(ts))<=300))return false;
  const exp=crypto.createHmac('sha256',Buffer.from(String(secret).replace(/^whsec_/,''),'base64')).update(`${id}.${ts}.${raw}`).digest('base64');
  return String(sig).split(' ').some(p=>{const[v,x]=p.split(',');return v==='v1'&&!!x&&safeEq(x,exp)});
}
const TAG=t=>`[HP-${t.id}]`;
function mailTicket(t,text,who){const u=byId(t.userId);if(!u||u.status==='closed')return;
  mail(u.email,`Re: ${t.subject.replace(/\s*\[HP-t_[a-z0-9]+\]/ig,'')} ${TAG(t)}`,`Hi ${first(u)},\n\n${who} replied to your message:\n\n${text}\n\nYou can reply to this email, or continue the chat on the Support page.`).catch(()=>{});}
const seenInbound=new Set();
function cleanReply(t){t=String(t||'').replace(/\r/g,'');
  const cut=[/\n\s*On .{0,300}wrote:\s*\n/is,/\n-{2,}\s*Original Message\s*-{2,}/i,/\n_{5,}\s*\nFrom:/i,/\nFrom: .*\nSent: /i,/\n>/];
  for(const re of cut){const m=t.match(re);if(m&&m.index>0)t=t.slice(0,m.index)}
  return t.trim().slice(0,5000)}
async function takeInbound(id){
  const r=await fetch(`${process.env.RESEND_API_BASE||'https://api.resend.com'}/emails/receiving/${encodeURIComponent(id)}`,{headers:{Authorization:'Bearer '+process.env.RESEND_API_KEY},signal:AbortSignal.timeout(15000)});
  if(!r.ok)throw new Error('could not fetch received email '+r.status);
  const e=await r.json(),from=(String(e.from||'').match(/<([^>]+)>/)||[0,e.from])[1].trim().toLowerCase(),subject=str(e.subject,140)||'(no subject)';
  const body=cleanReply(e.text||String(e.html||'').replace(/<br\s*\/?>/gi,'\n').replace(/<\/p>/gi,'\n\n').replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>'));
  const au=e.authentication||{},res=k=>{const x=au[k];return String(typeof x==='string'?x:(x&&(x.result||x.status))||'').toLowerCase()};
  const trusted=res('dmarc')==='pass'||res('dkim')==='pass'||res('spf')==='pass'; // a forged "From" must not reach someone's account
  const own=(MAIL_FROM.match(/@([^>\s]+)/)||[])[1];if(own&&from.endsWith('@'+own.toLowerCase()))return; // our own outgoing mail (e.g. alerts to a support@ address): never loop it back in
  const u=db.users.find(x=>x.role==='customer'&&x.status!=='closed'&&x.email.toLowerCase()===from);
  if(!u||!trusted){notifyAdmins(u?'Support email could not be verified':'Email from someone without an account',`From ${from}${u?' (the sender check failed, so it was not added to their account)':''}\nSubject: ${subject}\n\n${str(body,600)}`,'support');save();pushAdmins('sync',{});return}
  if(!body){return}
  const tag=subject.match(/\[HP-(t_[a-z0-9]+)\]/i);let t=tag&&db.tickets.find(x=>x.id===tag[1]&&x.userId===u.id);
  if(t&&t.status!=='open'){t.status='open';t.human=t.human||false}
  if(!t){t={id:uid('t'),userId:u.id,subject:str(subject.replace(/^((re|fwd?|aw)\s*:\s*)+/i,'').replace(/\s*\[HP-t_[a-z0-9]+\]/ig,''),140)||'Email to support',status:'open',ts:Date.now(),msgs:[]};db.tickets.unshift(t)}
  t.msgs.push({from:'user',text:body,ts:Date.now(),via:'email'});t.lastVia='email';
  addAudit(u.email,'Support email received',t.subject,'');
  if(botWillAnswer(t))queueBot(t);else notifyAdmins('Support email',`${u.name} (${u.email}): ${t.subject}\n"${str(body,300)}"`,'support');
  save();push(u.id,'sync',{});pushAdmins('sync',{});
}

// The service worker only keeps a copy of the page so the app opens with a friendly message when there is no internet.
// It never stores account data: every /api request goes straight to the server.
const SW_JS=`const C='hp-shell-v4';
const MAINT='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#06101F"><title>HarborPay</title><style>html,body{height:100%;margin:0}body{display:grid;place-items:center;background:radial-gradient(120% 60% at 50% -10%,#0E2546,#06101F 60%);color:#EEF4FF;font:400 16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;text-align:center;padding:24px;box-sizing:border-box}img{width:64px;height:64px;border-radius:16px}h1{font-size:24px;margin:18px 0 6px}p{color:#8EA9CF;margin:0 0 22px}.s{width:28px;height:28px;border:3px solid #1C3658;border-top-color:#5C8DFF;border-radius:50%;margin:0 auto;animation:r 1s linear infinite}@keyframes r{to{transform:rotate(360deg)}}button{margin-top:22px;background:#5C8DFF;color:#fff;border:0;border-radius:12px;padding:12px 22px;font:600 15px inherit;cursor:pointer}</style></head><body><main><img src="/icon-192.png" alt="" onerror="this.onerror=null;this.src=\\'/favicon.png\\'"><h1>This site can\\u2019t be reached right now</h1><p>Please try again in a moment. Your money is safe. This page reloads by itself when HarborPay is back.</p><div class="s"></div><button onclick="location.reload()">Reload</button></main><script>setInterval(function(){fetch("/healthz",{cache:"no-store"}).then(function(r){if(r.ok)location.reload()}).catch(function(){})},4000)</script></body></html>';
const down=()=>new Response(MAINT,{status:503,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Retry-After':'10'}});
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>Promise.all(['/icon-192.png','/favicon.png'].map(u=>c.add(u).catch(()=>{})))).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{const r=e.request,pth=new URL(r.url).pathname;if(r.method!=='GET'||pth.startsWith('/api/'))return;
  if(pth==='/icon-192.png'||pth==='/favicon.png')return e.respondWith(fetch(r).then(x=>x.ok?x:caches.match(pth).then(c=>c||x)).catch(()=>caches.match(pth)));
  if(r.mode==='navigate')e.respondWith(fetch(r).then(x=>{if(x.status>=500||!x.headers.get('x-hp'))return down();return x}).catch(()=>down()));});
self.addEventListener('push',e=>{let d={};try{d=e.data?e.data.json():{}}catch(_){d={title:'HarborPay',body:e.data?e.data.text():''}}
  e.waitUntil(self.registration.showNotification(d.title||'HarborPay',{body:d.body||'',icon:'/icon-192.png',badge:'/icon-192.png',tag:d.tag,data:{url:d.url||'/'},vibrate:[80,40,80]}))});
self.addEventListener('notificationclick',e=>{e.notification.close();const u=new URL((e.notification.data&&e.notification.data.url)||'/',self.location.origin).href;
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const c of l){if(new URL(c.url).origin===self.location.origin&&'focus' in c){c.postMessage({hpOpen:u});return c.focus()}}return self.clients.openWindow(u)}))});`;
/* ================= Extra protection =================
   1) Admin sign-in with a passkey only   2) Admin only on approved devices
   3) Withdrawal safety hold (first / large withdrawals wait, and a cool-down after security changes)   4) Daily encrypted backup by email
   Locked out? Set ADMIN_LOCK_OFF=1 in Railway Variables, sign in, fix it in Security, then delete the variable. */
function SEC(){db.sec=db.sec||{};const s=db.sec;s.devices=s.devices||[];s.pending=s.pending||[];
  s.hold=Object.assign({on:true,first:true,over:1000,hours:12,cool:24},s.hold||{});
  s.backup=Object.assign({on:false,to:'',hour:2,pass:'',last:0,lastDay:'',lastErr:'',tryAt:0},s.backup||{});return s}
const LOCK_OFF=process.env.ADMIN_LOCK_OFF==='1';
const devOf=req=>{const h=String(req.headers['x-hp-device']||'');return /^[a-f0-9]{32}$/.test(h)?crypto.createHash('sha256').update('hpdev:'+h).digest('hex').slice(0,24):''};
function adminGate(u,req,viaPk){if(!u||u.role!=='admin'||LOCK_OFF)return;const s=SEC(),ip=ipOf(req);
  if(s.adminPk&&!viaPk){addAudit(u.email,'Admin sign-in blocked: passkey required',uaName(req.headers['user-agent']),ip);save();throw fail(403,'Admin accounts must sign in with a passkey. Tap "Sign in with a passkey".')}
  if(!s.devLock)return;const d=devOf(req),ok=d&&s.devices.find(x=>x.id===d);
  if(ok){ok.lastUsed=Date.now();return}
  const name=uaName(req.headers['user-agent']);
  if(d){let p=s.pending.find(x=>x.id===d);if(!p){p={id:d,name,ip,ts:Date.now(),email:u.email};s.pending.unshift(p);if(s.pending.length>20)s.pending.length=20;
      for(const a of db.users.filter(x=>x.role==='admin'&&x.status!=='closed')){const pr=nPref('security');if(pr.app)notify(a.id,'New device wants admin access',`${u.email} tried to open admin on ${name} (IP ${ip}). It was blocked. If this was you, approve it in Security → Admin protection from a device you already use. If not, change your password now.`,{view:'security'});if(pr.mail)mail(a.email,'Admin access blocked on a new device',`Hi,\n\n${u.email} tried to sign in to the HarborPay admin on a device that is not approved.\n\nDevice: ${name}\nIP address: ${ip}\nTime: ${new Date().toUTCString()}\n\nIt was blocked. If this was you, approve it in Security → Admin protection from a device you already use. If it was not you, change your admin password now.`).catch(()=>{})}}
    else p.ts=Date.now()}
  addAudit(u.email,'Admin sign-in blocked: device not approved',`${name} (${ip})`,ip);save();
  throw fail(403,'This device is not approved for admin. Approve it from a device you already use: Security → Admin protection.')}
const COOL_WHY={'Password changed':'your password was just changed','Password reset':'your password was just reset','Transaction PIN changed':'your PIN was just changed','Email changed by customer':'your email address was just changed','Phone changed with passkey':'your phone number was just changed','Two-step sign-in off':'two-step sign-in was just turned off','Passkey added':'a new passkey was just added'};
function secCool(actor,action){const why=COOL_WHY[action];if(!why||!db||!db.users)return;const h=SEC().hold;if(!h.on||!(h.cool>0))return;
  const u=db.users.find(x=>x.email===actor&&x.role==='customer');if(!u)return;const until=Date.now()+h.cool*36e5;
  if(!(u.wdHold>until)){u.wdHold=until;u.wdHoldWhy=why}}
/* safety hold on a new withdrawal: the admin cannot mark it sent before the time is up (unless they choose Send anyway) */
function wdSafety(u,t){const h=SEC().hold;if(!h.on)return null;const why=[];
  if(h.first&&!db.txs.some(x=>x.id!==t.id&&x.userId===u.id&&x.type==='withdrawal'&&x.status==='completed'))why.push('first withdrawal');
  const usd=toUsd(t.currency,t.amount);if(h.over>0&&usd>=h.over)why.push(`over $${Number(h.over).toLocaleString('en-US')}`);
  if(!why.length||!(h.hours>0))return null;return t.d.hold={why,until:Date.now()+h.hours*36e5,hours:h.hours}}
/* backup: gzip + AES-256-GCM, key from the backup password (PBKDF2-SHA256, 200,000 rounds). Open it with harborpay-backup-opener.html */
function backupFile(pass){const raw=zlib.gzipSync(Buffer.from(JSON.stringify(db))),salt=crypto.randomBytes(16),iv=crypto.randomBytes(12),key=crypto.pbkdf2Sync(String(pass),salt,200000,32,'sha256'),c=crypto.createCipheriv('aes-256-gcm',key,iv),enc=Buffer.concat([c.update(raw),c.final()]);
  return Buffer.concat([Buffer.from('HPBK1'),salt,iv,c.getAuthTag(),enc])}
const bkName=()=>`harborpay-backup-${new Date().toISOString().slice(0,10)}.hpbak`;
async function sendBackup(why){const b=SEC().backup;if(!b.to||!b.pass)return'Set the email and backup password first.';
  const f=backupFile(b.pass),name=bkName(),big=f.length>7e6,stats=`Customers: ${db.users.filter(u=>u.role==='customer'&&u.status!=='closed').length}\nTransactions: ${db.txs.length}\nFile: ${name} (${(f.length/1024).toFixed(0)} KB)`;
  const st=await mail0(b.to,'HarborPay daily backup',`Hi,\n\nHere is your ${why==='manual'?'':'daily '}HarborPay backup.\n\n${stats}\n\n${big?'The file is too large to attach. Download it from Admin → Security → Admin protection → Download backup.':'The file is attached. It is locked with your backup password. Open it with harborpay-backup-opener.html on your computer.'}\n\nKeep this email private. Identity photos are not included (they are stored separately on the server).`,big?{}:{attach:{name,content:f.toString('base64'),type:'application/octet-stream'}});
  const ok=st==='sent'||st==='logged';b.last=ok?Date.now():b.last;b.lastErr=ok?'':String(st||'failed').slice(0,200);b.tryAt=Date.now();if(ok)b.lastDay=new Date().toISOString().slice(0,10);save();return ok?'':b.lastErr}
setInterval(()=>{try{const b=SEC().backup;if(!b.on||!b.to||!b.pass)return;const now=new Date(),day=now.toISOString().slice(0,10);
  if(b.lastDay===day||now.getUTCHours()<b.hour||Date.now()-b.tryAt<36e5)return;sendBackup('daily').catch(()=>{})}catch{}},10*6e4);
const secView=(a,req)=>{const s=SEC();return{adminPk:!!s.adminPk,devLock:!!s.devLock,lockOff:LOCK_OFF,myDev:devOf(req),myPasskeys:(a.passkeys||[]).length,
  devices:s.devices,pending:s.pending,hold:s.hold,backup:{on:!!s.backup.on,to:s.backup.to,hour:s.backup.hour,hasPass:!!s.backup.pass,last:s.backup.last,lastErr:s.backup.lastErr}}};
routes['GET /api/admin/sec']=async(req,res,url)=>{const a=admin(req,url);send(res,200,secView(a,req))};
routes['POST /api/admin/sec']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),s=SEC(),ip=ipOf(req),ch=[];
  if('adminPk' in b){const on=!!b.adminPk;if(on&&!(a.passkeys||[]).length)throw fail(400,'Add a passkey to your own admin account first (Passkeys, at the top of this page).');if(on!==!!s.adminPk){s.adminPk=on;ch.push(`passkey-only admin sign-in ${on?'on':'off'}`)}}
  if('devLock' in b){const on=!!b.devLock;if(on){const d=devOf(req);if(!d)throw fail(400,'Reload the page and try again.');
      if(!s.devices.some(x=>x.id===d))s.devices.push({id:d,name:uaName(req.headers['user-agent']),added:Date.now(),by:a.email,lastUsed:Date.now()});
      const ss=db.sessions.find(x=>x.id===req.sid);if(ss)ss.dev=d}
    if(on!==!!s.devLock){s.devLock=on;ch.push(`approved admin devices only ${on?'on':'off'}`)}}
  if(b.hold){const h=b.hold,n=(v,lo,hi)=>{v=Number(v);if(!isFinite(v)||v<lo||v>hi)throw fail(400,'Check the safety hold numbers.');return v};
    s.hold={on:!!h.on,first:!!h.first,over:n(h.over,0,1e9),hours:n(h.hours,0,168),cool:n(h.cool,0,168)};ch.push(`withdrawal safety hold ${s.hold.on?`on (first:${s.hold.first?'yes':'no'}, over $${s.hold.over}, ${s.hold.hours}h; cool-down ${s.hold.cool}h)`:'off'}`)}
  if(b.backup){const k=b.backup,to=str(k.to,120).toLowerCase(),hour=Math.round(Number(k.hour));
    if(to&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to))throw fail(400,'Enter a valid email for backups.');if(!(hour>=0&&hour<=23))throw fail(400,'Choose a time for the backup.');
    if(k.pass){if(String(k.pass).length<8)throw fail(400,'The backup password must be at least 8 characters.');s.backup.pass=String(k.pass).slice(0,200)}
    if(k.on&&(!to||!s.backup.pass))throw fail(400,'Enter the email and a backup password to turn on daily backups.');
    Object.assign(s.backup,{on:!!k.on,to,hour});ch.push(`daily backup ${s.backup.on?'on to '+to:'off'}${k.pass?' (password changed)':''}`)}
  if(ch.length){addAudit(a.email,'Admin protection changed',ch.join('; '),ip);notifyAdmins('Admin protection changed',`${a.email}: ${ch.join('; ')}`,'security')}
  save();send(res,200,secView(a,req))};
routes['POST /api/admin/sec/device']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),s=SEC(),ip=ipOf(req),id=String(b.id||'');
  if(b.action==='approve'){const p=s.pending.find(x=>x.id===id);if(!p)throw fail(404,'That request is no longer waiting.');s.pending=s.pending.filter(x=>x!==p);
    s.devices.push({id:p.id,name:str(b.name,40)||p.name,added:Date.now(),by:a.email,lastUsed:0});addAudit(a.email,'Admin device approved',`${p.name} (${p.ip})`,ip)}
  else if(b.action==='reject'){const p=s.pending.find(x=>x.id===id);s.pending=s.pending.filter(x=>x.id!==id);addAudit(a.email,'Admin device request rejected',p?`${p.name} (${p.ip})`:id,ip)}
  else if(b.action==='remove'){const d=s.devices.find(x=>x.id===id);if(!d)throw fail(404,'Device not found.');if(s.devLock&&s.devices.length===1)throw fail(400,'This is the last approved device. Turn off "Approved devices only" first.');
    s.devices=s.devices.filter(x=>x!==d);addAudit(a.email,'Admin device removed',d.name,ip);
    {const gone=db.sessions.filter(x=>x.dev===id&&(byId(x.userId)||{}).role==='admin').map(x=>x.id);db.sessions=db.sessions.filter(x=>!gone.includes(x.id));for(const[r,c]of clients)if(gone.includes(c.sid)){try{r.write('event: signedout\ndata: {}\n\n');r.end()}catch{}clients.delete(r)}}}
  else if(b.action==='rename'){const d=s.devices.find(x=>x.id===id);if(!d)throw fail(404,'Device not found.');d.name=str(b.name,40)||d.name}
  else throw fail(400,'Unknown action.');save();send(res,200,secView(a,req))};
routes['GET /api/admin/backup']=async(req,res,url)=>{const a=admin(req,url),b=SEC().backup;if(!b.pass)throw fail(400,'Set a backup password first (Daily backup, below).');
  const f=backupFile(b.pass);addAudit(a.email,'Backup downloaded',bkName(),ipOf(req));save();
  res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${bkName()}"`,'Cache-Control':'no-store'});res.end(f)};
routes['POST /api/admin/backup/send']=async(req,res,url)=>{const a=admin(req,url),e=await sendBackup('manual');if(e)throw fail(502,'Backup email failed: '+e);addAudit(a.email,'Backup emailed',SEC().backup.to,ipOf(req));save();send(res,200,{ok:true,to:SEC().backup.to})};
/* ================= Additional verification: ask any customer for more proof (incoming payment, account details, or general) ================= */
const VF_ITEMS={id_photo:['A clear photo of your ID (front and back)','file'],selfie_id:['A selfie holding your ID next to your face','file'],address:['Proof of address (utility bill or bank statement from the last 3 months)','file'],
  payment_proof:['Proof of payment: receipt or bank statement showing this transfer','file'],statement:['Bank statement of the account the money came from','file'],source_funds:['Where the money comes from (source of funds)','text'],explain:['A short written explanation','text'],other:['Anything else (see the message)','either']};
const VF_REASON={payment:'an incoming payment',account:'your account details',general:'your account'};
const vfOpen=u=>(db.verifs||[]).filter(v=>v.userId===u.id&&['open','submitted'].includes(v.status));
const vfPaused=u=>vfOpen(u).some(v=>v.pauseWd);
routes['POST /api/admin/verif']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),u=byId(b.userId);
  if(!u||u.role!=='customer'||u.status==='closed')throw fail(404,'Customer not found.');const v=vfCreate(a,u,b,req);save();pushAdmins('sync',{});push(u.id,'sync',{});send(res,200,{ok:true,id:v.id})};
function vfCreate(a,u,b,req,lockNote){const ip=ipOf(req);
  const items=[...new Set((b.items||[]).filter(k=>VF_ITEMS[k]))];if(!items.length)throw fail(400,'Choose at least one thing to ask for.');
  const reason=VF_REASON[b.reason]?b.reason:'general',msg=str(b.message,1200),hours=Math.max(1,Math.min(720,Math.round(+b.dueHours||72)));
  const t=b.txId?db.txs.find(x=>x.id===b.txId&&x.userId===u.id):null;if(b.txId&&!t)throw fail(404,'That transaction is not this customer’s.');
  const cur=FIAT.includes(b.cur)?b.cur:'';
  db.verifs=db.verifs||[];const v={id:uid('v'),userId:u.id,by:a.email,ts:Date.now(),due:Date.now()+hours*36e5,reason,txId:t?t.id:'',cur,items,message:msg,pauseWd:!!b.pauseWd,status:'open',rounds:[]};db.verifs.unshift(v);
  if(t){t.d=t.d||{};t.d.verif=v.id}
  const what=items.map(k=>'• '+VF_ITEMS[k][0]).join('\n'),about=t?`your ${t.type} of ${money(t.currency,t.amount)}`:cur?`your ${cur} account details`:VF_REASON[reason];
  notify(u.id,'Additional verification needed',`To complete a check on ${about}, we need a little more information from you:\n\n${what}${msg?`\n\nMessage: ${msg}`:''}\n\nPlease send it by ${new Date(v.due).toUTCString().slice(5,22)} UTC. Open HarborPay and tap "Action needed" to answer.${v.pauseWd?' Withdrawals are paused until this is done.':''}${lockNote||''}`,{view:'verify',kind:'verif'});
  addAudit(a.email,'Additional verification requested',`${u.email}: ${items.join(', ')}${t?` (tx ${t.id})`:''}${cur?` (${cur} details)`:''}`,ip);return v}
routes['POST /api/verif/submit']=async(req,res,url)=>{const u=authed(req,url),b=await body(req,24e6),v=(db.verifs||[]).find(x=>x.id===String(b.id||'')&&x.userId===u.id);
  if(!v)throw fail(404,'Request not found.');if(v.status!=='open')throw fail(400,v.status==='submitted'?'You already sent this. It is being reviewed.':'This request is closed.');
  const text=str(b.text,4000),files=(b.files||[]).slice(0,8);const needFile=v.items.some(k=>VF_ITEMS[k][1]==='file'),needText=v.items.some(k=>VF_ITEMS[k][1]==='text');
  if(needFile&&!files.length)throw fail(400,'Please add the documents we asked for.');if(needText&&text.length<3)throw fail(400,'Please write the answer we asked for.');if(!files.length&&!text)throw fail(400,'Add a document or write an answer.');
  const saved=[],round=v.rounds.length;
  for(let i=0;i<files.length;i++){const m=String(files[i]||'').match(/^data:([^;]+);base64,(.*)$/);if(!m||!DATAURL.test(files[i]))throw fail(400,'One of the files could not be read. Use photos (JPG, PNG) or PDF.');
    const buf=Buffer.from(m[2],'base64');if(buf.length>4e6)throw fail(413,'Each file must be under 4 MB.');const n=`${round}-${i}`;fs.writeFileSync(path.join(KYCDIR,`${v.id}-${n}.${EXT[m[1]]}`),buf);saved.push({n,type:m[1]})}
  v.rounds.push({ts:Date.now(),text,files:saved});v.status='submitted';
  notify(u.id,'Verification received','Thanks! We received your information. It will be reviewed, usually within 1 business day, and you will be notified.',{view:'verify',noMail:true});
  notifyAdmins('Verification answered',`${u.name} sent the additional verification you asked for.`,'verifs');addAudit(u.email,'Additional verification submitted',`${saved.length} file(s)`,ipOf(req));save();pushAdmins('sync',{});send(res,200,{ok:true})};
routes['POST /api/admin/verif/decide']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),v=(db.verifs||[]).find(x=>x.id===String(b.id||'')),ip=ipOf(req);if(!v)throw fail(404,'Request not found.');
  const u=byId(v.userId),note=str(b.note,800),act=b.action;if(!u)throw fail(404,'Customer not found.');
  if(act==='approve'){if(!['submitted','open'].includes(v.status))throw fail(400,'This request is already closed.');v.status='approved';v.done=Date.now();v.doneBy=a.email;v.note=note;
    for(const l of (u.locks||[]).filter(l=>l.verifId===v.id&&l.autoRelease))lockRelease(a,u,l,'verification approved',req);
    notify(u.id,'Verification approved',`Thank you. Your additional verification was approved${v.pauseWd?' and withdrawals are available again':''}.${note?`\n\n${note}`:''}`,{view:'verify'})}
  else if(act==='again'){if(v.status!=='submitted')throw fail(400,'You can ask again only after the customer has answered.');if(!note)throw fail(400,'Write what is still missing.');v.status='open';v.due=Date.now()+Math.max(1,Math.min(720,Math.round(+b.dueHours||48)))*36e5;v.rounds[v.rounds.length-1].reply=note;
    notify(u.id,'More information needed',`Thanks for your answer. We still need a little more:\n\n${note}\n\nPlease send it by ${new Date(v.due).toUTCString().slice(5,22)} UTC. Open HarborPay and tap "Action needed".`,{view:'verify',kind:'verif'})}
  else if(act==='reject'){if(!['submitted','open'].includes(v.status))throw fail(400,'This request is already closed.');if(!note)throw fail(400,'Write the reason. The customer sees it.');v.status='rejected';v.done=Date.now();v.doneBy=a.email;v.note=note;
    notify(u.id,'Verification not approved',`We could not approve your additional verification.\n\nReason: ${note}\n\nIf you have questions, contact Support.`,{view:'verify'})}
  else if(act==='cancel'){if(!['submitted','open'].includes(v.status))throw fail(400,'This request is already closed.');v.status='cancelled';v.done=Date.now();v.doneBy=a.email;
    for(const l of (u.locks||[]).filter(l=>l.verifId===v.id))lockRelease(a,u,l,'request withdrawn',req);
    notify(u.id,'Verification request withdrawn',`We no longer need the additional information we asked for. ${v.pauseWd?'Withdrawals are available again. ':''}No action is needed.`,{view:'verify',noMail:true})}
  else throw fail(400,'Unknown action.');
  addAudit(a.email,'Additional verification '+({approve:'approved',again:'asked again',reject:'rejected',cancel:'cancelled'}[act]),`${u.email}${note?': '+note.slice(0,120):''}`,ip);save();pushAdmins('sync',{});push(u.id,'sync',{});send(res,200,{ok:true})};

/* ================= Funds lock: hold part or all of a customer's balance while a payment or the account is checked ================= */
const lockedOf=(u,cur)=>{const L=(u.locks||[]).filter(l=>l.cur===cur);if(L.some(l=>l.all))return Math.max(0,+u.bal[cur]||0);return r8(L.reduce((s,l)=>s+(+l.amount||0),0))};
function lockCheck(me,cur,amt){const lk=lockedOf(me,cur);if(!(lk>0))return;const avail=Math.max(0,r8((+me.bal[cur]||0)-lk));
  if(amt>avail+1e-9){const v=(me.locks||[]).find(l=>l.cur===cur&&l.verifId&&(db.verifs||[]).some(x=>x.id===l.verifId&&x.status==='open'));
    throw fail(423,`${money(cur,lk)} of your ${cur} balance is on hold for a security check${v?'. Complete the verification we asked for (tap "Action needed") to release it':''}. You can use ${money(cur,avail)} now.`)}}
function lockRelease(a,u,l,why,req){u.locks=(u.locks||[]).filter(x=>x!==l);addAudit(a?a.email:'system','Funds unlocked',`${u.email}: ${l.all?'all '+l.cur:money(l.cur,l.amount)}${why?' ('+why+')':''}`,req?ipOf(req):'');
  notify(u.id,'Funds released',`${l.all?`Your ${l.cur} balance is`:`${money(l.cur,l.amount)} is`} no longer on hold. You can use it as normal.${why&&a?`\n\n${why}`:''}`,{view:'balances'})}
routes['POST /api/admin/lock']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),u=byId(b.userId),ip=ipOf(req);
  if(!u||u.role!=='customer'||u.status==='closed')throw fail(404,'Customer not found.');const cur=String(b.cur||'');if(!ALLC.includes(cur))throw fail(400,'Choose a currency.');
  const all=!!b.all,amount=all?0:r8(+b.amount);if(!all&&!(amount>0))throw fail(400,'Enter the amount to lock, or choose the whole balance.');
  const reason=str(b.reason,400);if(!reason)throw fail(400,'Write the reason. Only admins see it.');
  const t=b.txId?db.txs.find(x=>x.id===b.txId&&x.userId===u.id):null;
  const l={id:uid('lk'),cur,all,amount,reason,ts:Date.now(),by:a.email,txId:t?t.id:'',autoRelease:b.autoRelease!==false};
  let v=null;if(b.verif&&Array.isArray(b.verif.items)&&b.verif.items.length){v=vfCreate(a,u,{...b.verif,txId:t?t.id:'',reason:t?'payment':'general'},req,`\n\n${all?`Your ${cur} balance is`:`${money(cur,amount)} is`} on hold until this check is done.`);l.verifId=v.id}
  u.locks=u.locks||[];u.locks.push(l);
  if(!v)notify(u.id,'Funds on hold',`${all?`Your ${cur} balance has`:`${money(cur,amount)} has`} been placed on hold for a routine security check. You may be asked for more information. The rest of your balance is not affected.`,{view:'balances'});
  addAudit(a.email,'Funds locked',`${u.email}: ${all?'all '+cur:money(cur,amount)}${t?` (tx ${t.id})`:''} — ${reason}`,ip);save();pushAdmins('sync',{});push(u.id,'sync',{});send(res,200,{ok:true,id:l.id,verifId:v?v.id:''})};
routes['POST /api/admin/unlock']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),u=byId(b.userId);if(!u)throw fail(404,'Customer not found.');
  const l=(u.locks||[]).find(x=>x.id===String(b.id||''));if(!l)throw fail(404,'That hold is already released.');lockRelease(a,u,l,str(b.note,300),req);save();pushAdmins('sync',{});push(u.id,'sync',{});send(res,200,{ok:true})};
routes['GET /api/admin/verif-file']=async(req,res,url)=>{admin(req,url);const id=url.searchParams.get('id')||'',n=url.searchParams.get('n')||'';
  if(!/^v_[a-z0-9]+$/i.test(id)||!/^\d{1,2}-\d$/.test(n))throw fail(400,'Bad request');const f=fs.readdirSync(KYCDIR).find(x=>x.startsWith(`${id}-${n}.`));if(!f)throw fail(404,'No file on record');
  res.writeHead(200,{'Content-Type':MIME[f.split('.').pop()],'Cache-Control':'private, no-store'});res.end(fs.readFileSync(path.join(KYCDIR,f)))};
/* ================= Location alerts: sign-ins from unsupported countries, or through a VPN / proxy =================
   Country comes from Cloudflare's CF-IPCountry header when the site is behind Cloudflare, plus proxycheck.io (free, VPN/proxy detection;
   add PROXYCHECK_KEY in Railway for more lookups a day). Results are cached per IP for 12 hours. If the lookup fails, the sign-in goes ahead. */
const ISO_OK={'United States':'US','United Kingdom':'GB','Thailand':'TH','Poland':'PL','Mexico':'MX','Argentina':'AR','Morocco':'MA','Monaco':'MC','Philippines':'PH'};
const GEO_CACHE=new Map();
const geoPrivate=ip=>!ip||/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);
async function geoLookup(req){const ip=ipOf(req),cf=String(req.headers['cf-ipcountry']||'').toUpperCase();
  if(process.env.GEO_TEST==='1'&&req.headers['x-test-geo']){try{return{ip,...JSON.parse(String(req.headers['x-test-geo']))}}catch{}}
  if(geoPrivate(ip))return{ip,iso:cf&&cf!=='XX'?cf:'',country:'',vpn:false,skip:true};
  const c=GEO_CACHE.get(ip);if(c&&c.at>Date.now()-12*36e5)return{...c.r,iso:c.r.iso||cf};
  let r={ip,iso:cf&&cf!=='XX'&&cf!=='T1'?cf:'',country:'',vpn:cf==='T1',type:cf==='T1'?'Tor':''};
  try{const k=process.env.PROXYCHECK_KEY?`&key=${encodeURIComponent(process.env.PROXYCHECK_KEY)}`:'';const ac=new AbortController(),t=setTimeout(()=>ac.abort(),2500);
    const j=await (await fetch(`https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1${k}`,{signal:ac.signal})).json();clearTimeout(t);const x=j&&j[ip];
    if(x){r.iso=x.isocode||r.iso;r.country=x.country||'';r.vpn=r.vpn||x.proxy==='yes';r.type=x.proxy==='yes'?(x.type||'Proxy'):r.type;r.isp=x.provider||x.organisation||''}}catch{}
  GEO_CACHE.set(ip,{at:Date.now(),r});if(GEO_CACHE.size>5000)GEO_CACHE.delete(GEO_CACHE.keys().next().value);return r}
const geoAllowedIso=()=>Object.values(ISO_OK).filter((v,i)=>ELIGIBLE.includes(Object.keys(ISO_OK)[i]));
/* runs on every customer sign-in and sign-up; alerts at once, and blocks if you switched that on */
async function geoGate(u,req,what){if(!u||u.role!=='customer')return;const g=await geoLookup(req);if(g.skip&&!g.iso)return;
  const bad=g.iso&&!geoAllowedIso().includes(g.iso),vpn=!!g.vpn;if(!bad&&!vpn)return;
  const S=db.settings.geo||{},block=(bad&&S.blockCountry)||(vpn&&S.blockVpn),name=g.country||g.iso||'unknown country',dev=uaName(req.headers['user-agent']);
  db.geoFlags=db.geoFlags||[];const f={id:uid('geo'),userId:u.id,ts:Date.now(),ip:g.ip,iso:g.iso,country:name,vpn,type:g.type||'',isp:g.isp||'',device:dev,what,blocked:!!block,status:'new'};db.geoFlags.unshift(f);if(db.geoFlags.length>2000)db.geoFlags.length=2000;
  const why=[bad?`from ${name} (not a supported country)`:'',vpn?`through a ${g.type||'VPN/proxy'}`:''].filter(Boolean).join(' and ');
  addAudit(u.email,block?'Sign-in blocked: restricted location':'Restricted-location sign-in',`${what} ${why} · IP ${g.ip} · ${dev}`,g.ip);
  const rep6=db.geoFlags.slice(1).some(x=>x.userId===u.id&&x.iso===g.iso&&x.vpn===vpn&&x.ts>Date.now()-6*36e5);
  if(!rep6)notifyAdmins(`🚨 ${block?'Blocked':'Restricted-location'} ${what}`,`${u.name} (${u.email}) ${block?'tried to':'did a'} ${what} ${why}. IP ${g.ip}${g.isp?` · ${g.isp}`:''} · ${dev}.`,'geoalerts',{mailSubject:`🚨 ${u.name}: ${what} ${why}`,mailBody:`Hi,\n\n${u.name} (${u.email}) ${block?'tried to sign in':'signed in'} ${why}.\n\nIP address: ${g.ip}\nCountry: ${name}\n${vpn?`Connection: ${g.type||'VPN/proxy'}\n`:''}${g.isp?`Network: ${g.isp}\n`:''}Device: ${dev}\nTime: ${new Date().toUTCString()}\n\n${block?'The sign-in was blocked.':'The sign-in was allowed.'} Review it in Admin → Location alerts, where you can lock funds, ask for verification or suspend the account.`});
  if(!rep6||block)pushAdmins('geoalert',{name:u.name,email:u.email,why,blocked:!!block,id:f.id});pushAdmins('sync',{});save();
  if(block)throw fail(403,bad?`HarborPay can't be used from ${name}. Please sign in from a supported country.`:`Sign-ins through a VPN or proxy aren't allowed. Turn it off and try again. See section 3 of our Terms of Service.`)}
routes['POST /api/admin/geo']=async(req,res,url)=>{const a=admin(req,url),b=await body(req);
  if(b.settings){db.settings.geo={blockCountry:!!b.settings.blockCountry,blockVpn:!!b.settings.blockVpn};addAudit(a.email,'Location rules changed',`block unsupported countries: ${db.settings.geo.blockCountry?'on':'off'}; block VPN/proxy: ${db.settings.geo.blockVpn?'on':'off'}`,ipOf(req))}
  if(b.review){const f=(db.geoFlags||[]).find(x=>x.id===b.review);if(f){f.status='reviewed';f.by=a.email;f.at=Date.now()}}
  if(b.reviewAll){for(const f of db.geoFlags||[])if(f.status==='new'){f.status='reviewed';f.by=a.email;f.at=Date.now()}}
  save();pushAdmins('sync',{});send(res,200,{ok:true})};
/* ================= Joker Bat: the admin's flying monitoring companion =================
   One read-only call that sums up the server and HarborPay right now. Nothing is changed. */
let JB_CPU=process.cpuUsage(),JB_T=Date.now(),JB_LAG=0;
{let t=Date.now();setInterval(()=>{const now=Date.now();JB_LAG=Math.max(0,now-t-1000);t=now},1000).unref()}
const COPIER_RE=/httrack|wget|curl\/|python-requests|python-urllib|scrapy|sitesucker|webcopier|webzip|teleport ?pro|offline ?explorer|webreaper|website ?(downloader|ripper|copier)|cyotek|getleft|blackwidow|webstripper|websucker|grab-site|archivebox|monolith|singlefile|go-http-client|libwww-perl|aiohttp|node-fetch|axios\//i;
/* a copied HarborPay page reports itself here (sent from the copy, so it comes from another website) */
routes['POST /api/clone-report']=async(req,res,url)=>{let b={};try{b=JSON.parse(String(await new Promise(r=>{let d='';req.on('data',c=>{d+=c;if(d.length>2000)req.destroy()});req.on('end',()=>r(d))}))||'{}')}catch{}
  const host=str(b.host,120).toLowerCase(),href=str(b.href,300);res.writeHead(204,{'Access-Control-Allow-Origin':'*'});res.end();
  if(!host||/^(www\.)?harborpay\.us\.com$|^localhost$|^127\.0\.0\.1$|\.up\.railway\.app$/.test(host))return;
  db.clones=db.clones||[];let c=db.clones.find(x=>x.host===host);const now=Date.now(),first=!c;
  if(!c){c={host,first:now,hits:0,ips:[]};db.clones.unshift(c);if(db.clones.length>100)db.clones.length=100}
  c.hits++;c.last=now;c.href=href||c.href;const ip=ipOf(req);if(!c.ips.includes(ip)&&c.ips.length<20)c.ips.push(ip);
  if(first||now-(c.alerted||0)>6*36e5){c.alerted=now;addAudit('system','Copy of HarborPay detected',`${host} (${href})`,ip);
    notifyAdmins('🚨 Someone copied HarborPay',`A copy of HarborPay is running at ${host}${href?` (${href})`:''}. Visitors there are sent to the real site. Report it to the host or to Google so it is taken down.`,'activity',{mailSubject:'Copy of HarborPay detected',mailBody:`Hi,\n\nA copy of HarborPay was opened at:\n${href||host}\n\nVisitors on that copy see a warning and are sent to the real HarborPay. To get it taken down, report it to the company hosting that website and at https://safebrowsing.google.com/safebrowsing/report_phish/\n\nTime: ${new Date().toUTCString()}`})}
  save()};
routes['OPTIONS /api/clone-report']=async(req,res)=>{res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'});res.end()};
var JB_ERRS=[];function jbErr(msg,where){if(!JB_ERRS)return;JB_ERRS.unshift({ts:Date.now(),msg:String(msg).slice(0,160),where:String(where||'').split('?')[0].slice(0,60)});if(JB_ERRS.length>30)JB_ERRS.length=30}
routes['POST /api/antiphish']=async(req,res,url)=>{const u=authed(req,url),b=await body(req);if(!pinOk(u,b.pin))throw fail(400,'That PIN is not right.');
  const code=String(b.code||'').trim();if(code&&!/^[A-Za-z0-9 _-]{4,20}$/.test(code))throw fail(400,'Use 4 to 20 letters or numbers (spaces, - and _ are fine).');
  const had=!!u.apCode;if(code)u.apCode=code;else delete u.apCode;addAudit(u.email,code?(had?'Anti-phishing code changed':'Anti-phishing code set'):'Anti-phishing code removed','',ipOf(req));
  notify(u.id,code?'Anti-phishing code set':'Anti-phishing code removed',code?`Your anti-phishing code is now on. Every real HarborPay email will show it at the top. If you get an email that says it's from HarborPay without your code, it's fake: don't click anything and tell us.`:'Your anti-phishing code was removed. HarborPay emails will no longer show it.',{view:'security'});
  save();send(res,200,{ok:true,code:u.apCode||''})};
routes['POST /api/tour/done']=async(req,res,url)=>{const u=authed(req,url);u.tourDone=Date.now();save();send(res,200,{ok:true})};
routes['GET /api/admin/joker']=async(req,res,url)=>{admin(req,url);const os=require('os'),now=Date.now(),h1=now-36e5,d0=new Date();d0.setUTCHours(0,0,0,0);
  const c=process.cpuUsage(JB_CPU),dt=Math.max(1,now-JB_T)*1000;JB_CPU=process.cpuUsage();JB_T=now;
  const mem=process.memoryUsage(),tx=db.txs,cust=db.users.filter(u=>u.role==='customer'),aud=db.audit.filter(a=>a.ts>=h1);
  const watch=Object.entries(db.hdScan||{}).filter(([k,v])=>v&&typeof v==='object'&&'at' in v).map(([k,v])=>({k,ok:!v.err,err:v.err||'',at:v.at}));
  const ml=(db.mailLog||[]).slice(0,20),mailFail=ml.filter(m=>m.status!=='sent'&&m.status!=='logged'&&m.ts>=h1).length;
  send(res,200,{ts:now,
    sys:{cpu:Math.min(100,Math.round((c.user+c.system)/dt*1000)/10),ram:Math.round(mem.rss/1048576),heap:Math.round(mem.heapUsed/1048576),ramTotal:Math.round(os.totalmem()/1048576),load:os.loadavg()[0],uptime:Math.round(process.uptime()),lag:JB_LAG,live:typeof clients!=='undefined'?clients.size:0,db:Math.round(Buffer.byteLength(JSON.stringify(db))/1024)},
    hp:{depPending:tx.filter(t=>t.type==='deposit'&&t.status==='pending').length,wdPending:tx.filter(t=>t.type==='withdrawal'&&t.status==='pending').length,
      holds:tx.filter(t=>t.type==='withdrawal'&&t.status==='pending'&&t.d&&t.d.hold&&t.d.hold.until>now).length,
      kyc:(db.kycs||[]).filter(k=>k.status==='pending').length,tickets:(db.tickets||[]).filter(t=>t.status==='open').length,
      signupsToday:cust.filter(u=>(u.created||0)>=+d0).length,customers:cust.filter(u=>u.status!=='closed').length,
      failedSignins:aud.filter(a=>a.action==='Failed sign-in').length,blocked:aud.filter(a=>/blocked|Failed passkey/i.test(a.action)).length,
      volToday:Math.round(tx.filter(t=>t.ts>=+d0&&t.status==='completed'&&t.type!=='conversion').reduce((s,t)=>s+toUsd(t.currency,t.amount),0)),
      geoNew:(db.geoFlags||[]).filter(f=>f.status==='new').length,geoLast:(()=>{const f=(db.geoFlags||[]).find(f=>f.status==='new');const u=f&&byId(f.userId);return f?{name:u?u.name:'',country:f.country,vpn:f.vpn,blocked:f.blocked}:null})(),
      verifWait:(db.verifs||[]).filter(v=>v.status==='submitted').length,verifLast:(()=>{const v=(db.verifs||[]).find(v=>v.status==='submitted');const u=v&&byId(v.userId);return u?u.name:''})(),
      acctReq:cust.reduce((n,u)=>n+FIAT.filter(c=>u.accts&&u.accts[c]&&['under_review','requested'].includes(u.accts[c].status)).length,0),
      acctLast:(()=>{let best=null;for(const u of cust)for(const c of FIAT){const x=u.accts&&u.accts[c];if(x&&['under_review','requested'].includes(x.status)&&(!best||(x.requestedAt||0)>best.at))best={name:u.name,c,at:x.requestedAt||0}}return best})(),
      paused:!!db.settings.withdrawalsPaused,mailFail,mailMode:typeof mailMode==='function'?mailMode():''},
    clones:(db.clones||[]).length,lastClone:(db.clones||[])[0]?{host:db.clones[0].host,last:db.clones[0].last}:null,
    watch,errs:JB_ERRS.filter(e=>e.ts>=h1).length,lastErr:JB_ERRS[0]||null,
    recent:db.audit.slice(0,8).map(a=>({ts:a.ts,action:a.action,actor:String(a.actor||'').replace(/(.{2}).*(@.*)/,'$1…$2')}))})};
/* ================= Ben: the admin command assistant =================
   The admin types a plain command ("credit demo usd 10"). Ben works out what to do,
   shows a plan, and only changes anything after the admin taps Confirm.
   Look-ups (balances, pending items) answer straight away. Every change goes through
   the same checks, notifications and activity log as the buttons in the admin panel. */
/* Ben: automatic reminder (callback) messages */
const REM_WORDS=/\b(reminders?|call ?-?backs?|promos?|promotions?|automatic messages?|auto messages?)\b/;
function benRem(s,l){const A=db.settings.auto.nudge,M=A.msgs||[],nm=l.match(/\b(?:reminders?|callbacks?|call backs?|promos?|promotions?|messages?|number|no\.?)\s*#?\s*(\d{1,2})\b/)||l.match(/#(\d{1,2})\b/),n=nm?+nm[1]:null;
  const cp=x=>({on:A.on,email:A.email,every:A.every,who:A.who||'quiet',msgs:M.map(m=>m.slice()),...x});
  const split=t=>{t=t.trim().replace(/^["']|["']$/g,'');const p=t.split(/\s*\|\s*/);if(p.length>=2)return[p[0],p.slice(1).join(' | ')];const k=t.match(/^(.{2,80}?[.!?])\s+(.+)$/);return k?[k[1].replace(/[.]$/,''),k[2]]:[t.length>60?'HarborPay':t,t]};
  const text=()=>{const m=s.match(/(?::|\bsaying\b|\bthat says\b|\bsay\b)\s*(.+)$/i);return m?m[1].trim():''};
  const pickN=()=>{if(!n)return{ask:'Which one? Type "reminders" to see their numbers.'};if(n<1||n>M.length)return{ask:`There is no reminder ${n}. You have ${M.length}.`};return{m:M[n-1]}};
  const short_=m=>`"${m[0]}"`;
  if(/^(show|list|see|view|what are|which are|my|all)?\s*(all\s+|the\s+|my\s+)?(reminders?|call ?-?backs?|promos?|promotions?|automatic messages?|auto messages?)\s*\??$/.test(l)||/^(show|list|see|view)\b/.test(l))return{look:'rem'};
  if(/^(add|new|create|write|make)\b/.test(l)){const t=text();if(!t)return{ask:'Write it like: add reminder: Get paid in 5 currencies | Receive USD, EUR, GBP, MXN and COP and withdraw anytime.'};
    if(M.length>=20)return{ask:'You already have 20 reminders. Delete one first.'};const[ti,bo]=split(t);
    return{kind:'auto',args:cp({msgs:[...M.map(m=>m.slice()),[ti.slice(0,120),bo.slice(0,600)]]}),summary:`Add reminder ${M.length+1}: "${ti}" — ${bo}`}}
  if(/^(edit|change|update|rewrite|replace)\b/.test(l)&&!/\bevery\b/.test(l)){const p=pickN();if(p.ask)return p;const t=text();if(!t)return{ask:`Write it like: edit reminder ${n}: New title | New message`};
    const[ti,bo]=split(t),ms=M.map(m=>m.slice());ms[n-1]=[ti.slice(0,120),bo.slice(0,600)].concat(M[n-1][2]?[1]:[]);return{kind:'auto',args:cp({msgs:ms}),summary:`Change reminder ${n} to "${ti}" — ${bo}`}}
  if(/^(delete|remove|drop|erase)\b/.test(l)){const p=pickN();if(p.ask)return p;return{kind:'auto',args:cp({msgs:M.filter((_,i)=>i!==n-1).map(m=>m.slice())}),summary:`Delete reminder ${n}: ${short_(p.m)}`}}
  if(/^(send|push|blast|fire)\b/.test(l)){const p=pickN();if(p.ask)return p;
    const email=/\bapp only\b|\bno email\b|\bwithout email\b|\bno mail\b/.test(l)?false:/\bemail\b|\bmail\b/.test(l)?true:!!A.email;
    const rest=l.replace(/^\S+\s*/,'').replace(/\b(?:reminders?|callbacks?|call backs?|promos?|promotions?|messages?|number|no\.?)\s*#?\s*\d{1,2}\b/,' ').replace(/#\d{1,2}\b/,' ').replace(/\b(now|today|right away|immediately|by|email|mail|app|only|in|the|and|to|also|too|without|no|out)\b/g,' ').trim();
    if(!rest||/^(everyone|everybody|all|all customers|customers|all users|users)$/.test(rest)){const c=benCustomers().filter(u=>u.status==='active'&&u.reminders!==false).length;
      return{kind:'autosend',args:{i:n-1,email},summary:`Send reminder ${n} ${short_(p.m)} now to all ${c} customers (in the app${email?' and by email':''})`}}
    const f=benFind(benWhoText(rest));if(!f.length)return{ask:`I could not find a customer matching "${rest}".`};if(f.length>1)return{ask:'Which customer?',choices:f.slice(0,6)};
    return{kind:'autosend',args:{i:n-1,email,userId:f[0].id},summary:`Send reminder ${n} ${short_(p.m)} now to ${benWho(f[0])} (in the app${email?' and by email':''})`}}
  if(n&&/\b(off|pause|stop|disable|skip|untick|hold)\b/.test(l)){const p=pickN();if(p.ask)return p;if(p.m[2])return{ask:`Reminder ${n} is already off.`};
    const ms=M.map(m=>m.slice());ms[n-1]=[p.m[0],p.m[1],1];if(A.on&&!ms.some(m=>!m[2]))return{ask:'That is the last reminder switched on. Turn reminders off instead: reminders off'};
    return{kind:'auto',args:cp({msgs:ms}),summary:`Stop sending reminder ${n}: ${short_(p.m)}`}}
  if(n&&/\b(on|resume|start|enable|tick|use)\b/.test(l)){const p=pickN();if(p.ask)return p;if(!p.m[2])return{ask:`Reminder ${n} is already on.`};
    const ms=M.map(m=>m.slice());ms[n-1]=[p.m[0],p.m[1]];return{kind:'auto',args:cp({msgs:ms}),summary:`Start sending reminder ${n} again: ${short_(p.m)}`}}
  const ev=l.match(/\bevery\s+(\d{1,2})\s*days?\b/)||(/\b(every day|daily)\b/.test(l)?[0,'1']:null);
  if(ev){const d=+ev[1];if(!(d>=1&&d<=60))return{ask:'Pick from 1 to 60 days.'};return{kind:'auto',args:cp({every:d}),summary:`Send reminders every ${d} day${d>1?'s':''} (now every ${A.every})`}}
  if(/\b(email|mail)\b/.test(l)){const off=/\b(off|no|stop|disable|without)\b|\bapp only\b/.test(l);
    if(off===!A.email)return{ask:`Reminders are already ${A.email?'sent by email too':'app only'}.`};
    return{kind:'auto',args:cp({email:!off}),summary:off?'Send reminders in the app only (no email)':'Send reminders by email too, as well as in the app'}}
  if(/\b(everyone|everybody|all customers|every customer)\b/.test(l)&&!/\b(off|stop)\b/.test(l))return{kind:'auto',args:cp({who:'all'}),summary:`Send reminders to every customer every ${A.every} days, even ones who use HarborPay often`};
  if(/\b(quiet|inactive|not active|haven'?t|dormant|idle|only inactive)\b/.test(l))return{kind:'auto',args:cp({who:'quiet'}),summary:`Send reminders only to customers who haven't made a transaction in the last ${A.every} days`};
  const on=/\b(on|start|enable|resume|yes)\b/.test(l)&&!/\b(off|stop|disable|pause|no)\b/.test(l),off=/\b(off|stop|disable|pause)\b/.test(l);
  if(on||off){const who=benWhoText(l,['reminder','reminders','callback','callbacks','call','back','promo','promos','promotion','promotions','automatic','auto','messages','message','on','off','turn','start','stop','enable','disable','pause','resume','yes','no','all','everyone','every','customers']);
    if(who)return null; // a customer was named: the per-customer switch below handles it
    if(on&&!M.some(m=>!m[2]))return{ask:'Every reminder is switched off. Turn one on first, for example: reminder 1 on'};
    if(on===!!A.on)return{ask:`Automatic reminders are already ${A.on?'on':'off'}.`};
    return{kind:'auto',args:cp({on}),summary:on?`Turn automatic reminders on (one every ${A.every} days, ${A.email?'in the app and by email':'in the app only'})`:'Turn automatic reminders off for everyone'}}
  return null}
function benRemList(){const A=db.settings.auto.nudge,M=A.msgs||[];
  return`Automatic reminders are ${A.on?'ON':'OFF'}: one every ${A.every} day${A.every>1?'s':''}, ${A.email?'in the app and by email':'in the app only'}, to ${A.who==='all'?'every customer':`customers with no transaction in the last ${A.every} days`}, 9am–7pm UTC.

${M.length?M.map((m,i)=>`${i+1}. ${m[0]}${m[2]?'  (off)':''}\n   ${m[1]}`).join('\n'):'No reminders yet.'}

Try: send reminder 1 now · edit reminder 2: Title | message · add reminder: Title | message · reminder 3 off · reminders every 2 days · reminders email on`}
/* Ben: referral reward, getting-started messages, funnel */
function benGrowth(s,l){
  if(/^(funnel|drop ?-?off|conversion|conversions|sign ?-?up funnel)\b/.test(l))return{look:'funnel'};
  if(/^(set |change |update |make |turn |show |what is |what's )?(the |my )?((referral|invite)\s+)?(rewards?|bonus)\b/.test(l)&&/\b(reward|bonus)/.test(l)&&!/^(credit|message|send|tell)/.test(l)){const R=db.settings.refReward,cp=x=>({...R,...x}),words=[];
    if(/^(referral reward|invite reward|reward)s?\s*\??$/.test(l)||/^(show|what|how)\b/.test(l))return{look:'reward'};
    const x={};const off=/\b(off|stop|disable|pause|end)\b/.test(l),on=/\b(on|start|enable|resume)\b/.test(l);
    const mm=l.match(/\bmin(?:imum)?(?: deposit)?\s*(?:of\s*)?\$?\s*(\d+(?:\.\d+)?)/);if(mm){x.minUsd=+mm[1];words.push(`minimum deposit $${+mm[1]}`)}
    const rest=mm?l.replace(mm[0],' '):l,amt=benAmount(rest.replace(/\b(referral|invite|reward|bonus)\b/g,' ')),cur=benCurrency(rest);
    if(amt>0){x.amount=amt;if(cur&&FIAT.includes(cur))x.currency=cur;words.push(`${money(x.currency||R.currency,amt)} reward`)}else if(cur&&FIAT.includes(cur)){x.currency=cur;words.push(`paid in ${cur}`)}
    if(/\bask( me)?( first)?\b|\bapprove first\b|\bmanual\b/.test(l))x.mode='approve';else if(/\bautomatic(ally)?\b|\bauto\b/.test(l))x.mode='auto';
    if(/\binviter only\b|\bonly (the )?inviter\b|\bjust (the )?inviter\b/.test(l)){x.both=false;words.push('inviter only')}else if(/\bboth\b|\beach\b|\bfriend too\b/.test(l)){x.both=true;words.push('both get it')}
    if(off)x.on=false;else if(on||Object.keys(x).length)x.on=on||R.on;
    if(!Object.keys(x).length)return{look:'reward'};
    const n=cp(x);if(!(n.amount>0&&n.amount<=1000))return{ask:'The reward must be more than 0 and at most 1,000.'};
    return{kind:'reward',args:n,summary:n.on?`Referral reward ON: ${money(n.currency,n.amount)} to the inviter${n.both?` and ${money(n.currency,n.amount)} to the friend`:''} once the friend (ID verified) makes a deposit worth $${n.minUsd} or more. ${n.mode==='auto'?'Paid automatically.':'You get an alert and approve each one first.'}`:'Turn the referral reward off'}}
  if(/^(set |change |update |edit |turn )?(the )?(getting started|welcome|onboarding)\b/.test(l)){const G=db.settings.auto.stage,cp=x=>({...G,welcome:{...G.welcome},kyc:{...G.kyc},dep:{...G.dep},...x});
    const t=s.match(/(?::|\bsaying\b)\s*(.+)$/i);
    if(/\bwelcome\b/.test(l)&&t){const p=t[1].split(/\s*\|\s*/),ti=p.length>1?p[0]:'Welcome to HarborPay, {name}! 👋',bo=p.length>1?p.slice(1).join(' | '):p[0];
      return{kind:'stage',args:cp({welcome:{on:true,title:ti.slice(0,120),body:bo.slice(0,600)}}),summary:`Set the welcome message to "${ti}" — ${bo}`}}
    if(/\b(off|stop|disable)\b/.test(l))return{kind:'stage',args:cp({on:false}),summary:'Turn getting-started messages off (welcome, finish ID check, first deposit)'};
    if(/\b(on|start|enable)\b/.test(l))return{kind:'stage',args:cp({on:true}),summary:'Turn getting-started messages on (welcome, finish ID check, first deposit)'};
    return{look:'stage'}}
  return null}
function benFunnel(){const C=db.users.filter(u=>u.role==='customer'&&u.status!=='closed'),has=(u,f)=>db.txs.some(x=>x.userId===u.id&&f(x));
  const T=[['Signed up',()=>true],['ID verified',u=>u.kyc==='verified'],['Account details',u=>Object.values(u.accts||{}).some(a=>a&&a.status&&!['none','requested','rejected'].includes(a.status))],['First deposit',u=>has(u,realDeposit)],['First withdrawal',u=>has(u,x=>x.type==='withdrawal'&&x.status==='completed')]];
  const steps=T.map(([k],i)=>[k,C.filter(u=>T.slice(i).some(x=>x[1](u)))]);
  const n0=steps[0][1].length||1;
  return'Sign-up funnel (all time):\n'+steps.map(([k,l],i)=>`${i+1}. ${k}: ${l.length} (${Math.round(l.length/n0*100)}%)${i?` — ${steps[i-1][1].length-l.length} stopped here`:''}`).join('\n')+`\n\nBiggest drop: ${(()=>{let w=1,d=-1;for(let i=1;i<steps.length;i++){const x=steps[i-1][1].length-steps[i][1].length;if(x>d){d=x;w=i}}return`${steps[w-1][0]} → ${steps[w][0]} (${d} people)`})()}. Full chart in Statistics.`}
function benReward(){const R=db.settings.refReward,paid=db.users.filter(u=>u.refRewarded&&!u.refRewarded.declined).length,wait=db.users.filter(u=>u.refPending);
  return`Referral reward is ${R.on?'ON':'OFF'}: ${money(R.currency,R.amount)} to the inviter${R.both?' and the same to the friend':' only'}, once the friend is ID verified and makes a deposit worth $${R.minUsd} or more. ${R.mode==='auto'?'Paid automatically.':'You approve each one first.'} Paid so far: ${paid} time${paid===1?'':'s'}.${wait.length?`\nWaiting for you (${wait.length}): `+wait.map(u=>`${u.name} (invited by ${(byId(u.referredBy)||{}).name||'?'})`).join(', ')+' — say "approve reward <name>" or "decline reward <name> because …"':''}
Try: referral reward on · referral reward 10 usd min 100 · referral reward inviter only · referral reward ask first · referral reward automatic · referral reward off`}
function benStage(){const G=db.settings.auto.stage;return`Getting-started messages are ${G.on?'ON':'OFF'} (${G.email?'app and email':'app only'}):
• Welcome (at sign-up): ${G.welcome.on?'"'+G.welcome.title+'"':'off'}
• Finish your ID check (from day ${G.kyc.after}): ${G.kyc.on?'"'+G.kyc.title+'"':'off'}
• First deposit (from day ${G.dep.after}): ${G.dep.on?'"'+G.dep.title+'"':'off'}
Each one repeats every ${G.every} days, up to ${G.max} times, until the customer does it. Edit them in Messages.`}
const benFirst=t=>{let q=false;for(let i=0;i<t.length;i++){if(t[i]==='"')q=!q;else if(!q&&t[i]==='.'&&t[i+1]===' '&&!/\d/.test(t[i-1]||''))return t.slice(0,i)}return t.replace(/\.$/,'')};
const BEN_PLANS=new Map();
const BEN_CUR={usd:'USD',dollar:'USD',dollars:'USD','$':'USD',eur:'EUR',euro:'EUR',euros:'EUR','€':'EUR',gbp:'GBP',pound:'GBP',pounds:'GBP','£':'GBP',mxn:'MXN',peso:'MXN',pesos:'MXN',cop:'COP',btc:'BTC',bitcoin:'BTC',eth:'ETH',usdt:'USDT',usdc:'USDC'};
const benCustomers=()=>db.users.filter(u=>u.role==='customer'&&u.status!=='closed');
function benFind(q){
  q=String(q||'').toLowerCase().replace(/[^a-z0-9@._+\- ]/g,' ').replace(/\s+/g,' ').trim();if(!q)return[];
  const L=benCustomers(),em=L.filter(u=>u.email.toLowerCase()===q);if(em.length)return em;
  const id=L.filter(u=>u.id.toLowerCase()===q);if(id.length)return id;
  const full=L.filter(u=>u.name.toLowerCase()===q);if(full.length)return full;
  const w=q.split(' ').filter(x=>x.length>1);
  const all=L.filter(u=>{const h=(u.name+' '+u.email).toLowerCase();return w.length&&w.every(x=>h.includes(x))});if(all.length)return all;
  return L.filter(u=>{const h=u.name.toLowerCase().split(' ').concat(u.email.toLowerCase().split('@')[0]);return w.some(x=>h.some(y=>y.startsWith(x)))});
}
const benWho=u=>`${u.name} (${u.email})`;
function benAmount(s){const m=String(s).replace(/,/g,'').match(/(?:^|[^a-z0-9.])[$€£]?\s?(\d+(?:\.\d+)?)\s?(k|m)?(?![\d-])/i);if(!m)return null;let n=parseFloat(m[1]);if(m[2])n*=m[2].toLowerCase()==='k'?1e3:1e6;return n}
function benCurrency(s){const t=String(s).toLowerCase();if(/\$/.test(t)&&!/\b(eur|gbp|mxn|cop)\b/.test(t))return'USD';if(/€/.test(t))return'EUR';if(/£/.test(t))return'GBP';
  for(const w of t.split(/[^a-z$€£]+/))if(BEN_CUR[w])return BEN_CUR[w];return null}
/* strip command words so what is left names the customer */
function benWhoText(s,extra){let t=' '+String(s).toLowerCase()+' ';
  const words=['ben','please','pls','kindly','can','you','could','the','a','an','to','for','of','from','on','in','into','account','accounts','wallet','balance','balances','user','customer','client','his','her','their','my','and','with','by','now','with','me','i','want','need','money','funds','amount','it','is','that','this','dollar','dollars','euro','euros','pound','pounds','peso','pesos','usd','eur','gbp','mxn','cop','btc','eth','usdt','usdc','bitcoin'].concat(extra||[]);
  t=t.replace(/[$€£]?\s?\d[\d,]*(\.\d+)?\s?(k|m)?\b/g,' ').replace(/[$€£:;,!?"']/g,' ');
  for(const w of words)t=t.replace(new RegExp('\\s'+w.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'(?=\\s)','g'),' ');
  return t.replace(/\s+/g,' ').trim()}
const benAfter=(s,re)=>{const m=String(s).match(re);return m?m[1].trim().replace(/^["']|["']$/g,''):''};
const BEN_HELP=`Here is what I can do. Type it the way you would say it.

Money
• credit demo usd 10 — add money that arrived to a customer
• reverse demo eur 500 — take back a deposit credited by mistake
• approve deposit demo / decline deposit demo because name does not match
• fail deposit demo because returned by the sending bank
• approve withdrawal demo / reject withdrawal demo because wrong wallet

Customers
• balance demo — balances, checks and status
• find maria — search customers
• suspend demo / unsuspend demo
• delete demo because suspicious activity (add "quietly" to skip the email)
• unblock someone@email.com
• approve kyc demo / reject kyc demo because photo is blurry
• verify email demo
• change pin demo 4821 (add "no pause" to skip the 24-hour pause)
• lift pause demo
• set dob demo 1990-05-21
• reminders on demo / reminders off demo
• invite code for demo

Reminders (automatic callback messages)
• reminders — see them all, numbered
• send reminder 6 now — to every customer, app and email
• send reminder 6 to demo
• add reminder: Get paid in 5 currencies | Receive USD, EUR… and withdraw anytime
• edit reminder 2: New title | New message
• delete reminder 4 / reminder 3 off / reminder 3 on
• reminders every 2 days / reminders email on / reminders email off
• reminders to everyone / reminders to quiet customers
• reminders on / reminders off (everyone)

Growth
• funnel — where sign-ups stop
• referral reward — see the reward
• referral reward on / off
• referral reward 10 usd min 100 / referral reward inviter only / both
• referral reward ask first / referral reward automatic
• approve reward fola / decline reward fola because same person
• getting started on / off
• welcome message: Welcome, {name}! | Your account is ready…

Messages
• message demo: your account is ready
• message everyone: we are closed on Monday

Whole app
• pending — everything waiting for you
• pause withdrawals / resume withdrawals
• close sign-ups / open sign-ups
• fees / set usd fee 1.5% / set mxn fee 30 fixed / set fee 1% (every currency)

Nothing changes until you tap Confirm.`;

/* turn one plain command into a step: {say} for an answer, {ask} when unclear, or {kind,args,summary} for a change */
function benParse(raw){
  const s=String(raw||'').trim().replace(/^(hey |hi |ok |okay )?ben[\s,:!-]*/i,'').trim(),l=s.toLowerCase();
  if(!l||/^(help|commands|what can you do|\?|menu)\b/.test(l))return{say:BEN_HELP};
  const pick=(q,extra)=>{const who=benWhoText(q,extra);if(!who)return{err:'Which customer? Add their name or email.'};const f=benFind(who);
    if(!f.length)return{err:`I could not find a customer matching "${who}".`};if(f.length>1)return{err:`"${who}" matches ${f.length} customers. Which one?`,choices:f.slice(0,6)};return{u:f[0]}};
  const reason=()=>benAfter(s,/(?:because|reason[:\s]|why[:\s]|note[:\s]|-\s)(.+)$/i);
  const noReason=q=>q.replace(/(?:because|reason[:\s]|why[:\s]|note[:\s]|\s-\s).+$/i,' ');
  // ---- whole app ----
  if(/^(pending|what'?s pending|what is pending|queue|todo|to do|summary|overview|today|status|dashboard)\b/.test(l))return{look:'pending'};
  if(/\b(pause|stop|halt|freeze|disable)\b.*\bwithdraw/.test(l)&&!/\bfor\b|\bdemo\b/.test(l)&&benFind(benWhoText(l,['pause','stop','halt','freeze','disable','withdrawal','withdrawals','all','every','everyone'])).length!==1)
    return{kind:'settings',args:{withdrawalsPaused:true},summary:'Pause withdrawals for every customer'};
  if(/\b(resume|unpause|restart|enable|open|allow|start)\b.*\bwithdraw/.test(l)&&!/\bfor\b/.test(l)&&benFind(benWhoText(l,['resume','unpause','restart','enable','open','allow','start','withdrawal','withdrawals','all','again'])).length!==1)
    return{kind:'settings',args:{withdrawalsPaused:false},summary:'Turn withdrawals back on for every customer'};
  if(/\b(close|stop|disable|pause|turn off)\b.*\b(sign ?-?ups?|registrations?|new accounts?)/.test(l))return{kind:'settings',args:{registrations:false},summary:'Close sign-ups (no new accounts)'};
  if(/\b(open|allow|enable|resume|turn on)\b.*\b(sign ?-?ups?|registrations?|new accounts?)/.test(l))return{kind:'settings',args:{registrations:true},summary:'Open sign-ups again'};
  if(/^(fees|show fees|what are the fees|fee list|the fees)\??$/.test(l))return{say:'Fees by currency: '+feeText()+`. Crypto balances: ${+((+db.settings.fee||0)*100).toFixed(3)}%.\nTry: set usd fee 1.5% · set mxn fee 30 fixed · set fee 1% (every currency)`};
  if(/\bfees?\b/.test(l)&&/\b(set|change|make|update|charge)\b/.test(l)){feeSetup();const n=benAmount(l.replace(/\b(usd|eur|gbp|mxn|cop)\b/g,' ')),cur=(l.match(/\b(usd|eur|gbp|mxn|cop)\b/)||[])[1],C=cur?cur.toUpperCase():(/[€]/.test(l)?'EUR':/[£]/.test(l)?'GBP':null);
    const pct=/%|\bpercent(age)?\b/.test(l),flat=/\bfixed\b|\bflat\b|\bamount\b|[$€£]/.test(l)&&!pct;
    if(n==null)return{ask:'What should the fee be? For example: set usd fee 1.5% or set mxn fee 30 fixed'};
    if(!pct&&!flat)return{ask:`Is that ${n}% or a fixed ${n}? Say for example "set ${(C||'usd').toLowerCase()} fee ${n}%" or "set ${(C||'usd').toLowerCase()} fee ${n} fixed".`};
    const fees=JSON.parse(JSON.stringify(db.settings.fees));
    if(pct){const f=n/100;if(!(f>=0&&f<=0.1))return{ask:'A percentage fee can be from 0% to 10%.'};for(const c of C?[C]:FIAT)fees[c]={...fees[c],mode:'pct',pct:+f.toFixed(6)};
      return{kind:'settings',args:{fees},summary:`${C?`${C} fee`:'Fee for every currency'}: ${+(f*100).toFixed(3)}% of each conversion and withdrawal (now ${C?feeLabel(C):feeText()})`}}
    const c2=C||(/\$/.test(l)?'USD':null);if(!c2)return{ask:`Which currency is the fixed ${n} in? For example: set mxn fee ${n} fixed`};
    if(toUsd(c2,n)>1000)return{ask:`That is more than the same as $1,000. Choose a smaller ${c2} fee.`};fees[c2]={...fees[c2],mode:'flat',flat:Math.round(n*100)/100};
    return{kind:'settings',args:{fees},summary:`${c2} fee: a fixed ${money(c2,n)} per conversion and withdrawal (now ${feeLabel(c2)})`}}
  // ---- automatic reminders (callback messages) ----
  {const g=benGrowth(s,l);if(g)return g}
  if(REM_WORDS.test(l)){const r=benRem(s,l);if(r)return r}
  // ---- messages ----
  if(/^(message|msg|tell|send|notify|email|announce|broadcast)\b/.test(l)){
    const m=s.match(/^\S+\s+(?:a\s+)?(?:message\s+)?(?:to\s+)?([^\n]+?)\s*(?::|\bthat\b|\bsaying\b|\bsay\b|\s-\s|")\s*([\s\S]+)$/i);
    if(!m)return{ask:'Write it like: message demo: your account is ready'};
    let text=m[2].trim().replace(/^["']|["']$/g,'');const to=m[1].toLowerCase().trim(),email=/\bemail\b|\bby mail\b/.test(l);
    const everyone=/^(all|everyone|everybody|all customers|all users|customers|users)$/.test(to)||/^announce|^broadcast/.test(l);
    let title=text.length>60?'Message from HarborPay':text.replace(/[.!]+$/,'');
    {const ls=text.split('\n');if(ls.length>1&&ls[0].trim().length<=90&&ls.slice(1).join('').trim()){title=ls[0].trim().replace(/[:.]+$/,'');text=ls.slice(1).join('\n').trim()}} // first line as the headline
    if(everyone){const n=benCustomers().length;return{kind:'message',args:{to:'all',title,body:text,inApp:true,email},summary:`Send to all ${n} customers${email?' (in the app and by email)':' (in the app)'}. Headline: "${title}". Message: "${text}"`}}
    const p=pick(to);if(p.err)return{ask:p.err,choices:p.choices};
    return{kind:'message',args:{to:[p.u.id],title,body:text,inApp:true,email},summary:`Send ${benWho(p.u)}${email?' (in the app and by email)':' (in the app)'}: "${text}"`};
  }
  // ---- look-ups ----
  if(/^(find|search|look ?up|lookup|who is|who's)\b/.test(l)){const q=l.replace(/^(find|search|look ?up|lookup|who is|who's)\s*/,'');const f=benFind(q);
    return{look:'find',q,list:f}}
  if(/^(balance|balances|show|info|details|check|view|open|profile|account)\b/.test(l)||/\bbalance\b/.test(l)&&!/\b(credit|add|reverse|remove|deduct)\b/.test(l)){const p=pick(l,['show','info','details','check','view','open','profile','what','whats',"what's",'how','much','does','have','has']);
    if(p.err)return{ask:p.err,choices:p.choices};return{look:'user',u:p.u}}
  // ---- money ----
  if(/^(unblock|allow)\b.*@/.test(l)){const em=(l.match(/[^\s:]+@[^\s:]+/)||[])[0];if(!(db.blocked||[]).some(x=>x.email===em))return{ask:`${em} is not blocked.`};
    return{kind:'unblock',args:{email:em},summary:`Unblock ${em} so it can be used to sign up again`}}
  if(/^(delete|remove|close|terminate|kill|erase)\b.*\b(account|user|customer)?/.test(l)&&!/\b(notification|message|announcement)s?\b/.test(l)){const why=reason();
    const p=pick(noReason(l),['delete','remove','close','terminate','kill','erase','account','user','customer','permanently','forever','suspicious','fraud','activity','silently','quietly','dont','tell',"don't",'notify','email','block','unblock','without']);if(p.err)return{ask:p.err,choices:p.choices};
    if(!why)return{ask:`Why are you deleting ${p.u.name}'s account? Add the reason, for example: delete ${first(p.u).toLowerCase()} because suspicious activity`};
    const u=p.u,held=ALLC.filter(c=>(u.bal[c]||0)>0).map(c=>FIAT.includes(c)?money(c,u.bal[c]):+Number(u.bal[c]).toFixed(8)+' '+c),pend=db.txs.filter(t=>t.userId===u.id&&t.status==='pending').length,quiet=/\b(silently|quietly|don'?t tell|without telling|no email)\b/.test(l);
    return{kind:'delete',args:{userId:u.id,reason:why,block:!/\bdon'?t block|no block|without block/.test(l),tell:!quiet},summary:`DELETE ${benWho(u)}'s account. Reason (admins only): "${why}". They are signed out everywhere and cannot sign in again${/\bdon'?t block|no block/.test(l)?'':'; their email is blocked from signing up again'}.${pend?` ${pend} pending item${pend>1?'s are':' is'} cancelled.`:''}${held.length?` Their money stays held on the closed account: ${held.join(', ')}.`:''} ${quiet?'No email is sent.':'They get a short email saying the account was closed (no reason given).'}`}}
  const isCredit=/^(credit|fund|add|deposit|top ?up|topup|load|give|pay)\b/.test(l);
  if(isCredit){const amt=benAmount(l),cur=benCurrency(l),note=benAfter(s,/(?:note[:\s]|ref(?:erence)?[:\s])(.+)$/i);
    const p=pick(noReason(l.replace(/(?:note[:\s]|ref(?:erence)?[:\s]).+$/,'')),['credit','fund','add','deposit','top','up','topup','load','give','pay']);if(p.err)return{ask:p.err,choices:p.choices};
    if(!(amt>0))return{ask:`How much should I credit to ${p.u.name}? For example: credit ${first(p.u).toLowerCase()} usd 10`};
    if(!cur)return{ask:`Which currency? USD, EUR, GBP, MXN or COP. For example: credit ${first(p.u).toLowerCase()} usd ${amt}`};
    if(!ALLC.includes(cur))return{ask:'I can only credit USD, EUR, GBP, MXN, COP, BTC, ETH, USDT or USDC.'};
    return{kind:'credit',args:{userId:p.u.id,currency:cur,amount:amt,note},summary:`Credit ${money(cur,amt)} to ${benWho(p.u)}. ${cur} balance ${money(cur,p.u.bal[cur]||0)} → ${money(cur,(p.u.bal[cur]||0)+amt)}. They get a "Deposit received" notice.`}}
  if(/^(reverse|debit|deduct|remove|take back|takeback|undo|subtract|minus|withdraw from|charge|refund back|correct)\b/.test(l)){
    const amt=benAmount(l),cur=benCurrency(l),tell=/\b(tell|notify|inform|let .* know)\b/.test(l);
    const p=pick(noReason(l),['reverse','debit','deduct','remove','take','back','takeback','undo','subtract','minus','withdraw','charge','correct','deposit','duplicate','double','credit','credited','last','tell','notify','inform']);if(p.err)return{ask:p.err,choices:p.choices};
    const L=db.txs.filter(t=>t.userId===p.u.id&&t.type==='deposit'&&t.status==='completed'&&(!cur||t.currency===cur)&&(!(amt>0)||Math.abs(t.amount-amt)<1e-9)).sort((a,b)=>(b.creditedAt||b.ts)-(a.creditedAt||a.ts));
    if(!L.length)return{ask:`I found no credited ${cur||''} deposit${amt>0?' of '+(cur?money(cur,amt):amt):''} for ${p.u.name} to reverse. Balances can only be reduced by reversing a deposit.`};
    const t=L[0],have=p.u.bal[t.currency]||0;
    if(have+1e-9<t.amount)return{ask:`${p.u.name}'s ${t.currency} balance is ${money(t.currency,have)}, less than the ${money(t.currency,t.amount)} deposit. They may have spent or withdrawn it, so it cannot be reversed.`};
    return{kind:'reverse',args:{txId:t.id,reason:reason()||'Duplicate credit',tell},summary:`Reverse the ${money(t.currency,t.amount)} deposit credited ${new Date(t.creditedAt||t.ts).toISOString().slice(0,16).replace('T',' ')} UTC for ${benWho(p.u)}. ${t.currency} balance ${money(t.currency,have)} → ${money(t.currency,have-t.amount)}. ${tell?'The customer is told.':'Done quietly: the customer is not told.'}`}}
  const failed=/\bfail(ed|s)?\b/.test(l)&&/\bdeposit/.test(l),approve=!failed&&/^(approve|accept|confirm|ok|okay|verify|pass|clear|mark)\b/.test(l),reject=failed||/^(reject|decline|deny|refuse|cancel|fail)\b/.test(l);
  if(approve||reject){
    const why=reason(),rest=noReason(l),ex=['approve','accept','confirm','ok','okay','verify','pass','clear','mark','reject','decline','deny','refuse','cancel','fail','deposit','deposits','withdrawal','withdrawals','withdraw','kyc','id','identity','documents','document','docs','email','dob','birthday','birth','date','invite','code','request','pending','as','verified','paid','sent','reward','rewards','bonus','referral','failed','fails','declined','rejected','because'];
    const what=/\breward|\bbonus/.test(rest)?'reward':/\bkyc\b|\bidentity\b|\bdocuments?\b|\bdocs\b|\bid\b/.test(rest)?'kyc':/\bwithdraw/.test(rest)?'withdrawal':/\bdeposit/.test(rest)?'deposit':/\bemail\b/.test(rest)?'email':/\bdob\b|\bbirth/.test(rest)?'dob':/\binvite|\bcode\b/.test(rest)?'invite':null;
    if(!what)return{ask:'Approve or reject what? Say deposit, withdrawal, kyc, email, dob, invite or reward. For example: approve deposit demo'};
    const p=pick(rest,ex);if(p.err)return{ask:p.err,choices:p.choices};const u=p.u;
    if(what==='reward'){if(!u.refPending)return{ask:`${u.name} has no referral reward waiting for approval.`};const R=db.settings.refReward,iv=byId(u.referredBy)||{};
      return reject?{kind:'refdecide',args:{userId:u.id,ok:false,note:why},summary:`Decline the referral reward for ${u.name} (invited by ${iv.name})${why?`. Note: ${why}`:''}`}
        :{kind:'refdecide',args:{userId:u.id,ok:true},summary:`Pay the referral reward: ${money(R.currency,R.amount)} to ${iv.name}${R.both?` and ${money(R.currency,R.amount)} to ${u.name}`:''}`}}
    if(what==='email'){if(reject)return{ask:'I can mark an email verified, but not reject it.'};if(u.ev&&u.ev.status==='verified')return{ask:`${u.name}'s email is already verified.`};
      return{kind:'email',args:{userId:u.id,action:'verify'},summary:`Mark ${u.name}'s (${u.email}) email as verified`}}
    if(what==='kyc'){const k=db.kycs.find(x=>x.userId===u.id&&x.status==='pending');if(!k)return{ask:`${u.name} has no identity check waiting (status: ${u.kyc||'not started'}).`};
      return reject?{kind:'kyc',args:{id:k.id,status:'rejected',note:why||'Please check your details and submit again.'},summary:`Decline ${u.name}'s (${u.email}) identity check (${k.idType}). Reason told to them: "${why||'Please check your details and submit again.'}"`}
        :{kind:'kyc',args:{id:k.id,status:'verified'},summary:`Approve ${u.name}'s (${u.email}) identity check (${k.idType}, ${k.fullName})`}}
    if(what==='dob'){if(!u.dobPending)return{ask:`${u.name} has no date of birth waiting for confirmation.`};
      return{kind:'dob',args:{userId:u.id,ok:!reject,note:why},summary:`${reject?'Decline':'Confirm'} ${u.name}'s (${u.email}) date of birth ${u.dobPending.dob}`}}
    if(what==='invite'){const i=db.invites.find(x=>x.userId===u.id&&x.status==='pending');
      if(reject){if(!i)return{ask:`${u.name} has no invite request waiting.`};return{kind:'invite',args:{id:i.id,decline:true,note:why},summary:`Decline ${u.name}'s (${u.email}) invite code request`}}
      return{kind:'invite',args:i?{id:i.id}:{userId:u.id},summary:i?`Approve ${u.name}'s (${u.email}) invite request and send them a one-time code (valid 1 hour)`:`Send ${benWho(u)} a new one-time invite code (valid 1 hour)`}}
    const amt=benAmount(rest),cur=benCurrency(rest);
    const L=db.txs.filter(t=>t.userId===u.id&&t.type===what&&t.status==='pending'&&(!cur||t.currency===cur)&&(!(amt>0)||Math.abs(t.amount-amt)<1e-9));
    if(!L.length)return{ask:`${u.name} has no pending ${what}${cur?' in '+cur:''}${amt>0?' of '+amt:''}.`};
    if(L.length>1)return{ask:`${u.name} has ${L.length} pending ${what}s: ${L.map(t=>money(t.currency,t.amount)).join(', ')}. Add the currency and amount, for example: approve ${what} ${first(u).toLowerCase()} ${L[0].currency.toLowerCase()} ${L[0].amount}`};
    const t=L[0],dsc=what==='withdrawal'?(t.d.method==='bank'?`${money(t.currency,t.d.receive)} to ${bankDest(t.d)}`:`${t.d.receive} ${t.d.asset} on ${t.d.network} to ${String(t.d.address).slice(0,10)}…`):money(t.currency,t.amount);
    if(reject&&what==='deposit'){const r=why||(failed?'The transfer did not arrive.':'Declined.');return{kind:'depresult',args:{txId:t.id,result:failed?'failed':'rejected',reason:r},summary:`Mark ${benWho(u)}'s deposit of ${money(t.currency,t.amount)} as ${failed?'FAILED':'DECLINED'}. Nothing is added to their balance. Reason they see: "${r}"`}}
    if(reject)return{kind:'settle',args:{id:t.id,status:'rejected',note:why||'Rejected.'},summary:`Reject ${u.name}'s (${u.email}) ${what} of ${money(t.currency,t.amount)}${what==='withdrawal'?' (the money goes back to their balance)':''}. Reason told to them: "${why||'Rejected.'}"`};
    return what==='deposit'?{kind:'credit',args:{txId:t.id,userId:u.id,currency:t.currency,amount:t.amount},summary:`Approve ${u.name}'s (${u.email}) deposit and credit ${dsc}. Only do this if the money is on your bank statement.`}
      :{kind:'settle',args:{id:t.id,status:'completed'},summary:`Approve ${u.name}'s (${u.email}) withdrawal: ${dsc}. Only do this after you have sent the money.`}}
  if(/^(suspend|block|freeze|ban|lock|disable)\b/.test(l)){const p=pick(l,['suspend','block','freeze','ban','lock','disable']);if(p.err)return{ask:p.err,choices:p.choices};
    if(p.u.status==='suspended')return{ask:`${p.u.name} is already suspended.`};return{kind:'status',args:{id:p.u.id,status:'suspended'},summary:`Suspend ${benWho(p.u)}. They cannot use their account until you unsuspend it.`}}
  if(/^(unsuspend|unblock|unfreeze|unban|unlock|activate|reactivate|enable|restore)\b/.test(l)){const p=pick(l,['unsuspend','unblock','unfreeze','unban','unlock','activate','reactivate','enable','restore']);if(p.err)return{ask:p.err,choices:p.choices};
    if(p.u.status==='active')return{ask:`${p.u.name}'s account is already active.`};return{kind:'status',args:{id:p.u.id,status:'active'},summary:`Reactivate ${p.u.name}'s (${p.u.email}) account`}}
  if(/\bpin\b/.test(l)&&/\b(set|change|reset|new|update|make)\b/.test(l)){const pin=(l.match(/\b(\d{4})\b/)||[])[1],hold=!/\bno (pause|hold)\b|\bwithout (a )?(pause|hold)\b|\bdon'?t pause\b/.test(l);
    const p=pick(l.replace(/\b\d{4}\b/,' '),['set','change','reset','new','update','make','pin','transaction','no','pause','hold','without','dont',"don't"]);if(p.err)return{ask:p.err,choices:p.choices};
    if(!pin)return{ask:`What 4-digit PIN should ${p.u.name} have? For example: change pin ${first(p.u).toLowerCase()} 4821`};
    return{kind:'pin',args:{userId:p.u.id,pin,hold},summary:`Change ${p.u.name}'s (${p.u.email}) transaction PIN to ${pin}.${hold?' Withdrawals pause for 24 hours.':' No withdrawal pause.'} They are told their PIN was changed.`}}
  if(/\b(lift|remove|end|cancel|clear)\b.*\b(pause|hold)\b|\bunpause\b/.test(l)){const p=pick(l,['lift','remove','end','cancel','clear','pause','hold','unpause','withdrawal','withdrawals']);if(p.err)return{ask:p.err,choices:p.choices};
    if(!(p.u.wdHold>Date.now()))return{ask:`${p.u.name}'s withdrawals are not paused.`};return{kind:'hold',args:{userId:p.u.id},summary:`Lift the withdrawal pause for ${benWho(p.u)}`}}
  if(/^(verify|mark)\b.*\bemail\b|\bemail\b.*\bverif/.test(l)){const p=pick(l,['verify','mark','email','verified','as']);if(p.err)return{ask:p.err,choices:p.choices};
    return{kind:'email',args:{userId:p.u.id,action:'verify'},summary:`Mark ${p.u.name}'s (${p.u.email}) email as verified`}}
  if(/\b(dob|birthday|date of birth|born)\b/.test(l)&&/\d{4}-\d{2}-\d{2}/.test(l)){const dob=l.match(/\d{4}-\d{2}-\d{2}/)[0];const p=pick(l.replace(dob,' '),['set','change','update','dob','birthday','date','birth','born','is']);if(p.err)return{ask:p.err,choices:p.choices};
    return{kind:'setdob',args:{userId:p.u.id,dob},summary:`Set ${p.u.name}'s (${p.u.email}) date of birth to ${dob}${p.u.dob?' (was '+p.u.dob+')':''}`}}
  if(/\breminders?\b/.test(l)){const on=/\b(on|enable|start|yes)\b/.test(l)&&!/\b(off|disable|stop|no)\b/.test(l);const p=pick(l,['reminder','reminders','on','off','enable','disable','start','stop','turn','yes','no']);if(p.err)return{ask:p.err,choices:p.choices};
    return{kind:'reminders',args:{userId:p.u.id,on},summary:`Turn reminders ${on?'on':'off'} for ${benWho(p.u)}`}}
  if(/\binvite\b|\breferral code\b/.test(l)){const p=pick(l,['invite','code','codes','referral','send','give','make','create','new','generate']);if(p.err)return{ask:p.err,choices:p.choices};
    const i=db.invites.find(x=>x.userId===p.u.id&&x.status==='pending');return{kind:'invite',args:i?{id:i.id}:{userId:p.u.id},summary:`Send ${benWho(p.u)} a one-time invite code (valid 1 hour)`}}
  // a bare name: show that customer
  if(l.split(' ').length<=3){const f=benFind(l);if(f.length===1)return{look:'user',u:f[0]}}
  return null;
}
function benLook(st){
  if(st.look==='find'){if(!st.list.length)return`No customers match "${st.q}".`;return`${st.list.length} customer${st.list.length>1?'s':''} found:\n`+st.list.slice(0,15).map(u=>`• ${u.name} — ${u.email} — ${u.status}, ID check ${u.kyc||'none'}`).join('\n')+(st.list.length>15?`\n…and ${st.list.length-15} more. Add more of the name.`:'')}
  if(st.look==='user'){const u=st.u,bal=ALLC.filter(c=>(u.bal[c]||0)>0).map(c=>`${c} ${FIAT.includes(c)?money(c,u.bal[c]):+Number(u.bal[c]).toFixed(6)}`).join(' · ')||'all zero';
    const pend=db.txs.filter(t=>t.userId===u.id&&t.status==='pending'),last=db.txs.filter(t=>t.userId===u.id).slice(0,4);
    return`${u.name} — ${u.email}${u.phone?' — '+u.phone:''}
Country ${u.country||'—'} · account ${u.status} · ID check ${u.kyc||'none'} · email ${u.ev?u.ev.status:'—'}${u.dob?' · born '+u.dob:''}${u.wdHold>Date.now()?' · withdrawals paused until '+new Date(u.wdHold).toISOString().slice(0,16).replace('T',' ')+' UTC':''}
Balances: ${bal}
${pend.length?'Waiting for you: '+pend.map(t=>`${t.type} ${money(t.currency,t.amount)}`).join(', '):'Nothing waiting for you.'}
${last.length?'Recent: '+last.map(t=>`${t.type} ${money(t.currency,t.amount)} (${t.status})`).join(', '):'No transactions yet.'}`}
  if(st.look==='rem')return benRemList();
  if(st.look==='funnel')return benFunnel();if(st.look==='reward')return benReward();if(st.look==='stage')return benStage();
  if(st.look==='pending'){const by=(type)=>db.txs.filter(t=>t.type===type&&t.status==='pending'),dep=by('deposit'),wd=by('withdrawal'),C=benCustomers();
    const k=db.kycs.filter(x=>x.status==='pending'),ev=C.filter(u=>u.ev&&u.ev.status==='requested'),inv=db.invites.filter(i=>i.status==='pending'),dob=C.filter(u=>u.dobPending),tk=db.tickets.filter(t=>t.status==='open'&&t.needsHuman),ac=C.filter(u=>Object.values(u.accts||{}).some(a=>a&&a.status==='requested'));
    const nm=id=>{const u=byId(id);return u?u.name:'?'},lines=[];
    if(dep.length)lines.push(`Deposits (${dep.length}): `+dep.slice(0,8).map(t=>`${nm(t.userId)} ${money(t.currency,t.amount)}`).join(', '));
    if(wd.length)lines.push(`Withdrawals (${wd.length}): `+wd.slice(0,8).map(t=>`${nm(t.userId)} ${money(t.currency,t.amount)}`).join(', '));
    if(k.length)lines.push(`ID checks (${k.length}): `+k.slice(0,8).map(x=>nm(x.userId)).join(', '));
    if(ac.length)lines.push(`Account detail requests (${ac.length}): `+ac.slice(0,8).map(u=>u.name).join(', '));
    if(ev.length)lines.push(`Email checks (${ev.length}): `+ev.slice(0,8).map(u=>u.name).join(', '));
    if(inv.length)lines.push(`Invite requests (${inv.length}): `+inv.slice(0,8).map(i=>nm(i.userId)).join(', '));
    if(dob.length)lines.push(`Dates of birth to confirm (${dob.length}): `+dob.slice(0,8).map(u=>u.name).join(', '));
    const rw=C.filter(u=>u.refPending);if(rw.length)lines.push(`Referral rewards to approve (${rw.length}): `+rw.slice(0,8).map(u=>u.name).join(', '));
    if(tk.length)lines.push(`Support chats needing a person (${tk.length}): `+tk.slice(0,8).map(t=>nm(t.userId)).join(', '));
    const s=db.settings;
    return(lines.length?'Waiting for you:\n• '+lines.join('\n• '):'Nothing is waiting for you.')+`\n\n${C.length} customers · withdrawals ${s.withdrawalsPaused?'PAUSED':'on'} · sign-ups ${s.registrations===false?'closed':'open'} · fee ${feeText()}`}
  return'';
}
/* run a route exactly as the admin's own button would */
function benCall(req,key,payload){return new Promise((ok,no)=>{const h=routes[key];if(!h)return no(fail(500,'Missing action'));
  const fr=new (require('events').EventEmitter)();fr.headers=req.headers;fr.socket=req.socket;fr.method=key.split(' ')[0];fr.destroy=()=>{};
  const fres={code:200,writeHead(c){this.code=c},setHeader(){},end(x){let j={};try{j=x?JSON.parse(x):{}}catch{}this.code>=400?no(fail(this.code,j.error||'That did not work.')):ok(j)}};
  Promise.resolve().then(()=>h(fr,fres,new URL('http://x'+key.split(' ')[1]))).catch(no);setImmediate(()=>{fr.emit('data',JSON.stringify(payload||{}));fr.emit('end')})})}
/* ---- Ben: paste a block of bank details and he fills in the right customer's account details ---- */
const BB_KEYS=[[/^(beneficiary|account ?holder|holder|account)( name)?$|^name( on (the )?account)?$|^beneficiary$/,'accountName'],[/^bank( name)?$|^name of bank$/,'bankName'],[/^bank('?s)? address$/,'bankAddress'],
  [/^(bic|swift|bic\/swift|swift\/bic|swift code|bic code)$/,'bic'],[/^iban$/,'iban'],[/^(account|acct)( number| no\.?| #)$|^account no$/,'accountNumber'],[/^(routing|aba|ach routing|wire routing)( number| no\.?)?$/,'routingNumber'],
  [/^sort ?code$/,'sortCode'],[/^clabe$/,'clabe'],[/^(bre-?b|bre-?b key|llave|llave bre-?b)$/,'brebKey'],[/^currency$/,'currency'],[/^(customer|user|for)$/,'customer']];
const bbNorm=s=>String(s||'').normalize('NFD').replace(/[̀-ͯ]/g,'').toUpperCase().replace(/[^A-Z0-9 ]/g,' ').replace(/\s+/g,' ').trim();
function bbParse(text){const lines=String(text).replace(/\r/g,'').split('\n').map(l=>l.trim()),f={},extra=[];let pend=null;
  const put=(label,val)=>{val=val.trim();if(!val)return;const l=label.toLowerCase().replace(/\s+/g,' ').trim();const k=(BB_KEYS.find(([re])=>re.test(l))||[])[1];
    if(k&&!f[k])f[k]=val;else extra.push([(t=>t.charAt(0).toUpperCase()+t.slice(1))(label.trim()).replace(/\b(iban|bic|swift|aba|clabe)\b/gi,m=>m.toUpperCase()),val])};
  for(const l of lines){if(!l){continue}const m=l.match(/^([A-Za-z][A-Za-z /'()#.-]{1,40}?)\s*[:：]\s*(.*)$/);
    if(m){if(pend)pend=null;if(m[2].trim())put(m[1],m[2]);else pend=m[1];continue}
    if(pend){put(pend,l);pend=null}}
  return{f,extra,n:Object.keys(f).length+extra.length}}
const bbLooks=t=>{const p=bbParse(t);return p.n>=2&&(p.f.iban||p.f.accountNumber||p.f.clabe||p.f.brebKey||p.f.routingNumber||p.f.sortCode)&&!/^\s*(?:ben[\s,:]*)?(message|msg|tell|send|notify|email|announce|broadcast)\b/i.test(t)?p:null};
function bbCurrency(f){const c=String(f.currency||'').toUpperCase().match(/USD|EUR|GBP|MXN|COP/);if(c)return c[0];
  if(f.clabe||/^\d{18}$/.test(String(f.accountNumber||'').replace(/\s/g,'')))return'MXN';if(f.brebKey)return'COP';if(f.sortCode)return'GBP';if(f.routingNumber)return'USD';
  const ib=String(f.iban||'').replace(/\s/g,'').toUpperCase();if(ib)return ib.startsWith('GB')?'GBP':'EUR';return''}
function bbMatch(name,c){const n=bbNorm(name);if(!n)return{list:[]};const T=n.split(' ').filter(x=>x.length>1);
  const C=db.users.filter(u=>u.role==='customer'&&u.status!=='closed').map(u=>{const un=bbNorm(u.name),ut=un.split(' ');let sc=0;if(un===n)sc=100;else{const hit=T.filter(t=>ut.includes(t)).length;if(hit>=2&&hit>=Math.min(T.length,ut.length))sc=60+hit;else if(hit>=2)sc=30+hit}
    const st=(u.accts&&u.accts[c]||{}).status;if(sc&&['under_review','requested'].includes(st))sc+=20;return{u,sc}}).filter(x=>x.sc).sort((a,b)=>b.sc-a.sc);
  return{best:C[0]&&(C[0].sc>=80&&(!C[1]||C[1].sc<C[0].sc))?C[0].u:null,list:C.map(x=>x.u)}}
const bbWaiting=c=>db.users.filter(u=>u.role==='customer'&&u.status!=='closed'&&(!c||['under_review','requested'].includes((u.accts&&u.accts[c]||{}).status)));
function benBank(text,p){const f={...p.f},extra=[...p.extra];let c=bbCurrency(f);
  let u=null;const em=String(f.customer||'').match(/\S+@\S+\.\S+/)||text.match(/(?:^|\s)([^\s@]+@[^\s@]+\.[a-z]{2,})\s*$/i);if(em){const e=String(em[1]||em[0]).toLowerCase();u=db.users.find(x=>x.email===e&&x.role==='customer')||null}
  if(!c){return{ask:`These look like bank details${f.accountName?` for ${f.accountName}`:''}, but I can't tell the currency. Which currency are they for?`,choices:FIAT.map(x=>({name:x,email:x})),retry:text+'\nCurrency:'}}
  if(!u&&f.customer)u=bbMatch(f.customer,c).best;
  const nameM=!u&&f.accountName?bbMatch(f.accountName,c):{list:[]};if(!u)u=nameM.best;
  if(!u){const w=bbWaiting(c),cands=[...new Map([...nameM.list,...w].map(x=>[x.id,x])).values()].slice(0,8);
    return{ask:`${f.accountName?`The beneficiary "${f.accountName}" doesn't match a customer's name.`:'There is no beneficiary name.'} Which customer should get these ${c} details?${w.length?` Waiting for ${c} details: ${w.length}.`:` Nobody is waiting for ${c} details right now.`}`,choices:cands.length?cands:db.users.filter(x=>x.role==='customer'&&x.status!=='closed').slice(0,8),retry:text+'\nCustomer:'}}
  const spec=ACCT_FIELDS[c],det={};for(const[k]of spec.f)if(f[k])det[k]=f[k];
  for(const k of['iban','bic','accountNumber','routingNumber','sortCode','clabe','brebKey','bankName','bankAddress'])if(f[k]&&!spec.f.some(x=>x[0]===k))extra.push([{iban:'IBAN',bic:'BIC',accountNumber:'Account number',routingNumber:'Routing number',sortCode:'Sort code',clabe:'CLABE',brebKey:'Bre-B key',bankName:'Bank name',bankAddress:'Bank address'}[k],f[k]]);
  if(!det.accountName)det.accountName=u.name;
  const cur=(u.accts&&u.accts[c])||{},st=cur.status||'none',lines=spec.f.filter(([k])=>det[k]).map(([k,l])=>`${l}: ${det[k]}`).concat(extra.map(([l,v])=>`${l}: ${v}`));
  const nameNote=f.accountName&&bbNorm(f.accountName)!==bbNorm(u.name)?`\n⚠ The beneficiary name (${f.accountName}) is not the customer's name (${u.name}). Check this is right.`:'';
  return{kind:'acctfill',args:{userId:u.id,currency:c,details:{...det,extra},approve:true},
    summary:`${st==='approved'?'Replace':'Fill in and approve'} ${u.name}'s ${c} account details (${u.email})${st==='approved'?' — they already have approved details':st==='none'?' — they have not asked for them':''}.\n${lines.join('\n')}${nameNote}\nThe customer is told their details are ready.`}}
async function benRun(req,a,st){const x=st.args;
  switch(st.kind){
    case'acctfill':{await saveAcct(a,x,req);return'customer told their details are ready'}
    case'credit':await benCall(req,'POST /api/admin/deposit-credit',x);return'';
    case'reverse':await benCall(req,'POST /api/admin/deposit-reverse',x);return'';
    case'message':{const r=await benCall(req,'POST /api/admin/message',x);return`delivered to ${r.count} customer${r.count===1?'':'s'}`}
    case'settings':await benCall(req,'POST /api/admin/settings',x);return'';
    case'email':await benCall(req,'POST /api/admin/email-verify',x);return'';
    case'pin':await benCall(req,'POST /api/admin/user-pin',x);return'';
    case'hold':await benCall(req,'POST /api/admin/user-hold',x);return'';
    case'setdob':await benCall(req,'POST /api/admin/user-dob',x);return'';
    case'dob':await benCall(req,'POST /api/admin/dob-review',x);return x.ok?'':'they were asked to send it again';
    case'depresult':await benCall(req,'POST /api/admin/deposit-credit',x);return'';
    case'refdecide':await benCall(req,'POST /api/admin/ref-reward/decide',x);return'';
    case'reward':await benCall(req,'POST /api/admin/ref-reward',x);return'';
    case'stage':await benCall(req,'POST /api/admin/stage',x);return'';
    case'auto':await benCall(req,'POST /api/admin/auto',{nudge:x});return'';
    case'autosend':{const r=await benCall(req,'POST /api/admin/auto/send',x);return`delivered to ${r.count} customer${r.count===1?'':'s'}`}
    case'reminders':await benCall(req,'POST /api/admin/user-reminders',x);return'';
    case'invite':{const r=await benCall(req,'POST /api/admin/invite',x);return x.decline?'':(r.code?'code '+r.code:'')}
    case'kyc':{const k=db.kycs.find(y=>y.id===x.id);if(!k||k.status!=='pending')throw fail(400,'That identity check was already handled.');adminMerge({kycs:[x]});
      addAudit(a.email,x.status==='verified'?'KYC approved':'KYC rejected',(byId(k.userId)||{}).email+(x.note?': '+x.note:''),ipOf(req));break}
    case'settle':{const t=db.txs.find(y=>y.id===x.id);if(!t||t.status!=='pending')throw fail(400,'That request was already handled.');const u=byId(t.userId);adminMerge({txs:[x]});
      addAudit(a.email,t.type==='withdrawal'?(x.status==='completed'?'Withdrawal approved':'Withdrawal rejected (funds returned)'):'Deposit rejected',`${money(t.currency,t.amount)} for ${u.email}${x.note?': '+x.note:''}`,ipOf(req));break}
    case'delete':await benCall(req,'POST /api/admin/user-delete',x);return'';
    case'unblock':await benCall(req,'POST /api/admin/unblock',x);return'';
    case'status':{const u=byId(x.id);adminMerge({users:[x]});addAudit(a.email,x.status==='suspended'?'User suspended':'User reactivated',u.email,ipOf(req));break}
    default:throw fail(400,'Unknown step.');
  }
  save();push(null,'sync',{});return'';
}
/* optional: with an AI key set (Groq, Gemini or Claude), Ben also understands free-form wording by rewriting it into its own commands */
async function benAI(text){if(!aiOn())return null;
  const names=benCustomers().slice(0,300).map(u=>`${u.name} <${u.email}>`).join('\n');
  const system=`You turn an admin's request for the HarborPay admin panel into one or more short commands, one per line, using ONLY these forms (lowercase is fine):
credit <customer> <currency> <amount>
reverse <customer> <currency> <amount> [because <reason>]
approve deposit|withdrawal|kyc|email|dob|invite <customer> [<currency> <amount>]
reject deposit|withdrawal|kyc|dob|invite <customer> because <reason>
suspend <customer> / unsuspend <customer>
delete <customer> because <reason>
unblock <email>
change pin <customer> <4 digits> [no pause]
lift pause <customer>
set dob <customer> <YYYY-MM-DD>
reminders on|off <customer>
invite code for <customer>
message <customer>: <text>   /   message everyone: <text>
funnel / referral reward on|off / referral reward <amount> <currency> min <usd> / referral reward inviter only|both / getting started on|off / welcome message: <title> | <message>
reminders / send reminder <number> now / send reminder <number> to <customer> / add reminder: <title> | <message> / edit reminder <number>: <title> | <message> / delete reminder <number> / reminder <number> off|on / reminders every <n> days / reminders email on|off / reminders to everyone|quiet customers / reminders on|off
balance <customer> / find <text> / pending
pause withdrawals / resume withdrawals / close sign-ups / open sign-ups / set fee <percent>%
Currencies: usd eur gbp mxn cop. Use the customer's email from the list when you can.
If the request cannot be done with these commands, reply with one line starting with "SAY:" explaining briefly what the admin can do instead. Output nothing else.
Customers:\n${names}`;
  return await aiCall(system,[{role:'user',content:String(text).slice(0,2000)}],400,30000)||null}
const benChoices=l=>(l||[]).map(u=>({label:`${u.name} (${u.email})`,email:u.email}));
/* ---- crypto deposit wallets: the addresses customers send BTC, ETH, USDT and USDC to ---- */
/* ============ Own deposit address for each customer (from your wallet's PUBLIC keys: xpub/zpub). The server never holds a recovery phrase or private key. ============ */
/* HD wallet core: makes addresses from a public master key (xpub). Shared by the server and the offline key tool.
   H gives async hashes: hmac512(key,data), sha256(data), rmd160(data); all take and return Uint8Array. */
function makeHD(H){
  const P=2n**256n-2n**32n-977n,N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const G=[0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,1n];
  const mod=(a,m=P)=>{a%=m;return a<0n?a+m:a};
  const pow=(b,e,m=P)=>{let r=1n;b=mod(b,m);while(e>0n){if(e&1n)r=r*b%m;b=b*b%m;e>>=1n}return r};
  const inv=a=>pow(a,P-2n);
  const dbl=([X,Y,Z])=>{if(Z===0n||Y===0n)return[0n,1n,0n];const Y2=mod(Y*Y),S=mod(4n*X*Y2),M=mod(3n*X*X),X3=mod(M*M-2n*S);return[X3,mod(M*(S-X3)-8n*Y2*Y2),mod(2n*Y*Z)]};
  const add=(p,q)=>{if(p[2]===0n)return q;if(q[2]===0n)return p;const[X1,Y1,Z1]=p,[X2,Y2,Z2]=q,Z1s=mod(Z1*Z1),Z2s=mod(Z2*Z2);
    const U1=mod(X1*Z2s),U2=mod(X2*Z1s),S1=mod(Y1*Z2s*Z2),S2=mod(Y2*Z1s*Z1);
    if(U1===U2)return S1===S2?dbl(p):[0n,1n,0n];const Hh=mod(U2-U1),R=mod(S2-S1),H2=mod(Hh*Hh),H3=mod(Hh*H2),V=mod(U1*H2),X3=mod(R*R-H3-2n*V);
    return[X3,mod(R*(V-X3)-S1*H3),mod(Hh*Z1*Z2)]};
  const mul=(k,pt=G)=>{let r=[0n,1n,0n],a=pt;while(k>0n){if(k&1n)r=add(r,a);a=dbl(a);k>>=1n}return r};
  const aff=([X,Y,Z])=>{const zi=inv(Z),z2=mod(zi*zi);return[mod(X*z2),mod(Y*z2*zi)]};
  const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
  const unhex=h=>Uint8Array.from((h.match(/../g)||[]).map(x=>parseInt(x,16)));
  const cat=(...a)=>{const o=new Uint8Array(a.reduce((s,x)=>s+x.length,0));let i=0;for(const x of a){o.set(x,i);i+=x.length}return o};
  const b2n=b=>b.length?BigInt('0x'+hex(b)):0n;
  const n2b=(n,l=32)=>unhex(n.toString(16).padStart(l*2,'0'));
  const ser32=i=>Uint8Array.of(i>>>24&255,i>>>16&255,i>>>8&255,i&255);
  const comp=pt=>{const[x,y]=aff(pt);return cat([y&1n?3:2],n2b(x))};
  const decomp=b=>{const x=b2n(b.slice(1,33));if(b.length!==33||(b[0]!==2&&b[0]!==3)||x>=P)throw Error('bad key');let y=pow(mod(x*x*x+7n),(P+1n)/4n);if(mod(y*y)!==mod(x*x*x+7n))throw Error('bad key');if((y&1n)!==BigInt(b[0]&1))y=P-y;return[x,y,1n]};
  /* base58 */
  const A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const b58e=b=>{let n=b2n(b),s='';while(n>0n){s=A[Number(n%58n)]+s;n/=58n}for(const x of b){if(x)break;s='1'+s}return s};
  const b58d=s=>{let n=0n;for(const c of s){const i=A.indexOf(c);if(i<0)throw Error('bad character');n=n*58n+BigInt(i)}let h=n?n.toString(16):'';if(h.length%2)h='0'+h;let z=0;for(const c of s){if(c!=='1')break;z++}return cat(new Uint8Array(z),unhex(h))};
  const dsha=async b=>H.sha256(await H.sha256(b));
  const b58c=async b=>b58e(cat(b,(await dsha(b)).slice(0,4)));
  const b58cd=async s=>{const b=b58d(s),p=b.slice(0,-4);if(hex((await dsha(p)).slice(0,4))!==hex(b.slice(-4)))throw Error('checksum');return p};
  /* bech32 (segwit v0) */
  const CH='qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const polymod=v=>{const GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];let c=1;for(const x of v){const b=c>>>25;c=((c&0x1ffffff)<<5)^x;for(let i=0;i<5;i++)if((b>>>i)&1)c^=GEN[i]}return c>>>0};
  const bech32=(hrp,ver,prog)=>{const d=[ver];let acc=0,bits=0;for(const x of prog){acc=(acc<<8)|x;bits+=8;while(bits>=5){bits-=5;d.push((acc>>>bits)&31)}}if(bits)d.push((acc<<(5-bits))&31);
    const hx=[...hrp].map(c=>c.charCodeAt(0)>>5).concat([0],[...hrp].map(c=>c.charCodeAt(0)&31)),pm=polymod(hx.concat(d,[0,0,0,0,0,0]))^1;
    return hrp+'1'+d.concat([0,1,2,3,4,5].map(i=>(pm>>>(5*(5-i)))&31)).map(x=>CH[x]).join('')};
  /* keccak-256 (Ethereum's hash, not NIST SHA3) */
  const RC=['1','8082','800000000000808a','8000000080008000','808b','80000001','8000000080008081','8000000000008009','8a','88','80008009','8000000a','8000808b','800000000000008b','8000000000008089','8000000000008003','8000000000008002','8000000000000080','800a','800000008000000a','8000000080008081','8000000000008080','80000001','8000000080008008'].map(x=>BigInt('0x'+x));
  const ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]],M64=(1n<<64n)-1n;
  const rotl=(x,n)=>n?((x<<BigInt(n))|(x>>BigInt(64-n)))&M64:x;
  const keccak=bytes=>{const rate=136,m=[...bytes,1];while(m.length%rate)m.push(0);m[m.length-1]|=0x80;const s=Array(25).fill(0n);
    for(let o=0;o<m.length;o+=rate){for(let i=0;i<rate/8;i++){let v=0n;for(let b=7;b>=0;b--)v=(v<<8n)|BigInt(m[o+i*8+b]);s[i]^=v}
      for(let r=0;r<24;r++){const C=[0,1,2,3,4].map(x=>s[x]^s[x+5]^s[x+10]^s[x+15]^s[x+20]);for(let i=0;i<25;i++)s[i]^=C[(i%5+4)%5]^rotl(C[(i%5+1)%5],1);
        const B=Array(25);for(let x=0;x<5;x++)for(let y=0;y<5;y++)B[y+5*((2*x+3*y)%5)]=rotl(s[x+5*y],ROT[x][y]);
        for(let x=0;x<5;x++)for(let y=0;y<5;y++)s[x+5*y]=B[x+5*y]^((~B[(x+1)%5+5*y]&M64)&B[(x+2)%5+5*y]);s[0]^=RC[r]}}
    const out=new Uint8Array(32);for(let i=0;i<4;i++){let v=s[i];for(let b=0;b<8;b++){out[i*8+b]=Number(v&255n);v>>=8n}}return out};
  /* BIP32 */
  const parse=async s=>{const b=await b58cd(String(s).trim());if(b.length!==78)throw Error('wrong length');if(b[45]!==2&&b[45]!==3)throw Error('This is a private key. Use the public key (xpub/zpub) only.');decomp(b.slice(45));return{depth:b[4],chain:b.slice(13,45),key:b.slice(45),version:hex(b.slice(0,4))}};
  const ckdPub=async(n,i)=>{if(i>=0x80000000)throw Error('hardened');const I=await H.hmac512(n.chain,cat(n.key,ser32(i))),IL=b2n(I.slice(0,32));if(IL>=N)throw Error('invalid child');
    const pt=add(mul(IL),decomp(n.key));if(pt[2]===0n)throw Error('invalid child');return{chain:I.slice(32),key:comp(pt),depth:(n.depth||0)+1}};
  const pubOf=k=>comp(mul(k));
  const ckdPriv=async(n,i)=>{const data=i>=0x80000000?cat([0],n2b(n.k),ser32(i)):cat(pubOf(n.k),ser32(i));const I=await H.hmac512(n.chain,data),IL=b2n(I.slice(0,32)),k=(IL+n.k)%N;if(IL>=N||k===0n)throw Error('invalid child');
    return{chain:I.slice(32),k,depth:(n.depth||0)+1,parentKey:pubOf(n.k),index:i}};
  const master=async seed=>{const I=await H.hmac512(new TextEncoder().encode('Bitcoin seed'),seed);return{chain:I.slice(32),k:b2n(I.slice(0,32)),depth:0}};
  const xpubOf=async(n,version)=>{const fp=(await H.rmd160(await H.sha256(n.parentKey))).slice(0,4);
    return b58c(cat(unhex(version),[n.depth],fp,ser32(n.index),n.chain,pubOf(n.k)))};
  /* addresses */
  const h160=async b=>H.rmd160(await H.sha256(b));
  const btc=async pub=>bech32('bc',0,await h160(pub));
  const raw20=pub=>{const[x,y]=aff(decomp(pub));return keccak(cat(n2b(x),n2b(y))).slice(12)};
  const evm=pub=>{const a=hex(raw20(pub)),h=hex(keccak(new TextEncoder().encode(a)));return '0x'+[...a].map((c,i)=>parseInt(h[i],16)>=8?c.toUpperCase():c).join('')};
  const tron=pub=>b58c(cat([0x41],raw20(pub)));
  const derive=async(xpub,idx)=>{const n=await parse(xpub);return ckdPub(await ckdPub(n,0),idx)}; // external chain: .../0/idx
  const wif=k=>b58c(cat([0x80],n2b(k),[1]));
  return{parse,derive,ckdPub,ckdPriv,master,xpubOf,btc,evm,tron,wif,pubOf,keccak,hex,unhex,b58e,b58d,b58c,b58cd,bech32,n2b,N};
}

const HDK=makeHD({hmac512:async(k,d)=>new Uint8Array(crypto.createHmac('sha512',k).update(d).digest()),sha256:async d=>new Uint8Array(crypto.createHash('sha256').update(d).digest()),rmd160:async d=>new Uint8Array(crypto.createHash('ripemd160').update(d).digest())});
const HD_FAM=n=>n==='Bitcoin'?'btc':n==='Tron (TRC20)'?'tron':n==='Solana'?null:'evm';
/* chains watched for token deposits (USDT/USDC). Contract addresses are the official ones; RPCs can be changed with Railway variables. */
const EVM_CH={
  'Ethereum (ERC20)':{id:'eth',rpcs:[...(process.env.RPC_ETHEREUM?[process.env.RPC_ETHEREUM]:[]),...['https://ethereum-rpc.publicnode.com','https://eth.llamarpc.com','https://eth.drpc.org']],conf:12,step:500,tok:{USDT:'0xdAC17F958D2ee523a2206206994597C13D831ec7',USDC:'0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'}},
  'BNB Smart Chain (BEP20)':{id:'bsc',rpcs:[...(process.env.RPC_BSC?[process.env.RPC_BSC]:[]),...['https://bsc-rpc.publicnode.com','https://bsc.drpc.org','https://bsc-dataseed.bnbchain.org']],conf:15,step:1000,tok:{USDT:'0x55d398326f99059fF775485246999027B3197955',USDC:'0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d'}},
  'Polygon':{id:'pol',rpcs:[...(process.env.RPC_POLYGON?[process.env.RPC_POLYGON]:[]),...['https://polygon-bor-rpc.publicnode.com','https://polygon-rpc.com','https://polygon.drpc.org']],conf:64,step:1000,tok:{USDT:'0xc2132D05D31c914a87C6611C10748AEb04B58e8F',USDC:'0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359'}},
  'Arbitrum':{id:'arb',rpcs:[...(process.env.RPC_ARBITRUM?[process.env.RPC_ARBITRUM]:[]),...['https://arb1.arbitrum.io/rpc','https://arbitrum-one-rpc.publicnode.com','https://arbitrum.drpc.org']],conf:40,step:5000,tok:{USDT:'0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9',USDC:'0xaf88d065e77c8cC2239327C5EDb3A432268e5831'}}};
const TRON_USDT='TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',TRONGRID=process.env.TRONGRID_URL||'https://api.trongrid.io',MEMPOOL=process.env.MEMPOOL_URL||'https://mempool.space/api',BTC_CONF=2;
const HD_AUTO=new Set(['BTC|Bitcoin','USDT|Tron (TRC20)',...Object.entries(EVM_CH).flatMap(([n,c])=>Object.keys(c.tok).map(t=>t+'|'+n))]); // what can be credited automatically
db.hd=db.hd||{};db.hdSeen=db.hdSeen||{};db.hdScan=db.hdScan||{};db.hdNext=db.hdNext||1;db.settings.hdNets=db.settings.hdNets||{};db.settings.hdFam=db.settings.hdFam||{};
const hdOn=(c,n)=>!!(db.settings.hdNets[c+'|'+n]&&db.hd[HD_FAM(n)]&&HD_AUTO.has(c+'|'+n));
const hdFp=x=>crypto.createHash('sha256').update(String(x)).digest('hex').slice(0,10);
async function hdAddr(u,fam){ // the customer's own address for one wallet family; gives them a number the first time
  const x=db.hd[fam];if(!x)throw fail(400,'Not set up.');
  if(!u.dIdx){u.dIdx=db.hdNext++;save()}
  u.dAddr=u.dAddr||{};const c=u.dAddr[fam];if(c&&c.x===hdFp(x))return c.a;
  const k=(await HDK.derive(x,u.dIdx)).key,a=fam==='btc'?await HDK.btc(k):fam==='tron'?await HDK.tron(k):HDK.evm(k);
  u.dAddr[fam]={x:hdFp(x),a,at:Date.now()};save();return a}
const hdUsers=fam=>db.users.filter(u=>u.role==='customer'&&u.dAddr&&u.dAddr[fam]&&u.dAddr[fam].x===hdFp(db.hd[fam]));
const hdStat=(k,ok,err)=>{db.hdScan[k]=db.hdScan[k]||{};const s=db.hdScan[k];s.at=Date.now();if(ok){s.ok=Date.now();delete s.err}else{s.err=String(err).slice(0,200);
  if(!s.alertAt||Date.now()-s.alertAt>6*36e5){s.alertAt=Date.now();notifyAdmins('Crypto deposit watcher problem',`Checking ${k} for customer deposits failed: ${s.err}. Deposits on it are not credited automatically until this works again; nothing is lost. Controls → Crypto deposit wallets shows the status.`,'controls')}}};
function hdCredit(u,cur,net,amount,hash,key){
  if(db.hdSeen[key])return;amount=r8(amount);if(!(amount>0))return;
  const addr=(u.dAddr[HD_FAM(net)]||{}).a,min=+db.settings.cryptoMin[cur]||0;let hold=amount<min?'below the minimum of '+min+' '+cur:['suspended','closed'].includes(u.status)?'the account is '+u.status:'';
  if(!hold)try{curLimCheck(u,cur,'deposit',amount)}catch(e){hold='it is over a deposit limit ('+e.message.replace(/\.$/,'')+')'}
  const t={id:uid('tx'),userId:u.id,type:'deposit',status:hold?'pending':'completed',ts:Date.now(),currency:cur,amount,d:{sender:'self',method:'crypto',network:net,address:addr,hash,auto:true,idx:u.dIdx}};
  db.hdSeen[key]=t.id;db.txs.unshift(t);
  if(hold){t.d.adminNote='Arrived on their own address but not credited: '+hold+'.';notifyAdmins('Crypto deposit needs a decision',`${u.name} sent ${amount} ${cur} on ${net} to their own address, but it was not credited automatically because ${hold}. Check it on the Deposits page.`,'deposits')}
  else{u.bal[cur]=r8((u.bal[cur]||0)+amount);t.creditedAt=Date.now();refRewardCheck(t);
    notify(u.id,'Deposit received',`Your deposit of ${amount} ${cur} on ${net} has arrived and was added to your balance.`,{view:'transactions',tx:t.id,details:[['Asset',cur],['Amount',amount+' '+cur],['Network',net],['Transaction ID',hash]]});
    notifyAdmins('Crypto deposit credited',`${u.name}: ${amount} ${cur} on ${net}, credited automatically. It is on their address #${u.dIdx} (${addr}).`,'deposits');
    addAudit('system','Crypto deposit credited automatically',`${amount} ${cur} on ${net} for ${u.email} (tx ${hash})`,'')}
  save();push(u.id,'sync',{});pushAdmins('sync',{})}
const jget=async(u,h)=>{const r=await fetch(u,{headers:h||{},signal:AbortSignal.timeout(20000)});if(!r.ok)throw Error('HTTP '+r.status);return r.json()};
const rpc=async(url,method,params)=>{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(20000)});if(!r.ok)throw Error('HTTP '+r.status);const j=await r.json();if(j.error)throw Error(j.error.message||'RPC error');return j.result};
const DEC={};
async function crpc(C,method,params){let last;const n=C.rpcs.length;C.cur=C.cur||0;
  for(let t=0;t<n;t++){const i=(C.cur+t)%n;try{const r=await rpc(C.rpcs[i],method,params);C.cur=i;return r}catch(e){last=e;if(/range|limit|too many|exceed|large/i.test(e.message)&&method==='eth_getLogs')throw e}}
  throw Error(`${last&&last.message} (tried ${n} services)`)}
async function blockAt(C,ts){ // first block at or after a time (seconds), by binary search
  let lo=0,hi=parseInt(await crpc(C,'eth_blockNumber',[]),16);while(lo<hi){const mid=Math.floor((lo+hi)/2),b=await crpc(C,'eth_getBlockByNumber',['0x'+mid.toString(16),false]);if(parseInt(b.timestamp,16)<ts)lo=mid+1;else hi=mid}return lo}
async function hdEvm(net,C){
  const toks=Object.keys(C.tok).filter(t=>hdOn(t,net));if(!toks.length)return;
  const users=hdUsers('evm'),by=new Map(users.map(u=>[u.dAddr.evm.a.toLowerCase(),u]));const k='evm:'+C.id;
  try{const safe=parseInt(await crpc(C,'eth_blockNumber',[]),16)-C.conf;db.hdScan[k]=db.hdScan[k]||{};const s=db.hdScan[k];
    if(!s.block){const first=users.length?Math.min(...users.map(u=>u.dAddr.evm.at||Date.now())):0; // start from when the first customer got an address, so nothing sent before the first check is missed
      s.block=first?Math.min(safe,(await blockAt(C,Math.floor(first/1000)-600))-1):safe;hdStat(k,true);save();if(!first)return}
    if(!users.length){s.block=safe;hdStat(k,true);return}
    for(const t of toks){const a=C.tok[t];if(DEC[a]==null)DEC[a]=parseInt(await crpc(C,'eth_call',[{to:a,data:'0x313ce567'},'latest']),16)}
    let from=s.block+1,rounds=0;
    while(from<=safe&&rounds++<60){const to=Math.min(safe,from+C.step-1),addrs=[...by.keys()];
      for(let i=0;i<addrs.length;i+=200){const logs=await crpc(C,'eth_getLogs',[{fromBlock:'0x'+from.toString(16),toBlock:'0x'+to.toString(16),address:toks.map(t=>C.tok[t]),
          topics:['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',null,addrs.slice(i,i+200).map(x=>'0x'+'0'.repeat(24)+x.slice(2))]}]);
        for(const L of logs){const tok=toks.find(t=>C.tok[t].toLowerCase()===String(L.address).toLowerCase()),u=by.get('0x'+L.topics[2].slice(26).toLowerCase());if(!tok||!u||L.removed)continue;
          hdCredit(u,tok,net,Number(BigInt(L.data))/10**DEC[C.tok[tok]],L.transactionHash,`${C.id}:${L.transactionHash}:${parseInt(L.logIndex,16)}`)}}
      s.block=to;from=to+1}
    hdStat(k,true);save()}catch(e){if(/range|limit|too many|exceed|large/i.test(e.message))C.step=Math.max(20,C.step>>1);hdStat(k,false,e.message)}}
const RR={};const rr=(k,list,n)=>{if(!list.length)return[];const i=(RR[k]||0)%list.length;RR[k]=i+n;return[...list,...list].slice(i,i+Math.min(n,list.length))};
async function hdTron(){if(!hdOn('USDT','Tron (TRC20)'))return;const users=rr('tron',hdUsers('tron'),25),h=process.env.TRONGRID_API_KEY?{'TRON-PRO-API-KEY':process.env.TRONGRID_API_KEY}:{};
  try{for(const u of users){const a=u.dAddr.tron.a,since=Math.max(u.dAddr.tron.at-36e5,(u.dTronAt||0)-6*36e5);
      const q=`${TRONGRID}/v1/accounts/${a}/transactions/trc20?only_to=true&only_confirmed=true&limit=50&contract_address=${TRON_USDT}&min_timestamp=${since}`;
      let j;try{j=await jget(q,h)}catch(e){if(!/429/.test(e.message))throw e;await new Promise(r=>setTimeout(r,2500));try{j=await jget(q,h)}catch(e2){throw Error(/429/.test(e2.message)?(h['TRON-PRO-API-KEY']?'TronGrid is busy (HTTP 429). It will try again in a minute.':'TronGrid is limiting free checks (HTTP 429). Add a free TRONGRID_API_KEY in Railway Variables.'):e2.message)}}
      for(const x of j.data||[])if(x.to===a&&x.token_info&&x.token_info.address===TRON_USDT)hdCredit(u,'USDT','Tron (TRC20)',Number(x.value)/10**(+x.token_info.decimals||6),x.transaction_id,'tron:'+x.transaction_id);
      u.dTronAt=Date.now();await new Promise(r=>setTimeout(r,process.env.TRONGRID_API_KEY?150:400))}
    hdStat('tron',true)}catch(e){hdStat('tron',false,e.message)}}
async function hdBtc(){if(!hdOn('BTC','Bitcoin'))return;const users=rr('btc',hdUsers('btc'),25);if(!users.length)return hdStat('btc',true);
  try{const tip=+(await(await fetch(MEMPOOL+'/blocks/tip/height',{signal:AbortSignal.timeout(20000)})).text());if(!(tip>0))throw Error('no block height');
    for(const u of users){const a=u.dAddr.btc.a,txs=await jget(`${MEMPOOL}/address/${a}/txs`);
      for(const t of txs){if(!t.status||!t.status.confirmed||tip-t.status.block_height+1<BTC_CONF||(t.status.block_time||0)*1000<u.dAddr.btc.at-36e5)continue;
        const sat=(t.vout||[]).filter(o=>o.scriptpubkey_address===a).reduce((s,o)=>s+o.value,0);if(sat>0)hdCredit(u,'BTC','Bitcoin',sat/1e8,t.txid,'btc:'+t.txid)}
      await new Promise(r=>setTimeout(r,300))}
    hdStat('btc',true)}catch(e){hdStat('btc',false,e.message)}}
let hdBusy=false;
async function hdRun(){if(hdBusy)return;hdBusy=true;try{await Promise.all([...Object.entries(EVM_CH).map(([n,C])=>hdEvm(n,C)),hdTron(),hdBtc()])}finally{hdBusy=false}}
setInterval(hdRun,+process.env.HD_EVERY||60e3);setTimeout(hdRun,15e3);
routes['GET /api/admin/hd']=async(req,res,url)=>{admin(req,url);const o={},a0={};for(const f of['btc','evm','tron']){o[f]=db.hd[f]||'';if(db.hd[f])try{const k=(await HDK.derive(db.hd[f],0)).key;a0[f]=f==='btc'?await HDK.btc(k):f==='tron'?await HDK.tron(k):HDK.evm(k)}catch{a0[f]=''}}
  const money=[];for(const t of db.txs)if(t.d&&t.d.auto&&!t.d.swept&&t.status==='completed'){const k=t.d.network+'|'+t.d.address+'|'+t.currency;let m=money.find(x=>x.k===k);if(!m){const u=byId(t.userId)||{};money.push(m={k,network:t.d.network,address:t.d.address,cur:t.currency,idx:t.d.idx,name:u.name,email:u.email,amount:0,n:0,last:0})}m.amount=r8(m.amount+t.amount);m.n++;m.last=Math.max(m.last,t.ts)}
  send(res,200,{xpub:o,addr0:a0,scan:db.hdScan,auto:[...HD_AUTO],customers:db.users.filter(u=>u.dIdx).length,money:money.sort((a,b)=>b.last-a.last)})};
routes['POST /api/admin/hd']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),nx={};
  for(const f of['btc','evm','tron']){const v=str((b.xpub||{})[f],140).replace(/\s/g,'');if(!v){nx[f]='';continue}
    let p;try{p=await HDK.parse(v)}catch(e){throw fail(400,`The ${f==='btc'?'Bitcoin':f==='evm'?'Ethereum/BEP20/Polygon/Arbitrum':'Tron'} key is not valid: ${e.message}.`)}
    if(p.depth!==3)throw fail(400,`The ${f==='btc'?'Bitcoin':f==='evm'?'Ethereum':'Tron'} key must be the account key (path m/${f==='btc'?84:44}'/${f==='btc'?0:f==='evm'?60:195}'/0'). Use the offline key tool to get it.`);
    if(f==='btc'&&!['04b24746','0488b21e'].includes(p.version))throw fail(400,'Use the zpub for Bitcoin (native SegWit, bc1 addresses).');nx[f]=v}
  const changed=['btc','evm','tron'].filter(f=>(db.hd[f]||'')!==nx[f]);
  const nets={};for(const k of HD_AUTO)if((b.nets||{})[k])nets[k]=true;
  db.hd=nx;db.settings.hdNets=nets;db.settings.hdFam={btc:!!nx.btc,evm:!!nx.evm,tron:!!nx.tron};
  for(const f of changed)for(const k of Object.keys(db.hdScan))if(k===f||k.startsWith(f+':'))delete db.hdScan[k];
  addAudit(a.email,'Own customer deposit addresses saved',`keys changed: ${changed.join(', ')||'none'}; networks: ${Object.keys(nets).join(', ')||'none'}`,ipOf(req));
  if(changed.length)notifyAdmins('Customer deposit keys changed',`${a.email} changed the wallet key for: ${changed.join(', ')}. Customers get new addresses on those networks.`,'controls');
  save();pushAdmins('sync',{});db.users.filter(u=>u.role==='customer').forEach(u=>push(u.id,'sync',{}));send(res,200,{ok:true})};
routes['POST /api/admin/hd/swept']=async(req,res,url)=>{const a=admin(req,url),b=await body(req);let n=0;
  for(const t of db.txs)if(t.d&&t.d.auto&&!t.d.swept&&t.d.network===b.network&&t.d.address===b.address&&t.currency===b.cur){t.d.swept=Date.now();n++}
  addAudit(a.email,'Customer address marked as moved',`${b.cur} on ${b.network} from ${b.address} (${n} deposits)`,ipOf(req));save();send(res,200,{ok:true,n})};
routes['POST /api/crypto/my-address']=async(req,res,url)=>{const u=authed(req,url),b=await body(req),c=String(b.asset||''),n=String(b.network||'');
  if(u.role!=='customer')throw fail(403,'Customers only.');if(!hdOn(c,n))throw fail(400,'Not available.');
  let a;try{a=await hdAddr(u,HD_FAM(n))}catch(e){console.error('hd address',e.message);throw fail(503,'We could not get your address right now. Please try again in a few minutes.')}
  send(res,200,{address:a,confirmations:n==='Bitcoin'?BTC_CONF:n==='Tron (TRC20)'?19:EVM_CH[n].conf})};
/* ---- US bank accounts through Bridge (bridge.xyz): each customer gets their own US account number.
   USD they receive by ACH/wire/FedNow is turned into USDC/USDT by Bridge and sent to HarborPay's wallet,
   and the customer's USD balance goes up by the amount that arrived. Railway variables: BRIDGE_API_KEY
   (sk-test... = sandbox, anything else = live) and optionally BRIDGE_API_BASE. ---- */
const BR_DEST={tron:{cur:'usdt',label:'USDT on Tron',re:/^T[1-9A-HJ-NP-Za-km-z]{33}$/,fam:'tron'},polygon:{cur:'usdc',label:'USDC on Polygon',re:/^0x[0-9a-fA-F]{40}$/,fam:'evm'},arbitrum:{cur:'usdc',label:'USDC on Arbitrum',re:/^0x[0-9a-fA-F]{40}$/,fam:'evm'}};
db.settings.br={on:false,fee:'1',rail:'polygon',addr:'',...(db.settings.br||{})};db.brSeen=db.brSeen||{};db.brScan=db.brScan||{};
const brKey=()=>String(process.env.BRIDGE_API_KEY||'').trim();
const brTest=()=>/^sk-test/.test(brKey())||process.env.BRIDGE_ENV==='sandbox';
const brBase=()=>(process.env.BRIDGE_API_BASE||(brTest()?'https://api.sandbox.bridge.xyz':'https://api.bridge.xyz')).replace(/\/+$/,'').replace(/\/v0$/,'');
const brReady=()=>!!(brKey()&&db.settings.br.on&&db.settings.br.addr&&BR_DEST[db.settings.br.rail]);
async function brApi(method,path,data,idem){
  if(!brKey())throw fail(400,'Add BRIDGE_API_KEY in Railway first.');
  const h={'Api-Key':brKey(),Accept:'application/json'};if(data)h['Content-Type']='application/json';if(method!=='GET')h['Idempotency-Key']=idem||crypto.randomUUID();
  const r=await fetch(brBase()+'/v0'+path,{method,headers:h,body:data?JSON.stringify(data):undefined,signal:AbortSignal.timeout(25000)}),t=await r.text();let j;try{j=t?JSON.parse(t):{}}catch{j={raw:t.slice(0,300)}}
  if(!r.ok){const m=j.message||j.error||(j.errors?JSON.stringify(j.errors):'')||j.raw||'';throw Object.assign(Error(`Bridge said ${r.status}${m?': '+String(m).slice(0,300):''}`),{status:r.status,j})}
  return j}
const brErr=(u,what,e)=>{const b=u.br=u.br||{};b.err=String(e.message||e).slice(0,300);b.errAt=Date.now();
  if(!b.alertAt||Date.now()-b.alertAt>12*36e5){b.alertAt=Date.now();notifyAdmins('US bank account problem',`${what} for ${u.name} (${u.email}) failed: ${b.err}. Controls → US bank accounts shows it, and you can retry there.`,'controls')}save()};
async function brStart(u,actor){ // step 1: ask Bridge for an identity-check link for this customer
  if(!brReady())return false;const b=u.br=u.br||{};if(b.va)return true;
  if(!b.kl){const j=await brApi('POST','/kyc_links',{full_name:u.name,email:u.email,type:'individual',redirect_uri:MAIL_SITE+'/?v=deposit'},'hp-kyc-'+u.id+'-'+(b.n=(b.n||0)+1));
    Object.assign(b,{kl:j.id,cid:j.customer_id||'',link:j.kyc_link||'',tos:j.tos_link||'',ks:j.kyc_status||'not_started',ts:j.tos_status||'pending',at:Date.now()});delete b.err;
    notify(u.id,'One more step for your USD account',`To open your own US bank account, please confirm your identity with our banking partner, Bridge. It takes about 5 minutes. Open the Deposit page and tap "Continue with Bridge".`,{view:'deposit'});
    addAudit(actor||'system','US bank account: identity link created',u.email,'');save();push(u.id,'sync',{});pushAdmins('sync',{})}
  return true}
async function brCheck(u){ // step 2: when Bridge has approved them, open the account
  const b=u.br;if(!b||!b.kl||b.va)return;
  const j=await brApi('GET','/kyc_links/'+encodeURIComponent(b.kl)),was=b.ks+'|'+b.ts;
  Object.assign(b,{ks:j.kyc_status||b.ks,ts:j.tos_status||b.ts,cid:j.customer_id||b.cid,link:j.kyc_link||b.link,tos:j.tos_link||b.tos,checked:Date.now()});
  if(['rejected','offboarded'].includes(b.ks)&&!b.toldBad){b.toldBad=Date.now();notifyAdmins('US bank account: Bridge declined',`Bridge did not approve ${u.name} (${u.email}). Status: ${b.ks}. You can still give them account details by hand on the Account details page.`,'usdaccounts')}
  if(b.ks==='approved'&&b.ts==='approved'&&b.cid)await brOpen(u);
  if(was!==b.ks+'|'+b.ts){save();push(u.id,'sync',{});pushAdmins('sync',{})}}
async function brOpen(u){
  const b=u.br,S=db.settings.br,D=BR_DEST[S.rail];
  const j=await brApi('POST',`/customers/${encodeURIComponent(b.cid)}/virtual_accounts`,{developer_fee_percent:String(S.fee||'0'),source:{currency:'usd'},destination:{currency:D.cur,payment_rail:S.rail,address:S.addr}},'hp-va-'+u.id+'-'+b.cid);
  const i=j.source_deposit_instructions||{};
  b.va={id:j.id,status:j.status,dest:S.rail+':'+S.addr,fee:String(S.fee||'0'),at:Date.now()};delete b.err;
  const rl=(i.payment_rails||[i.payment_rail]).filter(Boolean).map(r=>({ach_push:'ACH',wire:'wire',fednow:'FedNow'})[r]||r),rails=rl.length>1?rl.slice(0,-1).join(', ')+' or '+rl[rl.length-1]:rl[0]||'ACH or wire';
  const det={method:rails,accountName:i.bank_beneficiary_name||u.name,accountNumber:i.bank_account_number||'',routingNumber:i.bank_routing_number||'',bankName:i.bank_name||'',bankAddress:i.bank_address||'',labels:{},hidden:[],
    extra:i.bank_beneficiary_address?[['Beneficiary address',i.bank_beneficiary_address]]:[],bridge:true,
    instructions:`Send US dollars by ${rails} to these details. The money is added to your USD balance automatically once it arrives. Payments from another person must be under $4,000 each.`};
  u.accts=u.accts||{};u.accts.USD={status:'approved',details:det,approvedAt:Date.now()};
  if(u.av&&u.av.status==='pending'){u.av.status='approved';u.av.reviewedAt=Date.now()}
  notify(u.id,'Your USD account details are ready',`Your own US bank account is open. Anyone can now send you US dollars by ${rails}, and the money is added to your USD balance automatically. Open the Deposit page to see the details.`,{view:'deposit',details:[['Bank',det.bankName],['Account name',det.accountName],['Account number',det.accountNumber],['Routing number',det.routingNumber]]});
  notifyAdmins('US bank account opened',`${u.name} (${u.email}) now has a US account at ${det.bankName||'Bridge'} ending ${String(det.accountNumber).slice(-4)}.`,'usdaccounts');
  addAudit('system','US bank account opened (Bridge)',`${u.email} account ending ${String(det.accountNumber).slice(-4)}`,'');save();push(u.id,'sync',{});pushAdmins('sync',{})}
function brEvent(e){ // one entry of Bridge's activity list
  if(!e||!e.id||db.brSeen[e.id])return;
  const u=db.users.find(x=>x.br&&x.br.va&&x.br.va.id===e.virtual_account_id);if(!u)return; // not one of ours (or not opened here)
  db.brSeen[e.id]=1;const dep=e.deposit_id||e.id,src=e.source||{},rail=({ach_push:'ACH',wire:'Wire transfer (Fedwire)',fednow:'Other'})[src.payment_rail]||'Bank transfer';
  let t=db.txs.find(x=>x.type==='deposit'&&x.d&&x.d.brDep===dep);
  const mk=amt=>{t={id:uid('tx'),userId:u.id,type:'deposit',status:'pending',ts:Date.parse(e.created_at)||Date.now(),currency:'USD',amount:r8(amt),d:{sender:'self',method:DEP_METHODS.includes(rail)?rail:'Bank transfer',bridge:true,brDep:dep,auto:true}};
    if(src.sender_name)t.d.fromName=str(src.sender_name,100);if(src.description)t.d.bankRef=str(src.description,60);db.txs.unshift(t);return t};
  if(['funds_scheduled','funds_received','in_review'].includes(e.type)){
    if(!t){mk(+e.amount||0);if(e.type!=='funds_scheduled')notify(u.id,'Bank deposit on the way',`We have received your bank transfer of ${fmtUsd(+e.amount)} and are adding it to your USD balance. This usually takes a few minutes.`,{view:'transactions',tx:t.id,noMail:true})}
    if(e.type==='in_review'){t.d.processing=true;t.d.adminNote='Bridge is reviewing this deposit.'}}
  else if(e.type==='payment_processed'){
    const rc=e.receipt||{},net=r8(+(rc.final_amount||rc.subtotal_amount||e.amount)||0);if(!(net>0))return;
    if(!t)mk(net);if(t.status==='completed')return;
    t.amount=net;t.d.gross=+(rc.initial_amount||0)||undefined;t.d.fee=r8((+(e.developer_fee_amount||rc.developer_fee||0))+(+(e.exchange_fee_amount||rc.exchange_fee||0))+(+(e.gas_fee||rc.gas_fee||0)))||undefined;
    t.d.hash=e.destination_tx_hash||undefined;delete t.d.processing;
    const hold=['suspended','closed'].includes(u.status)?'the account is '+u.status:'';
    if(hold){t.d.adminNote=`The money arrived at HarborPay's wallet but was not added to the balance because ${hold}.`;notifyAdmins('US bank deposit needs a decision',`${u.name} received ${fmtUsd(net)} by bank, but it was not added because ${hold}. Check it on the Deposits page.`,'deposits')}
    else{t.status='completed';t.creditedAt=Date.now();u.bal.USD=r8((u.bal.USD||0)+net);refRewardCheck(t);
      notify(u.id,'Deposit received',`Your bank deposit of ${fmtUsd(net)} has arrived and was added to your USD balance.`,{view:'transactions',tx:t.id,details:[['Amount',fmtUsd(net)],['From',t.d.fromName||'Bank transfer'],['Method',t.d.method]]});
      notifyAdmins('US bank deposit credited',`${u.name}: ${fmtUsd(net)} added to their USD balance. Bridge sent it to your wallet as ${BR_DEST[db.settings.br.rail].label}.`,'deposits');
      addAudit('system','US bank deposit credited automatically',`${fmtUsd(net)} for ${u.email} (Bridge ${dep})`,'')}}
  else if(['refund','refunded','refund_failed'].includes(e.type)&&t&&t.status==='pending'){t.status='failed';t.d.reason='The bank transfer was returned to the sender.';
    notify(u.id,'Bank deposit returned',`Your bank deposit of ${fmtUsd(t.amount)} could not be completed and was returned to the sender.`,{view:'transactions',tx:t.id})}
  else return;
  save();push(u.id,'sync',{});pushAdmins('sync',{})}
const fmtUsd=n=>'$'+(+n||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
let brBusy=false;
async function brRun(){if(brBusy||!brKey())return;brBusy=true;
  try{for(const u of db.users.filter(x=>x.br&&x.br.kl&&!x.br.va&&!['rejected','offboarded'].includes(x.br.ks)).slice(0,30))
      try{await brCheck(u)}catch(e){brErr(u,'Checking the identity check',e)}
    const since=(db.brScan.ok||Date.now()-7*864e5)-15*60e3,all=[];let after='';
    for(let p=0;p<20;p++){const j=await brApi('GET',`/virtual_accounts/history?limit=100&updated_after_ms=${since}${after?'&starting_after='+encodeURIComponent(after):''}`),d=j.data||[];all.push(...d);if(d.length<100)break;after=d[d.length-1].id}
    all.sort((a,b)=>(Date.parse(a.created_at)||0)-(Date.parse(b.created_at)||0)).forEach(brEvent);
    db.brScan={ok:Date.now()};save()}
  catch(e){db.brScan.err=String(e.message).slice(0,300);db.brScan.at=Date.now();if(!db.brScan.alertAt||Date.now()-db.brScan.alertAt>6*36e5){db.brScan.alertAt=Date.now();notifyAdmins('US bank deposit checker problem',`Checking Bridge for new bank deposits failed: ${db.brScan.err}. Nothing is lost; deposits are added once this works again.`,'controls')}save()}
  finally{brBusy=false}}
setInterval(brRun,+process.env.BRIDGE_EVERY||90e3);setTimeout(brRun,20e3);
routes['GET /api/admin/bridge']=async(req,res,url)=>{admin(req,url);const a0={};
  for(const f of['evm','tron'])if(db.hd[f])try{const k=(await HDK.derive(db.hd[f],0)).key;a0[f]=f==='tron'?await HDK.tron(k):HDK.evm(k)}catch{}
  send(res,200,{key:!!brKey(),sandbox:brTest(),settings:db.settings.br,dest:Object.fromEntries(Object.entries(BR_DEST).map(([k,v])=>[k,{label:v.label,fam:v.fam}])),mine:a0,scan:db.brScan,
    customers:db.users.filter(u=>u.br).map(u=>({id:u.id,name:u.name,email:u.email,ks:u.br.ks,ts:u.br.ts,va:!!u.br.va,acct:u.br.va&&u.accts&&u.accts.USD&&u.accts.USD.details?String(u.accts.USD.details.accountNumber||'').slice(-4):'',err:u.br.err||'',at:u.br.at}))})};
routes['POST /api/admin/bridge']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),S=db.settings.br,rail=String(b.rail||''),addr=str(b.addr,80).replace(/\s/g,''),fee=Number(b.fee);
  if(!BR_DEST[rail])throw fail(400,'Choose where Bridge should send the money.');
  if(addr&&!BR_DEST[rail].re.test(addr))throw fail(400,`That is not a ${rail==='tron'?'Tron (T...)':'Polygon/Arbitrum (0x...)'} address.`);
  if(!(fee>=0&&fee<10))throw fail(400,'Your fee must be between 0 and 10 percent.');
  if(b.on&&!addr)throw fail(400,'Add the wallet address that receives the money before switching this on.');
  if(b.on&&!brKey())throw fail(400,'Add BRIDGE_API_KEY in Railway Variables first.');
  const destChanged=S.rail+':'+S.addr!==rail+':'+addr,feeChanged=String(S.fee)!==String(fee);
  Object.assign(S,{on:!!b.on,rail,addr,fee:String(fee)});
  addAudit(a.email,'US bank account settings saved',`${b.on?'on':'off'}, ${BR_DEST[rail].label} to ${addr||'(none)'}, fee ${fee}%`,ipOf(req));save();pushAdmins('sync',{});
  let moved=0,failed=0; // accounts already open keep sending to the old wallet unless we tell Bridge
  if((destChanged||feeChanged)&&addr)for(const u of db.users.filter(x=>x.br&&x.br.va)){
    try{await brApi('PUT',`/customers/${encodeURIComponent(u.br.cid)}/virtual_accounts/${encodeURIComponent(u.br.va.id)}`,{developer_fee_percent:String(fee),destination:{currency:BR_DEST[rail].cur,payment_rail:rail,address:addr}});u.br.va.dest=rail+':'+addr;u.br.va.fee=String(fee);moved++}
    catch(e){failed++;brErr(u,'Updating the account',e)}}
  if(moved||failed)save();
  send(res,200,{ok:true,moved,failed})};
routes['POST /api/admin/bridge/invite']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),u=needUser(b.userId);
  if(!brReady())throw fail(400,'Switch US bank accounts on first.');if(u.kyc!=='verified')throw fail(400,'This customer has not passed the HarborPay identity check yet.');
  if(b.again&&u.br&&!u.br.va){delete u.br.kl;delete u.br.toldBad}
  try{await brStart(u,a.email)}catch(e){brErr(u,'Creating the identity link',e);throw fail(502,e.message)}
  send(res,200,{ok:true})};
routes['POST /api/admin/bridge/check']=async(req,res,url)=>{admin(req,url);const b=await body(req);
  if(b.userId){const u=needUser(b.userId);try{await brCheck(u)}catch(e){brErr(u,'Checking the identity check',e);throw fail(502,e.message)}}
  await brRun();send(res,200,{ok:true,scan:db.brScan})};
routes['POST /api/admin/bridge/simulate']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),u=needUser(b.userId),amt=Number(b.amount);
  if(!brTest())throw fail(400,'Test deposits only work with a sandbox key (sk-test...).');if(!u.br||!u.br.va)throw fail(400,'This customer has no Bridge account yet.');if(!(amt>0&&amt<=100000))throw fail(400,'Enter an amount.');
  await brApi('POST',`/customers/${encodeURIComponent(u.br.cid)}/virtual_accounts/${encodeURIComponent(u.br.va.id)}/simulate_deposit`,{currency:'usd',amount:amt.toFixed(2)});
  addAudit(a.email,'Sandbox test deposit sent',`${fmtUsd(amt)} to ${u.email}`,ipOf(req));setTimeout(brRun,5000);send(res,200,{ok:true})};
routes['POST /api/bank/bridge-status']=async(req,res,url)=>{const u=authed(req,url); // customer came back from Bridge: check straight away
  if(u.br&&u.br.kl&&!u.br.va&&(!u.br.checked||Date.now()-u.br.checked>15e3))try{await brCheck(u)}catch(e){brErr(u,'Checking the identity check',e)}
  send(res,200,{ks:(u.br||{}).ks,ts:(u.br||{}).ts,ready:!!(u.br&&u.br.va)})};
routes['POST /api/admin/crypto-wallets']=async(req,res,url)=>{
  const a=admin(req,url),b=await body(req),W={},M={},was=JSON.stringify(db.settings.cryptoIn);
  for(const c of CRYPTO){for(const n of DNETS[c]){const v=str(((b.wallets||{})[c]||{})[n.name],120).replace(/\s/g,'');if(!v)continue;
      if(!n.re.test(v))throw fail(400,`The ${c} address for ${n.name} does not look like a ${n.name} address.`);(W[c]=W[c]||{})[n.name]=v}
    const m=Number((b.min||{})[c]);if(!(m>=0)||!isFinite(m))throw fail(400,`Enter a minimum for ${c} (0 or more).`);M[c]=r8(m)}
  db.settings.cryptoIn=W;db.settings.cryptoMin=M;
  const list=CRYPTO.flatMap(c=>Object.entries(W[c]||{}).map(([n,v])=>`${c} ${n}: ${v}`));
  addAudit(a.email,'Crypto deposit wallets saved',list.join(' | ')||'none',ipOf(req));
  if(was!==JSON.stringify(W))notifyAdmins('Crypto deposit wallets changed',`${a.email} changed the wallet addresses customers deposit to.\n${list.join('\n')||'All removed.'}`,'controls');
  save();pushAdmins('sync',{});db.users.filter(u=>u.role==='customer').forEach(u=>push(u.id,'sync',{}));send(res,200,{ok:true})};
routes['GET /api/crypto-qr']=async(req,res,url)=>{ // QR code of a deposit address that is set up (never of arbitrary text)
  const c=url.searchParams.get('a'),n=url.searchParams.get('n');let v=((db.settings.cryptoIn||{})[c]||{})[n];
  if(hdOn(c,n)&&url.searchParams.get('t')){const u=authed(req,url);if(u.role==='customer')v=await hdAddr(u,HD_FAM(n))}
  if(!v)throw fail(404,'Not found');
  let svg;try{const Q=await import('qrcode');svg=await(Q.toString||Q.default.toString)(v,{type:'svg',margin:1,errorCorrectionLevel:'M'})}catch{throw fail(404,'Not found')}
  res.writeHead(200,{'Content-Type':'image/svg+xml','Cache-Control':'no-cache'});res.end(svg)};
/* edit or delete a message already sent in the app (the email copy can't be changed) */
routes['POST /api/admin/message/edit']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),m=db.sent.find(x=>x.id===b.id);
  if(!m||!m.nids||!m.nids.length)throw fail(404,'That message can no longer be edited.');const title=str(b.title,140),text=str(b.body,5000);if(!title||!text)throw fail(400,'Add a subject and a message.');
  const ids=new Set(m.nids),who=new Set();for(const n of db.notifs)if(ids.has(n.id)){n.title=title;n.body=text;n.edited=Date.now();who.add(n.userId)}
  m.title=title;m.body=text;m.edited=Date.now();addAudit(a.email,'Message edited',`${title} (${who.size} customer(s))`,ipOf(req));save();who.forEach(u=>push(u,'sync',{}));pushAdmins('sync',{});send(res,200,{ok:true,n:who.size})};
routes['POST /api/admin/message/delete']=async(req,res,url)=>{const a=admin(req,url),b=await body(req),i=db.sent.findIndex(x=>x.id===b.id);if(i<0)throw fail(404,'Message not found.');
  const m=db.sent[i],ids=new Set(m.nids||[]),who=new Set();db.notifs=db.notifs.filter(n=>{if(ids.has(n.id)){who.add(n.userId);return false}return true});
  db.sent.splice(i,1);addAudit(a.email,'Message deleted',`${m.title} (removed from ${who.size} customer(s))`,ipOf(req));save();who.forEach(u=>push(u,'sync',{}));pushAdmins('sync',{});send(res,200,{ok:true,n:who.size})};
/* ============ Passkeys (WebAuthn): sign in with Face ID, fingerprint, Windows Hello or a security key ============ */
const unb64u=s=>Buffer.from(String(s||''),'base64url');
function cbor(buf,pos=0){ // small CBOR reader, enough for WebAuthn attestation objects and COSE keys
  const b=buf[pos++],mt=b>>5,ai=b&31;let len=ai;
  const rd=n=>{let v=0;for(let i=0;i<n;i++)v=v*256+buf[pos++];return v};
  if(ai===24)len=rd(1);else if(ai===25)len=rd(2);else if(ai===26)len=rd(4);else if(ai===27)len=rd(8);else if(ai>27&&mt!==7)throw Error('cbor');
  if(mt===0)return[len,pos];if(mt===1)return[-1-len,pos];
  if(mt===2){const v=buf.subarray(pos,pos+len);return[v,pos+len]}
  if(mt===3){const v=buf.subarray(pos,pos+len).toString('utf8');return[v,pos+len]}
  if(mt===4){const a=[];for(let i=0;i<len;i++){const[v,p]=cbor(buf,pos);a.push(v);pos=p}return[a,pos]}
  if(mt===5){const m=new Map();for(let i=0;i<len;i++){const[k,p]=cbor(buf,pos);const[v,p2]=cbor(buf,p);m.set(k,v);pos=p2}return[m,pos]}
  if(mt===6)return cbor(buf,pos);
  if(mt===7){if(ai===20)return[false,pos];if(ai===21)return[true,pos];if(ai===22||ai===23)return[null,pos];throw Error('cbor')}
  throw Error('cbor')}
function coseJwk(m){const kty=m.get(1),alg=m.get(3);
  if(kty===2)return{alg,jwk:{kty:'EC',crv:m.get(-1)===1?'P-256':m.get(-1)===2?'P-384':'P-521',x:b64u(m.get(-2)),y:b64u(m.get(-3))}};
  if(kty===3)return{alg,jwk:{kty:'RSA',n:b64u(m.get(-1)),e:b64u(m.get(-2))}};
  if(kty===1)return{alg,jwk:{kty:'OKP',crv:'Ed25519',x:b64u(m.get(-2))}};
  throw Error('Unsupported key type')}
const pkRp=req=>{const h=String(process.env.PASSKEY_RP_ID||req.headers['x-forwarded-host']||req.headers.host||'').split(',')[0].trim();return{id:h.replace(/:\d+$/,''),host:h}};
const pkOrigins=req=>{const r=pkRp(req);return[`https://${r.host}`,...(/^(localhost|127\.0\.0\.1)$/.test(r.id)?[`http://${r.host}`]:[])]};
const PKCH=new Map(); // challenge -> {kind,uid,exp}
const pkChallenge=(kind,uid)=>{const c=b64u(crypto.randomBytes(32));PKCH.set(c,{kind,uid,exp:Date.now()+5*6e4});for(const[k,v]of PKCH)if(v.exp<Date.now())PKCH.delete(k);return c};
function pkClient(req,cdj,kind){const cd=JSON.parse(unb64u(cdj).toString('utf8'));const ch=PKCH.get(cd.challenge);
  if(cd.type!==(kind==='reg'?'webauthn.create':'webauthn.get')||!ch||ch.kind!==kind||ch.exp<Date.now())throw fail(400,'This passkey request expired. Please try again.');
  if(!pkOrigins(req).includes(cd.origin))throw fail(400,'This passkey was made for a different website.');
  PKCH.delete(cd.challenge);return ch}
function pkAuthData(req,ad){const rpHash=crypto.createHash('sha256').update(pkRp(req).id).digest();
  if(!ad.subarray(0,32).equals(rpHash))throw fail(400,'This passkey was made for a different website.');
  const flags=ad[32];if(!(flags&1))throw fail(400,'The passkey was not confirmed on your device.');return{flags,count:ad.readUInt32BE(33),uv:!!(flags&4)}}
function pkSig(req,k,r){const ad=unb64u(r.authenticatorData),f=pkAuthData(req,ad),data=Buffer.concat([ad,crypto.createHash('sha256').update(unb64u(r.clientDataJSON)).digest()]),sig=unb64u(r.signature);
  let ok=false;try{const pub=crypto.createPublicKey({key:k.jwk,format:'jwk'});ok=k.jwk.kty==='OKP'?crypto.verify(null,data,pub,sig):crypto.verify('sha256',data,k.jwk.kty==='EC'?{key:pub,dsaEncoding:'der'}:pub,sig)}catch{}
  return{f,ok}}
/* confirm a signed-in customer with one of their own passkeys (used to change or verify the phone number) */
function pkStep(req,u,b){const r=b.response||{},ch=pkClient(req,r.clientDataJSON,'step');if(ch.uid!==u.id)throw fail(400,'This passkey request expired. Please try again.');
  const k=(u.passkeys||[]).find(x=>x.id===String(b.id||''));if(!k)throw fail(400,'Use a passkey that is saved on this HarborPay account.');
  const{f,ok}=pkSig(req,k,r);if(!ok){addAudit(u.email,'Failed passkey check',k.name,ipOf(req));save();throw fail(401,'That passkey could not be verified. Please try again.')}
  k.count=f.count;k.lastUsed=Date.now();return k}
const pkList=u=>(u.passkeys||[]).map(k=>({id:k.id,name:k.name,created:k.created,lastUsed:k.lastUsed||0}));
routes['POST /api/passkey/register/options']=async(req,res,url)=>{const u=authed(req,url),rp=pkRp(req);
  send(res,200,{challenge:pkChallenge('reg',u.id),rp:{name:'HarborPay',id:rp.id},user:{id:b64u(Buffer.from(u.id)),name:u.email,displayName:u.name||u.email},
    pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-8},{type:'public-key',alg:-257}],timeout:120000,attestation:'none',
    authenticatorSelection:{residentKey:'required',requireResidentKey:true,userVerification:'preferred'},excludeCredentials:(u.passkeys||[]).map(k=>({type:'public-key',id:k.id}))})};
routes['POST /api/passkey/register/finish']=async(req,res,url)=>{const u=authed(req,url),b=await body(req),r=b.response||{};
  const ch=pkClient(req,r.clientDataJSON,'reg');if(ch.uid!==u.id)throw fail(400,'This passkey request expired. Please try again.');
  const[att]=cbor(unb64u(r.attestationObject));const ad=att.get('authData');if(!ad)throw fail(400,'The passkey could not be read.');
  const f=pkAuthData(req,ad);if(!(f.flags&64))throw fail(400,'The passkey could not be read.');
  const idLen=ad.readUInt16BE(53),credId=ad.subarray(55,55+idLen),[cose]=cbor(ad,55+idLen);let key;try{key=coseJwk(cose);crypto.createPublicKey({key:key.jwk,format:'jwk'})}catch{throw fail(400,'This kind of passkey is not supported. Try another device.')}
  const id=b64u(credId);if(db.users.some(x=>(x.passkeys||[]).some(k=>k.id===id)))throw fail(400,'This passkey is already added.');
  u.passkeys=u.passkeys||[];if(u.passkeys.length>=10)throw fail(400,'You can have up to 10 passkeys. Remove one first.');
  const name=str(b.name,40)||uaName(req.headers['user-agent'])||'Passkey';
  u.passkeys.push({id,name,jwk:key.jwk,alg:key.alg,count:f.count,created:Date.now(),transports:Array.isArray(b.transports)?b.transports.slice(0,6).map(String):[]});
  notify(u.id,'Passkey added',`A passkey was added to your HarborPay account on ${name}. You can now sign in with it instead of your password. If this wasn't you, remove it in Security and change your password.`,{view:'security',details:[['Passkey',name],['Time',new Date().toUTCString().replace('GMT','UTC')]]});
  addAudit(u.email,'Passkey added',name,ipOf(req));save();send(res,200,{ok:true,passkeys:pkList(u)})};
routes['POST /api/passkey/login/options']=async(req,res)=>{send(res,200,{challenge:pkChallenge('auth'),rpId:pkRp(req).id,timeout:120000,userVerification:'preferred',allowCredentials:[]})};
routes['POST /api/passkey/login/finish']=async(req,res)=>{const b=await body(req),r=b.response||{},ip=ipOf(req);pkClient(req,r.clientDataJSON,'auth');
  const id=String(b.id||''),u=db.users.find(x=>(x.passkeys||[]).some(k=>k.id===id)),k=u&&u.passkeys.find(x=>x.id===id);
  if(!u)throw fail(401,'This passkey is not linked to a HarborPay account. Sign in with your password, then add it in Security.');
  const{f,ok}=pkSig(req,k,r);
  if(!ok){addAudit(u.email,'Failed passkey sign-in',k.name,ip);save();throw fail(401,'That passkey could not be verified. Try again or use your password.')}
  if(f.count&&k.count&&f.count<=k.count){addAudit(u.email,'Passkey possibly copied',k.name,ip);notifyAdmins('Passkey warning',`${u.email}'s passkey "${k.name}" reported an old counter. It may have been copied.`,'users')}
  k.count=f.count;k.lastUsed=Date.now();req.viaPk=true;adminGate(u,req,true);await geoGate(u,req,'sign-in');
  if(u.twofa&&!f.uv&&!(u.role==='admin'&&db.sec&&db.sec.adminPk)&&(db.totp[u.id]||code2fa)){save();return send(res,200,{need2fa:true,tmp:sign('2fa-'+u.id,3e5),demo:!db.totp[u.id]})} // passkeys confirmed with face/fingerprint/PIN count as two-step
  addAudit(u.email,'Signed in with a passkey',k.name,ip);save();send(res,200,{token:newSession(u,req)})};
routes['POST /api/passkey/step/options']=async(req,res,url)=>{const u=authed(req,url);if(!(u.passkeys||[]).length)throw fail(400,'Add a passkey in Security first.');
  send(res,200,{challenge:pkChallenge('step',u.id),rpId:pkRp(req).id,timeout:120000,userVerification:'required',allowCredentials:u.passkeys.map(k=>({type:'public-key',id:k.id,...(k.transports&&k.transports.length?{transports:k.transports}:{})}))})};
routes['POST /api/phone/passkey']=async(req,res,url)=>{const u=authed(req,url),b=await body(req),phone=String(b.phone||'').replace(/[\s()-]/g,'');
  if(!/^\+[1-9]\d{7,14}$/.test(phone))throw fail(400,'Enter your number in international format, starting with + and your country code, for example +447700900123.');
  if(db.users.some(x=>x.id!==u.id&&x.status!=='closed'&&x.phone===phone&&x.pv&&x.pv.status==='verified'))throw fail(400,'This number is already verified on another HarborPay account.');
  const k=pkStep(req,u,b),old=u.phone,changed=!!old&&old!==phone,mask=x=>x.slice(0,-4).replace(/\d/g,'•')+x.slice(-4);
  u.phone=phone;u.pv={status:'verified',phone,ts:Date.now(),via:'passkey'};
  notify(u.id,changed?'Phone number changed':'Phone number verified',changed?`Your phone number was changed to ${phone} and confirmed with your passkey "${k.name}". If you did not do this, contact support right away.`:`Your phone number ${phone} is now verified on your HarborPay account, confirmed with your passkey "${k.name}". If you did not do this, contact support.`,{view:'profile',details:[...(changed?[['Old number',mask(old)]]:[]),['Number',mask(phone)],['Confirmed with',`Passkey (${k.name})`],['Time',new Date().toUTCString().replace('GMT','UTC')]]});
  addAudit(u.email,changed?'Phone changed with passkey':'Phone verified with passkey',`${changed?mask(old)+' → ':''}${mask(phone)} (${k.name})`,ipOf(req));save();pushAdmins('sync',{});send(res,200,{ok:true,changed})};
routes['POST /api/passkey/rename']=async(req,res,url)=>{const u=authed(req,url),b=await body(req),k=(u.passkeys||[]).find(x=>x.id===b.id);if(!k)throw fail(404,'Passkey not found.');
  k.name=str(b.name,40)||k.name;save();send(res,200,{ok:true,passkeys:pkList(u)})};
routes['POST /api/passkey/delete']=async(req,res,url)=>{const u=authed(req,url),b=await body(req),k=(u.passkeys||[]).find(x=>x.id===b.id);if(!k)throw fail(404,'Passkey not found.');
  u.passkeys=u.passkeys.filter(x=>x!==k);notify(u.id,'Passkey removed',`The passkey "${k.name}" was removed from your HarborPay account and can no longer be used to sign in. If this wasn't you, change your password now.`,{view:'security'});
  addAudit(u.email,'Passkey removed',k.name,ipOf(req));save();send(res,200,{ok:true,passkeys:pkList(u)})};
routes['POST /api/admin/ben']=async(req,res,url)=>{
  const a=admin(req,url),b=await body(req),text=String(b.text||'').replace(/\r/g,'').trim().slice(0,6000);if(!text)throw fail(400,'Type a command.');
  if(b.pick){} // the client rewrites the command with the chosen email
  {const bp=bbLooks(text);if(bp){const r=benBank(text,bp);if(r.ask)return send(res,200,{reply:r.ask,choices:(r.choices||[]).map(u=>u.id?{label:`${u.name} (${u.email})`,email:u.email}:{label:u.name,email:u.email}),retry:r.retry});
      const id=uid('ben');BEN_PLANS.set(id,{adminId:a.id,exp:Date.now()+10*6e4,steps:[r],text:text.slice(0,300)});return send(res,200,{reply:'I matched these bank details. Check them, then confirm.',plan:{id,steps:[r.summary]}})}}
  let parts=/^\s*(?:(?:hey |hi |ok |okay )?ben[\s,:!-]*)?(message|msg|tell|send|notify|email|announce|broadcast)\b/i.test(text)?[text]:text.split(/\n|;|\bthen\b|\band then\b/i).map(x=>x.trim()).filter(Boolean).slice(0,10),steps=parts.map(benParse); // a message is one step, however many lines it has
  let viaAI=false;
  const weak=L=>L.filter(x=>x===null||x.ask).length;
  if(weak(steps)&&aiOn()){try{const out=await benAI(text);
      if(out&&/^SAY:/i.test(out))return send(res,200,{reply:out.replace(/^SAY:\s*/i,'')});
      if(out){const p2=out.split('\n').map(x=>x.trim().replace(/^[-•\d.)\s]+/,'')).filter(Boolean).slice(0,10),s2=p2.map(benParse);if(s2.length&&s2.every(x=>x)&&weak(s2)<weak(steps)){parts=p2;steps=s2;viaAI=true}}}catch{}}
  const bad=steps.findIndex(x=>x===null);
  if(bad>=0)return send(res,200,{reply:`I did not understand "${parts[bad]}". Type help to see what I can do.${aiOn()?'':' Tip: start with the action, like "credit demo usd 10".'}`});
  const asks=steps.filter(x=>x.ask);if(asks.length)return send(res,200,{reply:asks.map(x=>x.ask).join('\n'),choices:benChoices(asks[0].choices),retry:asks[0].choices?parts[steps.indexOf(asks[0])]:''});
  const says=steps.filter(x=>x.say||x.look).map(x=>x.say||benLook(x)),todo=steps.filter(x=>x.kind);
  if(!todo.length)return send(res,200,{reply:says.join('\n\n')});
  const id=uid('ben');BEN_PLANS.set(id,{adminId:a.id,exp:Date.now()+10*6e4,steps:todo,text});
  for(const[k,v]of BEN_PLANS)if(v.exp<Date.now())BEN_PLANS.delete(k);
  send(res,200,{reply:says.join('\n\n'),plan:{id,steps:todo.map(x=>x.summary)},viaAI});
};
routes['POST /api/admin/ben/run']=async(req,res,url)=>{
  const a=admin(req,url),b=await body(req),p=BEN_PLANS.get(String(b.id||''));
  if(!p||p.adminId!==a.id||p.exp<Date.now())throw fail(400,'This plan expired. Type the command again.');
  BEN_PLANS.delete(b.id);const out=[];let ok=0;
  for(const st of p.steps){try{const r=await benRun(req,a,st);out.push('✓ '+benFirst(st.summary.split('\n')[0])+(r?` (${r})`:''));ok++}catch(e){out.push('✗ '+benFirst(st.summary)+' — '+e.message);break}}
  if(ok<p.steps.length&&ok+1<p.steps.length)out.push(`Stopped. The remaining ${p.steps.length-ok-1} step${p.steps.length-ok-1>1?'s were':' was'} not done.`);
  addAudit(a.email,'Ben command',`"${str(p.text,300)}" — ${ok}/${p.steps.length} done`,ipOf(req));save();
  send(res,200,{reply:out.join('\n'),ok:ok===p.steps.length});
};
const siteUrl=req=>APP_URL||origin(req);
let slugCache=null;const blogSlugs=()=>{if(!slugCache){try{slugCache=[...new Set((fs.readFileSync(findFile('index.html'),'utf8').match(/slug:'([a-z0-9-]+)'/g)||[]).map(x=>x.slice(6,-1)))]}catch{slugCache=[]}}return slugCache};
const HEADERS={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Permissions-Policy':'camera=(self), microphone=(self), geolocation=()','Cross-Origin-Opener-Policy':'same-origin','Content-Security-Policy':"frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"};
http.createServer(async(req,res)=>{
  for(const[k,v]of Object.entries(HEADERS))res.setHeader(k,v);
  res.setHeader('X-HP','1'); // marks pages that really come from HarborPay, so the app can hide the host's own error pages
  if(LIVE&&req.headers['x-forwarded-proto']==='https')res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
  const url=new URL(req.url,'http://x');
  try{
    /* anti-copy: website-copier tools get nothing, and other websites cannot use HarborPay's API from a visitor's browser */
    const ua=String(req.headers['user-agent']||'');
    if(req.method==='GET'&&!url.pathname.startsWith('/api/')&&url.pathname!=='/healthz'&&process.env.ALLOW_COPIERS!=='1'&&COPIER_RE.test(ua)){addAudit('system','Website copier blocked',`${ua.slice(0,80)} (${ipOf(req)})`,ipOf(req));res.writeHead(403,{'Content-Type':'text/plain'});return res.end('Copying this website is not allowed.')}
    if(url.pathname.startsWith('/api/')&&req.method!=='GET'&&url.pathname!=='/api/clone-report'){const o=req.headers.origin;if(o&&o!=='null'){let oh='';try{oh=new URL(o).host}catch{}const hosts=[req.headers.host,req.headers['x-forwarded-host']].filter(Boolean);if(oh&&!hosts.includes(oh)){addAudit('system','Request from another website blocked',`${o} → ${url.pathname}`,ipOf(req));throw fail(403,'Requests from other websites are not allowed.')}}}
    const h=routes[req.method+' '+url.pathname];
    if(h)return await h(req,res,url);
    if(req.method==='GET'&&url.pathname.startsWith('/verify/')){ // the tap-to-verify link
      const tk=url.pathname.slice(8),u=tk.length>=16&&db.users.find(x=>x.ev&&x.ev.token===tk);
      if(!u){res.writeHead(404,{'Content-Type':'text/plain'});return res.end('This verification link is not valid.')}
      u.ev={status:'verified',ts:Date.now()};addAudit(u.email,'Email verified',u.email,ipOf(req));save();pushAdmins('sync',{});
      res.writeHead(302,{Location:'/?verified=1'});return res.end();
    }
    /* installable app (PWA): manifest, service worker, icons, and the Android app link file */
    if(req.method==='GET'&&url.pathname==='/manifest.webmanifest'){res.writeHead(200,{'Content-Type':'application/manifest+json','Cache-Control':'public, max-age=3600'});return res.end(JSON.stringify({
      id:'/',name:'HarborPay',short_name:'HarborPay',description:'Get paid in USD, EUR, GBP, MXN and COP, and withdraw in crypto or to your bank.',
      start_url:'/?source=app',scope:'/',display:'standalone',orientation:'portrait',background_color:'#FFFFFF',theme_color:'#2F5BEA',categories:['finance'],
      icons:[{src:'/icon-192.png',sizes:'192x192',type:'image/png',purpose:'any'},{src:'/icon-512.png',sizes:'512x512',type:'image/png',purpose:'any'},
        {src:'/icon-maskable-192.png',sizes:'192x192',type:'image/png',purpose:'maskable'},{src:'/icon-maskable-512.png',sizes:'512x512',type:'image/png',purpose:'maskable'}]}))}
    if((req.method==='GET'||req.method==='HEAD')&&url.pathname==='/healthz'){res.writeHead(200,{'Content-Type':'text/plain','Cache-Control':'no-store'});return res.end('ok')}
    if(req.method==='GET'&&url.pathname==='/sw.js'){res.writeHead(200,{'Content-Type':'text/javascript','Cache-Control':'no-cache','Service-Worker-Allowed':'/'});return res.end(SW_JS)}
    if(req.method==='GET'&&/^\/(icon-(maskable-)?(192|512)|apple-touch-icon)\.png$/.test(url.pathname)){const f=findFile(url.pathname.slice(1));if(!f){res.writeHead(404);return res.end()}res.writeHead(200,{'Content-Type':'image/png','Cache-Control':'public, max-age=86400'});return res.end(fs.readFileSync(f))}
    if(req.method==='GET'&&url.pathname==='/.well-known/assetlinks.json'){const f=findFile('assetlinks.json');if(!f){res.writeHead(404);return res.end()}res.writeHead(200,{'Content-Type':'application/json'});return res.end(fs.readFileSync(f))}
    if(req.method==='GET'&&/^\/(favicon(-16|-32)?\.png|favicon\.ico)$/.test(url.pathname)){ // the small browser-tab icon
      const want=url.pathname.slice(1),f=findFile(want)||findFile('favicon.png');if(!f){res.writeHead(404);return res.end()}
      res.writeHead(200,{'Content-Type':f.endsWith('.ico')?'image/x-icon':'image/png','Cache-Control':'public, max-age=86400'});return res.end(fs.readFileSync(f))}
    /* search engines: robots.txt, sitemap.xml, share image; every website page has its own address */
    if(req.method==='GET'&&url.pathname==='/robots.txt'){res.writeHead(200,{'Content-Type':'text/plain'});return res.end(`User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /verify/\n\nSitemap: ${siteUrl(req)}/sitemap.xml\n`)}
    if(req.method==='GET'&&url.pathname==='/sitemap.xml'){const b=siteUrl(req),d=new Date().toISOString().slice(0,10),pages=['/','/product','/faq','/blog','/security',...blogSlugs().map(x=>'/blog/'+x)];
      res.writeHead(200,{'Content-Type':'application/xml'});return res.end(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${pages.map(p=>`  <url><loc>${b}${p}</loc><lastmod>${d}</lastmod></url>`).join('\n')}\n</urlset>\n`)}
    if(req.method==='GET'&&/^\/mail-[a-z0-9-]{1,30}\.(png|jpg)$/.test(url.pathname)){const f=findFile(url.pathname.slice(1));if(!f){res.writeHead(404);return res.end()}res.writeHead(200,{'Content-Type':url.pathname.endsWith('.jpg')?'image/jpeg':'image/png','Cache-Control':'public, max-age=604800'});return res.end(fs.readFileSync(f))}
    if(req.method==='GET'&&url.pathname==='/og-image.png'){const f=findFile('og-image.png');if(!f){res.writeHead(404);return res.end()}res.writeHead(200,{'Content-Type':'image/png','Cache-Control':'public, max-age=86400'});return res.end(fs.readFileSync(f))}
    if(req.method==='GET'&&/^\/(product|faq|security|blog)(\/[a-z0-9-]+)?\/?$/.test(url.pathname))url.pathname='/';
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){const f=findFile('index.html');if(!f){res.writeHead(500,{'Content-Type':'text/plain'});return res.end('index.html not found. Put it in a "public" folder next to server.js (or beside server.js).')}res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache, must-revalidate'});return res.end(fs.readFileSync(f))}
    send(res,404,{error:'Not found'});
  }catch(e){if(!res.headersSent)send(res,e.code>=400&&e.code<600?e.code:500,{error:e.message||'Server error'});if(!(e.code>=400)){console.error(e);jbErr(String(e&&e.message||e),req.url)}}
}).on('error',e=>{
  if(e.code==='EADDRINUSE'){console.error(`\nPort ${PORT} is already in use. An older copy of HarborPay is probably still running, so your browser is still showing the OLD site.\nClose that one first (press Ctrl+C in its window, or close the window), then run "node server.js" again.\n`);process.exit(1)}
  throw e;
}).listen(PORT,process.env.HOST||(LIVE&&!process.env.RAILWAY_ENVIRONMENT&&!process.env.RENDER?'127.0.0.1':undefined),()=>console.log(`HarborPay${LIVE?' (live mode)':' (demo mode)'} on http://localhost:${PORT}  (email: ${({resend:'Resend',smtp:'SMTP',log:'logged to data/outbox.log'})[mailMode()]}${process.env.RESEND_WEBHOOK_SECRET?', replies by email on':''})`));
/* keep the site running if one request hits an unexpected error, instead of the whole server stopping (which shows the host's error page) */
process.on('uncaughtException',e=>{console.error('Unexpected error (server kept running):',e&&e.stack||e);jbErr(String(e&&e.message||e),'background')});
process.on('unhandledRejection',e=>{console.error('Unhandled promise (server kept running):',e&&e.stack||e);jbErr(String(e&&e.message||e),'background')});
