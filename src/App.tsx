import { useEffect, useState } from 'react';
import { ShieldCheck, LockKeyhole, UploadCloud, FileCheck2, Download, Trash2, RefreshCw, AlertTriangle, CheckCircle2, KeyRound } from 'lucide-react';

type VaultRecord = { id:string; name:string; size:number; type:string; created:string; sha256:string; iv:ArrayBuffer; salt:ArrayBuffer; ciphertext:ArrayBuffer };
const DB_NAME = 'ciphernest-vault-v1';
function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve,reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('files', { keyPath: 'id' });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function allRecords(): Promise<VaultRecord[]> {
  const db=await openDb();
  return new Promise((resolve,reject)=>{ const tx=db.transaction('files','readonly'); const r=tx.objectStore('files').getAll(); r.onsuccess=()=>resolve(r.result as VaultRecord[]); r.onerror=()=>reject(r.error); });
}
async function saveRecord(record:VaultRecord) {
  const db=await openDb();
  return new Promise<void>((resolve,reject)=>{ const tx=db.transaction('files','readwrite'); tx.objectStore('files').put(record); tx.oncomplete=()=>resolve(); tx.onerror=()=>reject(tx.error); });
}
async function removeRecord(id:string) {
  const db=await openDb();
  return new Promise<void>((resolve,reject)=>{ const tx=db.transaction('files','readwrite'); tx.objectStore('files').delete(id); tx.oncomplete=()=>resolve(); tx.onerror=()=>reject(tx.error); });
}
const hex = (buffer:ArrayBuffer) => [...new Uint8Array(buffer)].map(b=>b.toString(16).padStart(2,'0')).join('');
async function digest(data:ArrayBuffer) { return hex(await crypto.subtle.digest('SHA-256',data)); }
async function deriveKey(password:string,salt:ArrayBuffer) {
  const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function bytes(n:number): ArrayBuffer { return crypto.getRandomValues(new Uint8Array(n)).buffer as ArrayBuffer; }
function formatBytes(n:number) { if(n<1024)return `${n} B`; if(n<1024*1024)return `${(n/1024).toFixed(1)} KB`; return `${(n/1024/1024).toFixed(2)} MB`; }
export default function App() {
  const [records,setRecords]=useState<VaultRecord[]>([]);
  const [selected,setSelected]=useState<File|null>(null);
  const [password,setPassword]=useState('');
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState<{kind:'ok'|'error'|'info';text:string}|null>(null);
  const [verifyId,setVerifyId]=useState('');
  const [verifyResult,setVerifyResult]=useState<string|null>(null);
  const [decryptPasswords,setDecryptPasswords]=useState<Record<string,string>>({});
  const refresh=async()=>{try{setRecords((await allRecords()).sort((a,b)=>b.created.localeCompare(a.created)));}catch{setMessage({kind:'error',text:'Browser storage is unavailable. Use a modern browser over HTTPS.'});}};
  useEffect(()=>{void refresh();},[]);
  const upload=async()=>{
    if(!selected||password.length<8){setMessage({kind:'error',text:'Choose a file and use a passphrase of at least 8 characters.'});return;}
    setBusy(true);setMessage(null);
    try{
      const plain=await selected.arrayBuffer();
      const sha256=await digest(plain);
      const salt=bytes(16),iv=bytes(12),key=await deriveKey(password,salt);
      const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,plain);
      const rec:VaultRecord={id:crypto.randomUUID(),name:selected.name,size:selected.size,type:selected.type||'application/octet-stream',created:new Date().toISOString(),sha256,iv,salt,ciphertext};
      await saveRecord(rec); await refresh(); setSelected(null);setPassword('');
      setMessage({kind:'ok',text:`Encrypted and saved ${rec.name}. SHA-256 is calculated from the original file contents.`});
    }catch(e){setMessage({kind:'error',text:`Could not encrypt/save file: ${e instanceof Error?e.message:'unknown error'}`});}
    finally{setBusy(false);}
  };
  const decrypt=async(rec:VaultRecord)=>{
    const pass=decryptPasswords[rec.id]||'';
    if(!pass){setMessage({kind:'error',text:'Enter the passphrase used when this file was encrypted.'});return;}
    setBusy(true);setMessage(null);
    try{
      const key=await deriveKey(pass,rec.salt);
      const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:rec.iv},key,rec.ciphertext);
      const actual=await digest(plain);
      if(actual!==rec.sha256) throw new Error('Integrity check failed: decrypted content hash does not match.');
      const blob=new Blob([plain],{type:rec.type});const url=URL.createObjectURL(blob);
      const a=document.createElement('a');a.href=url;a.download=rec.name;a.click();URL.revokeObjectURL(url);
      setMessage({kind:'ok',text:`Decryption and SHA-256 integrity check succeeded for ${rec.name}.`});
    }catch{setMessage({kind:'error',text:'Decryption failed. The passphrase may be wrong or stored data may be damaged.'});}
    finally{setBusy(false);}
  };
  const verify=async()=>{
    const rec=records.find(r=>r.id===verifyId);if(!rec){setVerifyResult('Choose a stored file first.');return;}
    setBusy(true);
    try{
      const key=await deriveKey(decryptPasswords[rec.id]||'',rec.salt);
      const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:rec.iv},key,rec.ciphertext);
      const actual=await digest(plain);
      setVerifyResult(actual===rec.sha256?`PASS — decrypted file content matches SHA-256 ${actual}`:'FAIL — content hash does not match.');
    }catch{setVerifyResult('Verification could not decrypt this file. Enter its correct passphrase in the file card first.');}
    finally{setBusy(false);}
  };
  const del=async(rec:VaultRecord)=>{if(!confirm(`Permanently delete encrypted local copy of "${rec.name}" from this browser?`))return;await removeRecord(rec.id);await refresh();setMessage({kind:'ok',text:'Encrypted local copy deleted.'});};
  return <div className="min-h-screen bg-slate-950 text-slate-100">
    <header className="border-b border-slate-800 bg-slate-900/80"><div className="mx-auto flex max-w-6xl items-center gap-3 px-5 py-5"><div className="rounded-xl bg-emerald-400/10 p-2 text-emerald-300"><ShieldCheck size={28}/></div><div><h1 className="text-xl font-bold tracking-tight">CipherNest</h1><p className="text-xs text-slate-400">Local-first encrypted file vault</p></div><span className="ml-auto rounded-full border border-emerald-500/30 px-3 py-1 text-xs text-emerald-300">AES-256-GCM</span></div></header>
    <main className="mx-auto max-w-6xl space-y-6 px-5 py-8">
      <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><div className="mb-4 flex items-center gap-2"><LockKeyhole className="text-emerald-300"/><h2 className="text-lg font-semibold">Encrypt and store a file</h2></div><p className="mb-5 text-sm text-slate-400">Files are encrypted in your browser before being saved to this browser's IndexedDB. Your passphrase is not saved.</p>
        <div className="grid gap-4 md:grid-cols-2"><label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-700 bg-slate-950 p-6 text-center"><UploadCloud className="mb-2 text-emerald-300"/><span className="text-sm font-medium">{selected?selected.name:'Choose a file'}</span><span className="mt-1 text-xs text-slate-500">{selected?formatBytes(selected.size):'Any file type'}</span><input type="file" className="mt-3 block max-w-full text-xs text-slate-400" onChange={e=>setSelected(e.target.files?.[0]||null)}/></label>
        <div className="flex flex-col gap-3"><label className="text-sm text-slate-300">Encryption passphrase (minimum 8 characters)<input type="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-3 text-sm outline-none focus:border-emerald-400" placeholder="Create a strong passphrase"/></label><button disabled={busy||!selected||password.length<8} onClick={()=>void upload()} className="mt-auto flex items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 py-3 font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"><LockKeyhole size={17}/>{busy?'Working…':'Encrypt & save locally'}</button></div></div>
      </section>
      {message&&<div className={`flex items-start gap-3 rounded-xl border p-4 text-sm ${message.kind==='error'?'border-rose-500/30 bg-rose-950/30 text-rose-200':'border-emerald-500/30 bg-emerald-950/30 text-emerald-200'}`}>{message.kind==='error'?<AlertTriangle size={18}/>:<CheckCircle2 size={18}/>}<span>{message.text}</span></div>}
      <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><div className="mb-4 flex items-center justify-between"><div className="flex items-center gap-2"><FileCheck2 className="text-emerald-300"/><h2 className="text-lg font-semibold">Your encrypted vault</h2></div><button onClick={()=>void refresh()} className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:bg-slate-800" aria-label="Refresh"><RefreshCw size={16}/></button></div>
        {records.length===0?<p className="rounded-xl border border-dashed border-slate-700 p-8 text-center text-sm text-slate-400">No files saved in this browser yet. Upload a file above to get started.</p>:<div className="space-y-3">{records.map(r=><article key={r.id} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"><div className="flex flex-wrap items-start gap-3"><div className="min-w-0 flex-1"><h3 className="break-all font-medium">{r.name}</h3><p className="mt-1 text-xs text-slate-400">{formatBytes(r.size)} · {new Date(r.created).toLocaleString()} · AES-256-GCM</p><p className="mt-3 break-all font-mono text-[11px] text-emerald-300">SHA-256: {r.sha256}</p><label className="mt-3 block text-xs text-slate-400">Passphrase to decrypt / verify<input type="password" autoComplete="current-password" value={decryptPasswords[r.id]||''} onChange={e=>setDecryptPasswords(p=>({...p,[r.id]:e.target.value}))} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white outline-none focus:border-emerald-400" placeholder="Enter original passphrase"/></label></div><div className="flex gap-2"><button disabled={busy} onClick={()=>void decrypt(r)} className="flex items-center gap-2 rounded-lg bg-emerald-400 px-3 py-2 text-xs font-semibold text-slate-950 disabled:opacity-40"><Download size={15}/>Decrypt</button><button onClick={()=>void del(r)} className="rounded-lg border border-rose-900 px-3 py-2 text-rose-300 hover:bg-rose-950/40" aria-label="Delete file"><Trash2 size={15}/></button></div></div></article>)}</div>}
      </section>
      <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><div className="mb-3 flex items-center gap-2"><KeyRound className="text-emerald-300"/><h2 className="text-lg font-semibold">Integrity verification</h2></div><p className="mb-4 text-sm text-slate-400">Decrypts the stored ciphertext and recomputes SHA-256 over the original file bytes. This is a local integrity check, not a blockchain proof.</p><div className="flex flex-col gap-3 sm:flex-row"><select value={verifyId} onChange={e=>setVerifyId(e.target.value)} className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-3 text-sm"><option value="">Select a vault file</option>{records.map(r=><option key={r.id} value={r.id}>{r.name}</option>)}</select><button disabled={busy||!verifyId} onClick={()=>void verify()} className="rounded-lg bg-slate-100 px-4 py-3 text-sm font-semibold text-slate-900 disabled:opacity-40">Verify content</button></div>{verifyResult&&<p className="mt-4 break-all rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs">{verifyResult}</p>}</section>
      <footer className="space-y-2 pb-6 text-xs leading-relaxed text-slate-500"><p><strong className="text-slate-300">Important limitations:</strong> this is a local-first browser vault, not shared cloud storage. Files remain in the current browser profile on this device and are not uploaded to Vercel. Clearing browser site data can erase them. Losing a passphrase means the file cannot be decrypted.</p><p>Uses Web Crypto AES-GCM with a PBKDF2-SHA-256 derived key (310,000 iterations), random salt and 96-bit IV. Keep backups of important originals. This prototype has not undergone an independent security audit.</p></footer>
    </main>
  </div>;
}
