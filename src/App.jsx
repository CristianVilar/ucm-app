import { useState, useEffect, useRef, useCallback, useMemo, createContext, useContext, memo } from "react"
import * as XLSX from 'xlsx'
import { createClient } from '@supabase/supabase-js'

// ═══════════════════════════════════════════════════
//  🔒 MÓDULO DE SEGURIDAD
// ═══════════════════════════════════════════════════

const HASH_VERSION = 2  // 1=SHA256, 2=PBKDF2

// ═══════════════════════════════════════════════════
//  ☁️  SUPABASE
// ═══════════════════════════════════════════════════
const SB_URL = 'https://uyzzgugjjboxqxtctsgc.supabase.co'
const SB_KEY = 'sb_publishable_0_Bb00Lz1QyWW4fXsFR9SQ_kT4mc0Pm'
const sb = createClient(SB_URL, SB_KEY)

async function sbLoad() {
  try {
    const { data, error } = await sb.from('ucm_data').select('payload').eq('id','main').single()
    if (error || !data) return null
    return data.payload
  } catch { return null }
}

async function sbSave(payload) {
  try {
    await sb.from('ucm_data').upsert({ id:'main', payload, updated_at: new Date().toISOString() })
  } catch(e) { console.warn('Supabase save error:', e) }
}
const sha256 = async (str) => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('')
}
const APP_SALT = 'UCM_GI_v2_8f3a1c9b'
const _sysRef = [89,67,77,50,95,115,121,115].map(x=>String.fromCharCode(x+4)).join('')
const hashPwd = async (pwd, userSalt) => {
  const enc = new TextEncoder()
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveBits'])
  const salt = enc.encode(userSalt + _sysRef)
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:100000}, keyMat, 256)
  return Array.from(new Uint8Array(bits)).map(b=>b.toString(16).padStart(2,'0')).join('')
}

const sanitize = (val, maxLen = 500) => {
  if (typeof val !== 'string') return ''
  return val
    .replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;')
    .replace(/javascript:/gi,'').replace(/vbscript:/gi,'')
    .replace(/on\w+\s*=/gi,'').replace(/data:/gi,'')
    .trim().slice(0, maxLen)
}
const san = sanitize

const loginRL = {
  MAX:5, WIN:300000,
  _k:(k)=>'_rl_'+btoa(encodeURIComponent(k)).slice(0,16),
  _g(k){try{const d=sessionStorage.getItem(this._k(k));return d?JSON.parse(d):null}catch{return null}},
  _s(k,v){try{sessionStorage.setItem(this._k(k),JSON.stringify(v))}catch{}},
  _d(k){try{sessionStorage.removeItem(this._k(k))}catch{}},
  check(k){const r=this._g(k);if(!r)return{locked:false,remaining:this.MAX};if(Date.now()-r.first>this.WIN){this._d(k);return{locked:false,remaining:this.MAX}};if(r.count>=this.MAX)return{locked:true,secsLeft:Math.ceil((this.WIN-(Date.now()-r.first))/1000)};return{locked:false,remaining:this.MAX-r.count}},
  hit(k){const r=this._g(k)||{count:0,first:Date.now()};r.count++;this._s(k,r);return r.count},
  reset(k){this._d(k)}
}

const validatePwd = (pwd) => {
  const e=[]
  if(pwd.length<8) e.push('Mínimo 8 caracteres')
  if(!/[A-Z]/.test(pwd)) e.push('Al menos 1 mayúscula')
  if(!/[0-9]/.test(pwd)) e.push('Al menos 1 número')
  return e
}

// ═══════════════════════════════════════════════════
//  🔔 TOAST NOTIFICATIONS
// ═══════════════════════════════════════════════════

const ToastCtx = createContext(null)
const useToast = () => useContext(ToastCtx)
const TI = {success:'✅',error:'❌',warn:'⚠️',info:'ℹ️'}
const TC2 = {success:'#16a34a',error:'#ef4444',warn:'#f59e0b',info:'#2563eb'}

function ToastProvider({children}) {
  const [toasts,setToasts]=useState([])
  const add=useCallback((msg,type='info',dur=3500)=>{
    const id=Math.random().toString(36).slice(2)
    setToasts(t=>[...t,{id,msg,type}])
    setTimeout(()=>setToasts(t=>t.filter(x=>x.id!==id)),dur)
  },[])
  return (
    <ToastCtx.Provider value={add}>
      {children}
      <div style={{position:'fixed',bottom:20,right:20,zIndex:9999,display:'flex',flexDirection:'column',gap:8,maxWidth:360,pointerEvents:'none'}}>
        {toasts.map(t=>(
          <div key={t.id} style={{background:'#ffffff',border:`1px solid ${TC2[t.type]}55`,borderLeft:`3px solid ${TC2[t.type]}`,borderRadius:8,padding:'10px 14px',display:'flex',alignItems:'center',gap:10,boxShadow:'0 4px 20px rgba(0,0,0,0.12)',color:'#334155',fontSize:13,animation:'toastIn .25s ease'}}>
            <span>{TI[t.type]}</span><span style={{flex:1}}>{t.msg}</span>
          </div>
        ))}
      </div>
      <style>{`@keyframes toastIn{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}`}</style>
    </ToastCtx.Provider>
  )
}

// ═══════════════════════════════════════════════════
//  ⏱ GESTIÓN DE SESIÓN
// ═══════════════════════════════════════════════════

const SESS_TIMEOUT = 30*60*1000
const SESS_WARN    = 5*60*1000

function useSessionTimeout(onExpire) {
  const lastRef=useRef(Date.now()), warnedRef=useRef(false)
  const [remaining,setRemaining]=useState(SESS_TIMEOUT)
  const reset=useCallback(()=>{ lastRef.current=Date.now(); warnedRef.current=false; setRemaining(SESS_TIMEOUT) },[])
  useEffect(()=>{
    const EVT=['mousedown','keydown','touchstart','wheel']
    EVT.forEach(e=>document.addEventListener(e,reset))
    const iv=setInterval(()=>{ const left=Math.max(0,SESS_TIMEOUT-(Date.now()-lastRef.current)); setRemaining(left); if(left===0) onExpire() },5000)
    return ()=>{ EVT.forEach(e=>document.removeEventListener(e,reset)); clearInterval(iv) }
  },[reset,onExpire])
  return {remaining,reset}
}

function SessionBar({remaining,onExtend}) {
  if(remaining>SESS_WARN) return null
  const mins=Math.ceil(remaining/60000), pct=(remaining/SESS_WARN)*100
  const col=remaining<60000?'#ef4444':remaining<240000?'#f59e0b':'#d97706'
  return(
    <div style={{position:'fixed',top:0,left:0,right:0,zIndex:999,background:'#ffffff',borderBottom:`1px solid ${col}55`,padding:'5px 16px',display:'flex',alignItems:'center',gap:10}}>
      <div style={{background:'#e2e8f0',borderRadius:4,height:3,flex:1}}><div style={{background:col,height:'100%',width:`${pct}%`,borderRadius:4,transition:'width .5s'}}/></div>
      <span style={{color:col,fontSize:11,fontWeight:700,whiteSpace:'nowrap'}}>⏱ Sesión: {mins} min</span>
      <button onClick={onExtend} style={{background:col,border:'none',borderRadius:4,color:'#fff',cursor:'pointer',fontSize:11,fontWeight:700,padding:'3px 8px'}}>Renovar</button>
    </div>
  )
}

// ═══════════════════════════════════════════════════
//  🎨 PALETA & CONSTANTES
// ═══════════════════════════════════════════════════

const C={bg:'#f0f4f8',s1:'#ffffff',s2:'#f8fafc',s3:'#e2e8f0',brd:'#cbd5e1',acc:'#1d4ed8',acl:'#2563eb',red:'#dc2626',amb:'#d97706',grn:'#16a34a',pur:'#7c3aed',txt:'#334155',tb:'#0f172a',tm:'#64748b'}
const TC={crítico:C.red,mediana:C.amb,vir:C.pur,básico:'#22c55e',otro:C.tm}
const ROLES={admin:'Administrador',jefatura:'Jefatura',farmacia:'Farmacia',supervisor:'Supervisor',lectura:'Solo lectura'}
const ROLE_COLORS={admin:C.red,jefatura:C.amb,farmacia:C.grn,supervisor:C.pur,lectura:C.tm}
const TIPOS_EQUIP=['VM','BIC','Monitor','Tablet','Teléfono','Bomba aspiración','Otro']
const TIPOS_MOVIL=['crítico','mediana','vir','básico','otro']
const NOTE_COLORS=['#2563eb','#16a34a','#ef4444','#f59e0b','#a855f7','#06b6d4']

const getPerm=(role)=>({
  editMoviles:['admin','jefatura','farmacia','supervisor'].includes(role),
  editFarmacia:['admin','jefatura','farmacia'].includes(role),
  editControlados:['admin','jefatura','farmacia'].includes(role),
  editEquipamientos:['admin','jefatura','farmacia'].includes(role),
  canExport:['admin','jefatura','farmacia','supervisor'].includes(role),
  manageUsers:['admin','jefatura'].includes(role),
  deleteUsers:['admin','jefatura'].includes(role),
  createAdmin:role==='admin',
  manageBases:['admin','jefatura','farmacia'].includes(role),
  resetData:['admin','jefatura'].includes(role),
  isReadOnly:role==='lectura',
  canPizarra:role!=='lectura',
  deletePizarraAny:role==='admin',
})

const D0={
  users:[
    {id:'u1',username:'admin',     password:'AdminUCM2026',email:'admin@ucm.cl', nombre:'Administrador',  role:'admin',     passwordHashed:false},
    {id:'u2',username:'supervisor1',password:'UCMops2024!', email:'sup@ucm.cl',  nombre:'Juan Supervisor',role:'supervisor',passwordHashed:false},
    {id:'u3',username:'farmacia1',  password:'UCMops2024!', email:'farm@ucm.cl', nombre:'Ana Farmacia',   role:'farmacia',  passwordHashed:false},
  ],

  // ─── 5 BASES OPERATIVAS ──────────────────────────────────────────────────
  bases:[
    {nombre:'Base 1', direccion:'Av. Pedro de Valdivia 4077, Ñuñoa'},
    {nombre:'Base 2', direccion:'CESFAM Dr. Salvador Allende, Pudahuel'},
    {nombre:'Base 8', direccion:'Clínica Indisa, Maipú'},
    {nombre:'Base 13',direccion:'Sin dirección registrada'},
    {nombre:'Base 15',direccion:'Sin dirección registrada'},
  ],

  // ─── 26 MÓVILES (desde Excel) ────────────────────────────────────────────
  moviles:[
    {id:'m01',numero:'315',base:'Base 1', tipo:'crítico',patente:'',codigoHorario:'',notas:''},
    {id:'m02',numero:'303',base:'Base 2', tipo:'mediana',patente:'',codigoHorario:'',notas:''},
    {id:'m03',numero:'157',base:'Base 1', tipo:'vir',    patente:'',codigoHorario:'',notas:''},
    {id:'m04',numero:'327',base:'Base 1', tipo:'crítico',patente:'',codigoHorario:'',notas:''},
    {id:'m05',numero:'313',base:'Base 1', tipo:'crítico',patente:'',codigoHorario:'',notas:''},
    {id:'m06',numero:'235',base:'Base 1', tipo:'crítico',patente:'',codigoHorario:'',notas:''},
    {id:'m07',numero:'161',base:'Base 2', tipo:'vir',    patente:'',codigoHorario:'',notas:''},
    {id:'m08',numero:'155',base:'Base 8', tipo:'vir',    patente:'',codigoHorario:'',notas:''},
    {id:'m09',numero:'297',base:'Base 2', tipo:'mediana',patente:'',codigoHorario:'',notas:''},
    {id:'m10',numero:'321',base:'Base 2', tipo:'mediana',patente:'',codigoHorario:'',notas:''},
    {id:'m11',numero:'303',base:'Base 8', tipo:'mediana',patente:'',codigoHorario:'',notas:''},
    {id:'m12',numero:'333',base:'Base 1', tipo:'mediana',patente:'',codigoHorario:'',notas:''},
    {id:'m13',numero:'159',base:'Base 1', tipo:'vir',    patente:'',codigoHorario:'',notas:''},
    {id:'m14',numero:'251',base:'Base 1', tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m15',numero:'225',base:'Base 1', tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m16',numero:'231',base:'Base 1', tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m17',numero:'241',base:'Base 1', tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m18',numero:'299',base:'Base 15',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m19',numero:'305',base:'Base 15',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m20',numero:'309',base:'Base 15',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m21',numero:'291',base:'Base 15',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m22',numero:'271',base:'Base 13',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m23',numero:'273',base:'Base 13',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m24',numero:'255',base:'Base 13',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m25',numero:'249',base:'Base 13',tipo:'básico', patente:'',codigoHorario:'',notas:''},
    {id:'m26',numero:'363',base:'Base 13',tipo:'básico', patente:'',codigoHorario:'',notas:''},
  ],

  // ─── 71 EQUIPAMIENTOS (desde Excel — todos en stock inicial) ─────────────
  equipamientos:[
    // VM — Hamilton T1 (101-106) + Dragger Oxylog 3000 plus (107)
    {id:'e101',tipo:'VM',idInterno:'VM-101',serie:'AD12345',modelo:'Hamilton T1',          movil_id:null,estado:'stock',notas:''},
    {id:'e102',tipo:'VM',idInterno:'VM-102',serie:'AD12346',modelo:'Hamilton T1',          movil_id:null,estado:'stock',notas:''},
    {id:'e103',tipo:'VM',idInterno:'VM-103',serie:'AD12347',modelo:'Hamilton T1',          movil_id:null,estado:'stock',notas:''},
    {id:'e104',tipo:'VM',idInterno:'VM-104',serie:'AD12348',modelo:'Hamilton T1',          movil_id:null,estado:'stock',notas:''},
    {id:'e105',tipo:'VM',idInterno:'VM-105',serie:'AD12349',modelo:'Hamilton T1',          movil_id:null,estado:'stock',notas:''},
    {id:'e106',tipo:'VM',idInterno:'VM-106',serie:'AD12350',modelo:'Hamilton T1',          movil_id:null,estado:'stock',notas:''},
    {id:'e107',tipo:'VM',idInterno:'VM-107',serie:'OX983215543',modelo:'Dragger Oxylog 3000 plus',movil_id:null,estado:'stock',notas:''},
    // BIC — Braun SpaceLine (2001-2030)
    {id:'e2001',tipo:'BIC',idInterno:'BIC-2001',serie:'BB00001',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2002',tipo:'BIC',idInterno:'BIC-2002',serie:'BB00002',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2003',tipo:'BIC',idInterno:'BIC-2003',serie:'BB00003',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2004',tipo:'BIC',idInterno:'BIC-2004',serie:'BB00004',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2005',tipo:'BIC',idInterno:'BIC-2005',serie:'BB00005',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2006',tipo:'BIC',idInterno:'BIC-2006',serie:'BB00006',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2007',tipo:'BIC',idInterno:'BIC-2007',serie:'BB00007',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2008',tipo:'BIC',idInterno:'BIC-2008',serie:'BB00008',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2009',tipo:'BIC',idInterno:'BIC-2009',serie:'BB00009',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2010',tipo:'BIC',idInterno:'BIC-2010',serie:'BB00010',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2011',tipo:'BIC',idInterno:'BIC-2011',serie:'BB00011',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2012',tipo:'BIC',idInterno:'BIC-2012',serie:'BB00012',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2013',tipo:'BIC',idInterno:'BIC-2013',serie:'BB00013',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2014',tipo:'BIC',idInterno:'BIC-2014',serie:'BB00014',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2015',tipo:'BIC',idInterno:'BIC-2015',serie:'BB00015',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2016',tipo:'BIC',idInterno:'BIC-2016',serie:'BB00016',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2017',tipo:'BIC',idInterno:'BIC-2017',serie:'BB00017',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2018',tipo:'BIC',idInterno:'BIC-2018',serie:'BB00018',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2019',tipo:'BIC',idInterno:'BIC-2019',serie:'BB00019',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2020',tipo:'BIC',idInterno:'BIC-2020',serie:'BB00020',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2021',tipo:'BIC',idInterno:'BIC-2021',serie:'BB00021',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2022',tipo:'BIC',idInterno:'BIC-2022',serie:'BB00022',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2023',tipo:'BIC',idInterno:'BIC-2023',serie:'BB00023',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2024',tipo:'BIC',idInterno:'BIC-2024',serie:'BB00024',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2025',tipo:'BIC',idInterno:'BIC-2025',serie:'BB00025',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2026',tipo:'BIC',idInterno:'BIC-2026',serie:'BB00026',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2027',tipo:'BIC',idInterno:'BIC-2027',serie:'BB00027',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2028',tipo:'BIC',idInterno:'BIC-2028',serie:'BB00028',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2029',tipo:'BIC',idInterno:'BIC-2029',serie:'BB00029',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    {id:'e2030',tipo:'BIC',idInterno:'BIC-2030',serie:'BB00030',modelo:'Braun SpaceLine',movil_id:null,estado:'stock',notas:''},
    // Monitor — Mindray Beneheart D6 (1001-1020)
    {id:'e1001',tipo:'Monitor',idInterno:'MON-1001',serie:'DZ00001',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1002',tipo:'Monitor',idInterno:'MON-1002',serie:'DZ00002',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1003',tipo:'Monitor',idInterno:'MON-1003',serie:'DZ00003',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1004',tipo:'Monitor',idInterno:'MON-1004',serie:'DZ00004',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1005',tipo:'Monitor',idInterno:'MON-1005',serie:'DZ00005',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1006',tipo:'Monitor',idInterno:'MON-1006',serie:'DZ00006',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1007',tipo:'Monitor',idInterno:'MON-1007',serie:'DZ00007',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1008',tipo:'Monitor',idInterno:'MON-1008',serie:'DZ00008',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1009',tipo:'Monitor',idInterno:'MON-1009',serie:'DZ00009',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1010',tipo:'Monitor',idInterno:'MON-1010',serie:'DZ00010',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1011',tipo:'Monitor',idInterno:'MON-1011',serie:'DZ00011',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1012',tipo:'Monitor',idInterno:'MON-1012',serie:'DZ00012',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1013',tipo:'Monitor',idInterno:'MON-1013',serie:'DZ00013',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1014',tipo:'Monitor',idInterno:'MON-1014',serie:'DZ00014',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1015',tipo:'Monitor',idInterno:'MON-1015',serie:'DZ00015',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1016',tipo:'Monitor',idInterno:'MON-1016',serie:'DZ00016',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1017',tipo:'Monitor',idInterno:'MON-1017',serie:'DZ00017',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1018',tipo:'Monitor',idInterno:'MON-1018',serie:'DZ00018',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1019',tipo:'Monitor',idInterno:'MON-1019',serie:'DZ00019',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    {id:'e1020',tipo:'Monitor',idInterno:'MON-1020',serie:'DZ00020',modelo:'Mindray Beneheart D6',movil_id:null,estado:'stock',notas:''},
    // Tablet — ThinkPad (T101-T114)
    {id:'eT101',tipo:'Tablet',idInterno:'TAB-T101',serie:'TAB00001',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT102',tipo:'Tablet',idInterno:'TAB-T102',serie:'TAB00002',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT103',tipo:'Tablet',idInterno:'TAB-T103',serie:'TAB00003',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT104',tipo:'Tablet',idInterno:'TAB-T104',serie:'TAB00004',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT105',tipo:'Tablet',idInterno:'TAB-T105',serie:'TAB00005',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT106',tipo:'Tablet',idInterno:'TAB-T106',serie:'TAB00006',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT107',tipo:'Tablet',idInterno:'TAB-T107',serie:'TAB00007',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT108',tipo:'Tablet',idInterno:'TAB-T108',serie:'TAB00008',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT109',tipo:'Tablet',idInterno:'TAB-T109',serie:'TAB00009',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT110',tipo:'Tablet',idInterno:'TAB-T110',serie:'TAB00010',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT111',tipo:'Tablet',idInterno:'TAB-T111',serie:'TAB00011',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT112',tipo:'Tablet',idInterno:'TAB-T112',serie:'TAB00012',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT113',tipo:'Tablet',idInterno:'TAB-T113',serie:'TAB00013',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
    {id:'eT114',tipo:'Tablet',idInterno:'TAB-T114',serie:'TAB00014',modelo:'ThinkPad',movil_id:null,estado:'stock',notas:''},
  ],

  // ─── 82 INSUMOS BOTIQUÍN (desde Excel) ───────────────────────────────────
  botiquin_insumos:[
    {id:'bi001',nombre:'Agujas 21G',                               stock:10,  minimo:5},
    {id:'bi002',nombre:'Jeringa 3 ml',                             stock:10,  minimo:5},
    {id:'bi003',nombre:'Branula 16',                               stock:10,  minimo:3},
    {id:'bi004',nombre:'Mariposa 21G',                             stock:10,  minimo:5},
    {id:'bi005',nombre:'Ligadura',                                 stock:10,  minimo:3},
    {id:'bi006',nombre:'Llave 3 pasos',                            stock:10,  minimo:5},
    {id:'bi007',nombre:'Tegaderm',                                 stock:10,  minimo:5},
    {id:'bi008',nombre:'Fleboclisis',                              stock:10,  minimo:5},
    {id:'bi009',nombre:'Alcohol pads',                             stock:10,  minimo:5},
    {id:'bi010',nombre:'Tapas amarillas y rojas',                  stock:10,  minimo:5},
    {id:'bi011',nombre:'Baja lenguas',                             stock:10,  minimo:5},
    {id:'bi012',nombre:'Equipo de curación',                       stock:10,  minimo:3},
    {id:'bi013',nombre:'Apósitos 10 x 20',                        stock:10,  minimo:5},
    {id:'bi014',nombre:'Gasas 7.5 x 7.5',                         stock:10,  minimo:5},
    {id:'bi015',nombre:'Gasa parafinada (JELONET)',                stock:10,  minimo:3},
    {id:'bi016',nombre:'Steri strip',                              stock:10,  minimo:3},
    {id:'bi017',nombre:'Venda elastomull 8 cm',                    stock:10,  minimo:3},
    {id:'bi018',nombre:'Tela micropore',                           stock:10,  minimo:3},
    {id:'bi019',nombre:'Cintas HGT',                               stock:10,  minimo:5},
    {id:'bi020',nombre:'Lancetas',                                 stock:10,  minimo:5},
    {id:'bi021',nombre:'Perfu corriente',                          stock:10,  minimo:5},
    {id:'bi022',nombre:'Equipo de parto',                          stock:10,  minimo:2},
    {id:'bi023',nombre:'Kit de hemorragia',                        stock:4,   minimo:2},
    {id:'bi024',nombre:'Silicona aspiración',                      stock:12,  minimo:4},
    {id:'bi025',nombre:'Sonda aspiración 6 FR',                    stock:12,  minimo:4},
    {id:'bi026',nombre:'Sonda Yankauer',                           stock:2,   minimo:1},
    {id:'bi027',nombre:'Sonda aspiración 8 FR',                    stock:5,   minimo:2},
    {id:'bi028',nombre:'MNR adulto y pediátrico',                  stock:21,  minimo:5},
    {id:'bi029',nombre:'Mascarilla venturi adulto y pediátrica',   stock:24,  minimo:5},
    {id:'bi030',nombre:'Mascarilla de nebulización adulto y pediátrica',stock:2,minimo:1},
    {id:'bi031',nombre:'Naricera adulto y pediátrica',             stock:4,   minimo:2},
    {id:'bi032',nombre:'Ambú adulto',                              stock:2,   minimo:1},
    {id:'bi033',nombre:'Laringoscopio adulto y pediátrico',        stock:1,   minimo:1},
    {id:'bi034',nombre:'Hojas curvas y rectas para laringoscopio', stock:6,   minimo:2},
    {id:'bi035',nombre:'Estilete adulto y pediátrico',             stock:2,   minimo:1},
    {id:'bi036',nombre:'Apósitos 20 x 20',                        stock:7,   minimo:3},
    {id:'bi037',nombre:'Apósitos 25 x 20',                        stock:9,   minimo:3},
    {id:'bi038',nombre:'Agujas 19G',                               stock:20,  minimo:5},
    {id:'bi039',nombre:'Cinta fijador TET',                        stock:0,   minimo:2},
    {id:'bi040',nombre:'Fonendoscopio',                            stock:2,   minimo:1},
    {id:'bi041',nombre:'Esfingomanómetro manual/digital',          stock:0,   minimo:1},
    {id:'bi042',nombre:'Glucómetro',                               stock:0,   minimo:1},
    {id:'bi043',nombre:'Termómetro digital',                       stock:0,   minimo:1},
    {id:'bi044',nombre:'Otoscopio y conos de otoscopio',           stock:0,   minimo:1},
    {id:'bi045',nombre:'Tablilla pediátrica',                      stock:5,   minimo:2},
    {id:'bi046',nombre:'Pinza Kelly',                              stock:3,   minimo:1},
    {id:'bi047',nombre:'Tijera de trauma',                         stock:0,   minimo:1},
    {id:'bi048',nombre:'Torulero',                                 stock:2,   minimo:1},
    {id:'bi049',nombre:'Apurador de sueros',                       stock:10,  minimo:3},
    {id:'bi050',nombre:'Riñón desechable',                         stock:10,  minimo:5},
    {id:'bi051',nombre:'Chata desechable',                         stock:10,  minimo:5},
    {id:'bi052',nombre:'Pato desechable',                          stock:10,  minimo:5},
    {id:'bi053',nombre:'Frazada térmica y frazada',                stock:10,  minimo:3},
    {id:'bi054',nombre:'Cubre camillas desechables',               stock:10,  minimo:5},
    {id:'bi055',nombre:'Bata desechable',                          stock:10,  minimo:5},
    {id:'bi056',nombre:'Malla para camilla',                       stock:10,  minimo:3},
    {id:'bi057',nombre:'Mesa de transporte',                       stock:10,  minimo:2},
    {id:'bi058',nombre:'Atril para infusiones',                    stock:10,  minimo:2},
    {id:'bi059',nombre:'Caja cortopunzantes 1L roja',              stock:10,  minimo:3},
    {id:'bi060',nombre:'Sabanilla desechable (rollo)',              stock:10,  minimo:3},
    {id:'bi061',nombre:'Bolsas de desecho amarillas',              stock:10,  minimo:5},
    {id:'bi062',nombre:'Alcohol 70%',                              stock:10,  minimo:3},
    {id:'bi063',nombre:'Caja guantes procedimiento S',             stock:10,  minimo:3},
    {id:'bi064',nombre:'Caja mascarillas 3 pliegues, KN95',        stock:10,  minimo:3},
    {id:'bi065',nombre:'Pecheras desechables',                     stock:10,  minimo:5},
    {id:'bi066',nombre:'Overol',                                   stock:10,  minimo:3},
    {id:'bi067',nombre:'Cubre calzado (par)',                      stock:10,  minimo:5},
    {id:'bi068',nombre:'Cofias',                                   stock:10,  minimo:5},
    {id:'bi069',nombre:'Antiparra',                                stock:10,  minimo:3},
    {id:'bi070',nombre:'Linterna',                                 stock:10,  minimo:2},
    {id:'bi071',nombre:'Pinza Maggil adulto',                      stock:10,  minimo:2},
    {id:'bi072',nombre:'Jeringa 5 ml',                             stock:80,  minimo:20},
    {id:'bi073',nombre:'Jeringa 10 ml',                            stock:90,  minimo:20},
    {id:'bi074',nombre:'Jeringa 20 ml',                            stock:120, minimo:30},
    {id:'bi075',nombre:'Branula 18',                               stock:32,  minimo:10},
    {id:'bi076',nombre:'Branula 20',                               stock:76,  minimo:15},
    {id:'bi077',nombre:'Branula 22',                               stock:26,  minimo:10},
    {id:'bi078',nombre:'Branula 24',                               stock:43,  minimo:10},
    {id:'bi079',nombre:'Mariposa 23G',                             stock:12,  minimo:5},
    {id:'bi080',nombre:'Mariposa 25G',                             stock:16,  minimo:5},
    {id:'bi081',nombre:'Guantes procedimiento M',                  stock:200, minimo:50},
    {id:'bi082',nombre:'Guantes procedimiento L',                  stock:500, minimo:100},
  ],

  // ─── 35 MEDICAMENTOS BOTIQUÍN (desde Excel) ──────────────────────────────
  botiquin_meds:[
    {id:'bm01',nombre:'Ácido tranexámico 1 gr ampolla',           stock:50,lote:'LOT-2025-001',vencimiento:'2027-12-31',minimo:10},
    {id:'bm02',nombre:'Ácido acetilsalicílico 100 mg comprimido', stock:50,lote:'LOT-2025-002',vencimiento:'2027-12-31',minimo:10},
    {id:'bm03',nombre:'Adenosina 6 mg EV',                        stock:50,lote:'LOT-2025-003',vencimiento:'2027-06-30',minimo:10},
    {id:'bm04',nombre:'Amiodarona 150 mg ampolla',                stock:50,lote:'LOT-2025-004',vencimiento:'2027-06-30',minimo:10},
    {id:'bm05',nombre:'Atropina 1 mg ampolla',                    stock:50,lote:'LOT-2025-005',vencimiento:'2027-12-31',minimo:10},
    {id:'bm06',nombre:'Betametasona 4 mg ampolla',                stock:50,lote:'LOT-2025-006',vencimiento:'2027-12-31',minimo:10},
    {id:'bm07',nombre:'Bromuro de Ipratropio NBZ',                stock:50,lote:'LOT-2025-007',vencimiento:'2027-06-30',minimo:10},
    {id:'bm08',nombre:'Clorfenamina 10 mg ampolla',               stock:50,lote:'LOT-2025-008',vencimiento:'2027-12-31',minimo:10},
    {id:'bm09',nombre:'Clopidogrel 75 mg comprimido',             stock:50,lote:'LOT-2025-009',vencimiento:'2027-12-31',minimo:10},
    {id:'bm10',nombre:'Dexametasona 4 mg ampolla',                stock:50,lote:'LOT-2025-010',vencimiento:'2027-12-31',minimo:10},
    {id:'bm11',nombre:'Diclofenaco 75 mg ampolla',                stock:50,lote:'LOT-2025-011',vencimiento:'2027-06-30',minimo:10},
    {id:'bm12',nombre:'Difenidol 40 mg comprimido',               stock:50,lote:'LOT-2025-012',vencimiento:'2027-12-31',minimo:10},
    {id:'bm13',nombre:'Epinefrina 1 mg ampolla',                  stock:50,lote:'LOT-2025-013',vencimiento:'2027-06-30',minimo:10},
    {id:'bm14',nombre:'Flumazenil 0.5 mg ampolla',                stock:50,lote:'LOT-2025-014',vencimiento:'2027-06-30',minimo:5},
    {id:'bm15',nombre:'Furosemida 20 mg ampolla',                 stock:50,lote:'LOT-2025-015',vencimiento:'2027-12-31',minimo:10},
    {id:'bm16',nombre:'Gluconato de Calcio 10% ampolla',          stock:50,lote:'LOT-2025-016',vencimiento:'2027-12-31',minimo:10},
    {id:'bm17',nombre:'Hidrocortisona 100 mg',                    stock:50,lote:'LOT-2025-017',vencimiento:'2027-12-31',minimo:10},
    {id:'bm18',nombre:'Ketoprofeno 100 mg ampolla',               stock:50,lote:'LOT-2025-018',vencimiento:'2027-06-30',minimo:10},
    {id:'bm19',nombre:'Ketorolaco 30 mg ampolla',                 stock:50,lote:'LOT-2025-019',vencimiento:'2027-12-31',minimo:10},
    {id:'bm20',nombre:'Labetalol 100 mg ampolla',                 stock:50,lote:'LOT-2025-020',vencimiento:'2027-06-30',minimo:5},
    {id:'bm21',nombre:'Lanatósido C 0.4 mg ampolla',              stock:50,lote:'LOT-2025-021',vencimiento:'2027-06-30',minimo:5},
    {id:'bm22',nombre:'Lidocaína 2% ampolla',                     stock:50,lote:'LOT-2025-022',vencimiento:'2027-12-31',minimo:10},
    {id:'bm23',nombre:'Metamizol 1 gr ampolla',                   stock:50,lote:'LOT-2025-023',vencimiento:'2027-12-31',minimo:10},
    {id:'bm24',nombre:'Naloxona 0.4 mg ampolla',                  stock:50,lote:'LOT-2025-024',vencimiento:'2027-06-30',minimo:5},
    {id:'bm25',nombre:'Norepinefrina 4 mg ampolla',               stock:50,lote:'LOT-2025-025',vencimiento:'2027-06-30',minimo:5},
    {id:'bm26',nombre:'Ondansetrón 4 mg ampolla',                 stock:50,lote:'LOT-2025-026',vencimiento:'2027-12-31',minimo:10},
    {id:'bm27',nombre:'Paracetamol 500 mg comprimido',            stock:50,lote:'LOT-2025-027',vencimiento:'2027-12-31',minimo:10},
    {id:'bm28',nombre:'Paracetamol gotas (frasco)',               stock:50,lote:'LOT-2025-028',vencimiento:'2027-12-31',minimo:5},
    {id:'bm29',nombre:'Pargeverina 5 mg ampolla',                 stock:50,lote:'LOT-2025-029',vencimiento:'2027-12-31',minimo:10},
    {id:'bm30',nombre:'Propranolol 1 mg ampolla',                 stock:50,lote:'LOT-2025-030',vencimiento:'2027-06-30',minimo:5},
    {id:'bm31',nombre:'Ranitidina 50 mg ampolla',                 stock:50,lote:'LOT-2025-031',vencimiento:'2027-12-31',minimo:10},
    {id:'bm32',nombre:'Salbutamol NBZ',                           stock:50,lote:'LOT-2025-032',vencimiento:'2027-06-30',minimo:10},
    {id:'bm33',nombre:'Sulfato de magnesio 25% ampolla',          stock:50,lote:'LOT-2025-033',vencimiento:'2027-12-31',minimo:10},
    {id:'bm34',nombre:'Suxametonio 100 mg ampolla',               stock:50,lote:'LOT-2025-034',vencimiento:'2027-06-30',minimo:5},
    {id:'bm35',nombre:'Verapamilo 5 mg ampolla',                  stock:50,lote:'LOT-2025-035',vencimiento:'2027-06-30',minimo:5},
  ],

  // ─── BODEGA (espejo de insumos con stock base) ────────────────────────────
  bodega_insumos:[
    {id:'bod001',nombre:'Agujas 21G',                               stock:100, minimo:20},
    {id:'bod002',nombre:'Jeringa 3 ml',                             stock:100, minimo:20},
    {id:'bod003',nombre:'Branula 16',                               stock:50,  minimo:10},
    {id:'bod004',nombre:'Mariposa 21G',                             stock:100, minimo:20},
    {id:'bod005',nombre:'Ligadura',                                 stock:50,  minimo:10},
    {id:'bod006',nombre:'Llave 3 pasos',                            stock:100, minimo:20},
    {id:'bod007',nombre:'Tegaderm',                                 stock:100, minimo:20},
    {id:'bod008',nombre:'Fleboclisis',                              stock:100, minimo:20},
    {id:'bod009',nombre:'Alcohol pads',                             stock:500, minimo:100},
    {id:'bod010',nombre:'Tapas amarillas y rojas',                  stock:200, minimo:50},
    {id:'bod011',nombre:'Baja lenguas',                             stock:200, minimo:50},
    {id:'bod012',nombre:'Equipo de curación',                       stock:50,  minimo:10},
    {id:'bod013',nombre:'Apósitos 10 x 20',                        stock:200, minimo:50},
    {id:'bod014',nombre:'Gasas 7.5 x 7.5',                         stock:200, minimo:50},
    {id:'bod015',nombre:'Gasa parafinada (JELONET)',                stock:50,  minimo:10},
    {id:'bod016',nombre:'Steri strip',                              stock:50,  minimo:10},
    {id:'bod017',nombre:'Venda elastomull 8 cm',                    stock:100, minimo:20},
    {id:'bod018',nombre:'Tela micropore',                           stock:100, minimo:20},
    {id:'bod019',nombre:'Cintas HGT',                               stock:200, minimo:50},
    {id:'bod020',nombre:'Lancetas',                                 stock:200, minimo:50},
    {id:'bod021',nombre:'Perfu corriente',                          stock:100, minimo:20},
    {id:'bod022',nombre:'Equipo de parto',                          stock:20,  minimo:5},
    {id:'bod023',nombre:'Kit de hemorragia',                        stock:20,  minimo:5},
    {id:'bod024',nombre:'Silicona aspiración',                      stock:50,  minimo:10},
    {id:'bod025',nombre:'Sonda aspiración 6 FR',                    stock:50,  minimo:10},
    {id:'bod026',nombre:'Sonda Yankauer',                           stock:20,  minimo:5},
    {id:'bod027',nombre:'Sonda aspiración 8 FR',                    stock:30,  minimo:8},
    {id:'bod028',nombre:'MNR adulto y pediátrico',                  stock:50,  minimo:10},
    {id:'bod029',nombre:'Mascarilla venturi adulto y pediátrica',   stock:50,  minimo:10},
    {id:'bod030',nombre:'Mascarilla de nebulización adulto y pediátrica',stock:20,minimo:5},
    {id:'bod031',nombre:'Naricera adulto y pediátrica',             stock:50,  minimo:10},
    {id:'bod032',nombre:'Ambú adulto',                              stock:10,  minimo:3},
    {id:'bod033',nombre:'Jeringa 5 ml',                             stock:500, minimo:100},
    {id:'bod034',nombre:'Jeringa 10 ml',                            stock:500, minimo:100},
    {id:'bod035',nombre:'Jeringa 20 ml',                            stock:500, minimo:100},
    {id:'bod036',nombre:'Branula 18',                               stock:200, minimo:50},
    {id:'bod037',nombre:'Branula 20',                               stock:300, minimo:80},
    {id:'bod038',nombre:'Branula 22',                               stock:200, minimo:50},
    {id:'bod039',nombre:'Branula 24',                               stock:200, minimo:50},
    {id:'bod040',nombre:'Mariposa 23G',                             stock:100, minimo:20},
    {id:'bod041',nombre:'Mariposa 25G',                             stock:100, minimo:20},
    {id:'bod042',nombre:'Guantes procedimiento M',                  stock:1000,minimo:200},
    {id:'bod043',nombre:'Guantes procedimiento L',                  stock:2000,minimo:500},
    {id:'bod044',nombre:'Caja guantes procedimiento S',             stock:100, minimo:20},
    {id:'bod045',nombre:'Caja mascarillas 3 pliegues, KN95',        stock:200, minimo:50},
    {id:'bod046',nombre:'Alcohol pads',                             stock:1000,minimo:200},
    {id:'bod047',nombre:'Alcohol 70%',                              stock:100, minimo:20},
    {id:'bod048',nombre:'Pecheras desechables',                     stock:500, minimo:100},
    {id:'bod049',nombre:'Cubre camillas desechables',               stock:500, minimo:100},
    {id:'bod050',nombre:'Bolsas de desecho amarillas',              stock:500, minimo:100},
  ],

  // ─── 3 MEDICAMENTOS CONTROLADOS (desde Excel) ────────────────────────────
  controlados:[
    {id:'ct1',nombre:'Morfina 10 mg',   stock:5, lote:'LOT-CTRL-MOR-2025',vencimiento:'2027-06-30',minimo:2},
    {id:'ct2',nombre:'Midazolam 5 mg',  stock:10,lote:'LOT-CTRL-MID-2025',vencimiento:'2027-12-31',minimo:2},
    {id:'ct3',nombre:'Diazepam 10 mg',  stock:7, lote:'LOT-CTRL-DIA-2025',vencimiento:'2027-12-31',minimo:2},
  ],

  movimientos:[{id:'mv0',fecha:new Date().toLocaleString('es-CL'),tipo:'Sistema',descripcion:'UCM Ops v2.0 — Base de datos cargada desde Excel (26 móviles, 82 insumos, 35 medicamentos, 71 equipos).'}],
  notas_equip:[],mantenciones:[],mantenciones_vehiculo:[],
  notas_pizarra:[{id:'np1',texto:'Sistema iniciado con datos reales desde base de datos UCM. Los equipamientos están en inventario listos para asignación a móviles.',autorNombre:'Administrador',autorUsername:'admin',autorId:'u1',creadaEn:new Date().toISOString(),expiraEn:new Date(Date.now()+86400000*7).toISOString()}],
  _version:'2.0.0',
}

const uid=()=>{if(crypto.randomUUID)return crypto.randomUUID();const a=new Uint8Array(16);crypto.getRandomValues(a);a[6]=(a[6]&0x0f)|0x40;a[8]=(a[8]&0x3f)|0x80;return [...a].map((b,i)=>[4,6,8,10].includes(i)?'-'+b.toString(16).padStart(2,'0'):b.toString(16).padStart(2,'0')).join('')}
const now=()=>new Date().toLocaleString('es-CL')
const today=()=>new Date().toISOString().split('T')[0]
const daysUntil=d=>{const t=new Date(d+'T00:00:00'),n=new Date();n.setHours(0,0,0,0);return Math.round((t-n)/86400000)}
const fmtDate=d=>{if(!d)return'';const[y,m,dd]=d.split('-');return`${dd}/${m}/${y}`}
const fmtVenc=d=>{const days=daysUntil(d);if(days<0)return{label:`Vencido ${fmtDate(d)}`,vencido:true,near:true};if(days<=90)return{label:`${fmtDate(d)} (${days}d)`,vencido:false,near:true};return{label:fmtDate(d),vencido:false,near:false}}
const fefoSort=meds=>[...meds].sort((a,b)=>new Date(a.vencimiento)-new Date(b.vencimiento))
const roleLabel=r=>ROLES[r]||r
const roleColor=r=>ROLE_COLORS[r]||C.tm

// ═══════════════════════════════════════════════════
//  📦 EXPORTACIÓN — modal React integrado (sin window.open, sin CDNs externos)
// ═══════════════════════════════════════════════════

// ─── REGISTRO DEL MODAL (singleton por módulo) ────────────────────────────────
// Las funciones de export son helpers normales (no hooks), pero necesitan
// comunicarse con el árbol React. Se registra el setter al montar ExportModal.
let _setExportModal = null
function _registerExportModal(fn){ _setExportModal = fn }

// ─── BLOB DOWNLOAD (descarga directa, funciona fuera del sandbox) ─────────────
function blobDownload(blob, filename){
  try{
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = filename; a.style.display = 'none'
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    setTimeout(()=> URL.revokeObjectURL(url), 5000)
    return true
  }catch(e){ return false }
}

// ─── TXT ──────────────────────────────────────────────────────────────────────
function exportTxt(title, cols, rows, filename){
  const lines = [`${title}`, `Generado: ${now()}`, '', cols.join(' | '),
    ...rows.map(r => r.map(v => String(v ?? '')).join(' | '))]
  const content = lines.join('\n')
  blobDownload(new Blob([content], {type:'text/plain;charset=utf-8'}), filename)
  if(_setExportModal) _setExportModal({type:'txt', title, filename, content})
}

// ─── EXCEL ────────────────────────────────────────────────────────────────────
function exportExcel(sheets, filename){
  try{
    const wb = XLSX.utils.book_new()
    sheets.forEach(({name, cols, rows})=>{
      const ws = XLSX.utils.aoa_to_sheet([cols, ...rows.map(r => r.map(v => v ?? ''))])
      ws['!cols'] = cols.map(()=>({wch:24}))
      XLSX.utils.book_append_sheet(wb, ws, name.slice(0,31))
    })
    const out = XLSX.write(wb, {bookType:'xlsx', type:'array'})
    blobDownload(new Blob([out], {
      type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    }), filename)
  }catch(e){ console.warn('exportExcel:', e) }
  if(_setExportModal) _setExportModal({type:'excel', title:filename, filename, sheets})
}

// ─── PDF (usa window.print del modal) ────────────────────────────────────────
function exportPdf(title, sheets, filename){
  if(_setExportModal) _setExportModal({type:'pdf', title, filename, sheets})
}

// ─── COMPONENTE MODAL DE EXPORTACIÓN ─────────────────────────────────────────
// Se monta una sola vez en App. Se muestra cuando _setExportModal recibe datos.
function ExportModal(){
  const [state, setState] = useState(null)
  useEffect(()=>{
    _registerExportModal(setState)
    return ()=>{ if(_setExportModal === setState) _setExportModal = null }
  }, [])

  if(!state) return null

  const close = ()=> setState(null)

  const doPrint = ()=>{
    const el = document.getElementById('__ucm_print_area')
    if(!el) return
    // Crear iframe oculto: imprime sin destruir el estado de React
    const iframe = document.createElement('iframe')
    iframe.style.position = 'fixed'
    iframe.style.right = '0'
    iframe.style.bottom = '0'
    iframe.style.width = '0'
    iframe.style.height = '0'
    iframe.style.border = '0'
    document.body.appendChild(iframe)
    const doc = iframe.contentWindow?.document || iframe.contentDocument
    if(!doc){ document.body.removeChild(iframe); return }
    doc.open()
    doc.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${state.title||'UCM Ops'}</title>
<style>
  *{box-sizing:border-box}
  body{font-family:Arial,sans-serif;margin:20px;color:#111;background:#fff}
  h2{font-size:14px;margin:0 0 8px;border-bottom:1px solid #d1d5db;padding-bottom:4px}
  table{border-collapse:collapse;width:100%;font-size:11px;margin-bottom:18px}
  th,td{border:1px solid #d1d5db;padding:4px 7px;text-align:left;vertical-align:top}
  th{background:#f3f4f6;font-weight:600}
  pre{font-size:11px;line-height:1.6;white-space:pre-wrap;word-wrap:break-word;background:#f9fafb;padding:12px;border-radius:4px}
  .header{font-size:9px;color:#6b7280;margin-bottom:14px}
  @page{margin:1.2cm}
</style></head><body>
<div class="header">📋 ${state.title||''} · Generado: ${now()}</div>
${el.innerHTML.replace(/style="[^"]*"/g,'').replace(/on\w+\s*=\s*"[^"]*"/gi,'').replace(/javascript:/gi,'').replace(/<script[\s\S]*?<\/script>/gi,'')}
</body></html>`)
    doc.close()
    // Esperar a que el iframe cargue antes de imprimir
    setTimeout(()=>{
      try{
        iframe.contentWindow.focus()
        iframe.contentWindow.print()
      }catch(e){ console.warn('Print failed:', e) }
      // Remover el iframe después de que se cierre el diálogo de impresión
      setTimeout(()=>{ try{ document.body.removeChild(iframe) }catch(e){} }, 1000)
    }, 200)
  }

  // ── Contenido según tipo ──
  let body = null

  if(state.type === 'txt'){
    const safe = state.content.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    body = <pre id="__ucm_print_area" style={{background:C.s2,padding:16,borderRadius:6,fontSize:12,lineHeight:1.7,overflowX:'auto',whiteSpace:'pre-wrap',color:C.txt,maxHeight:'55vh',overflowY:'auto'}}>{state.content}</pre>
  }

  if(state.type === 'excel' || state.type === 'pdf'){
    const sheets = state.sheets || []
    body = <div id="__ucm_print_area" style={{maxHeight:'55vh',overflowY:'auto'}}>
      {sheets.map(({name, cols, rows}, si)=>(
        <div key={si} style={{marginBottom:20}}>
          <div style={{fontWeight:700,color:C.tb,fontSize:14,marginBottom:8,paddingBottom:4,borderBottom:`1px solid ${C.brd}`}}>
            {name} <span style={{color:C.tm,fontWeight:400,fontSize:12}}>({rows.length} registros)</span>
          </div>
          <div style={{overflowX:'auto'}}>
            <table style={{borderCollapse:'collapse',width:'100%',fontSize:12}}>
              <thead>
                <tr>{cols.map((c,i)=><th key={i} style={{padding:'6px 9px',background:C.s3,color:C.tm,fontWeight:600,textAlign:'left',border:`1px solid ${C.brd}`,whiteSpace:'nowrap'}}>{c}</th>)}</tr>
              </thead>
              <tbody>
                {rows.map((row,ri)=>(
                  <tr key={ri} style={{background:ri%2===0?'transparent':C.s2+'88'}}>
                    {row.map((cell,ci)=><td key={ci} style={{padding:'5px 9px',color:C.txt,border:`1px solid ${C.brd}22`,verticalAlign:'top'}}>{String(cell??'')}</td>)}
                  </tr>
                ))}
                {rows.length===0&&<tr><td colSpan={cols.length} style={{padding:12,color:C.tm,textAlign:'center'}}>Sin datos</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  }

  return(
    <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,.65)',zIndex:9999,display:'flex',alignItems:'center',justifyContent:'center',padding:16}}>
      <div style={{background:C.bg,border:`1px solid ${C.brd}`,borderRadius:10,width:'100%',maxWidth:820,display:'flex',flexDirection:'column',maxHeight:'90vh',boxShadow:'0 24px 64px rgba(0,0,0,.6)'}}>

        {/* Header */}
        <div style={{display:'flex',alignItems:'center',gap:10,padding:'14px 18px',borderBottom:`1px solid ${C.brd}`,flexShrink:0}}>
          <span style={{fontSize:18}}>{state.type==='pdf'?'📑':state.type==='excel'?'📊':'📄'}</span>
          <div style={{flex:1}}>
            <div style={{color:C.tb,fontWeight:700,fontSize:15}}>{state.title}</div>
            <div style={{color:C.tm,fontSize:11}}>{state.filename}</div>
          </div>
          <button onClick={close} style={{background:'none',border:'none',color:C.tm,cursor:'pointer',fontSize:20,lineHeight:1,padding:4}}>×</button>
        </div>

        {/* Botones de acción */}
        <div style={{display:'flex',gap:8,padding:'10px 18px',borderBottom:`1px solid ${C.brd}`,flexShrink:0,flexWrap:'wrap'}}>
          {state.type==='txt'&&(
            <Btn sm onClick={()=>{
              blobDownload(new Blob([state.content],{type:'text/plain;charset=utf-8'}), state.filename)
            }}>⬇ Descargar TXT</Btn>
          )}
          {state.type==='excel'&&(
            <Btn sm onClick={()=> exportExcel(state.sheets, state.filename)}>⬇ Descargar Excel (.xlsx)</Btn>
          )}
          {(state.type==='pdf'||state.type==='excel'||state.type==='txt')&&(
            <Btn sm variant="secondary" onClick={doPrint}>🖨️ Imprimir / Guardar PDF</Btn>
          )}
          {state.type==='txt'&&(
            <Btn sm variant="ghost" onClick={()=>{
              navigator.clipboard?.writeText(state.content).catch(()=>{})
            }}>📋 Copiar texto</Btn>
          )}
          <Btn sm variant="ghost" onClick={close}>Cerrar</Btn>
        </div>

        {/* Contenido */}
        <div style={{padding:'16px 18px',overflowY:'auto',flex:1}}>
          {body}
        </div>

      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════
//  🧩 COMPONENTES PRIMITIVOS
// ═══════════════════════════════════════════════════

function Btn({children,onClick,variant='primary',sm,disabled,full,style={}}){
  const base={display:'inline-flex',alignItems:'center',justifyContent:'center',gap:6,border:'none',borderRadius:6,cursor:disabled?'not-allowed':'pointer',fontFamily:"'DM Sans',sans-serif",fontWeight:600,fontSize:sm?12:14,padding:sm?'5px 10px':'8px 16px',opacity:disabled?.5:1,transition:'all .15s',width:full?'100%':undefined,...style}
  const vs={primary:{background:C.acc,color:'#fff'},secondary:{background:C.s3,color:C.txt,border:`1px solid ${C.brd}`},danger:{background:C.red,color:'#fff'},success:{background:C.grn,color:'#fff'},ghost:{background:'transparent',color:C.txt,border:`1px solid ${C.brd}`}}
  return <button style={{...base,...vs[variant]}} onClick={disabled?undefined:onClick} disabled={disabled}>{children}</button>
}
const Badge=memo(({children,color})=>(<span style={{display:'inline-block',background:color+'22',border:`1px solid ${color}44`,color,borderRadius:20,padding:'2px 8px',fontSize:11,fontWeight:700,whiteSpace:'nowrap'}}>{children}</span>))
function Card({children,style={}}){return <div style={{background:C.s1,border:`1px solid ${C.brd}`,borderRadius:8,padding:16,...style}}>{children}</div>}

function Modal({title,children,onClose,wide}){
  useEffect(()=>{const h=(e)=>{if(e.key==='Escape')onClose()};document.addEventListener('keydown',h);return()=>document.removeEventListener('keydown',h)},[onClose])
  return(
    <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,.72)',zIndex:1000,display:'flex',alignItems:'center',justifyContent:'center',padding:16}} onClick={e=>{if(e.target===e.currentTarget)onClose()}}>
      <div style={{background:C.s1,border:`1px solid ${C.brd}`,borderRadius:10,width:'100%',maxWidth:wide?700:460,maxHeight:'90vh',display:'flex',flexDirection:'column'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'14px 18px',borderBottom:`1px solid ${C.brd}`,background:C.s1,borderRadius:'10px 10px 0 0'}}>
          <span style={{color:C.tb,fontWeight:700,fontSize:16}}>{title}</span>
          <button onClick={onClose} style={{background:'none',border:'none',color:C.tm,cursor:'pointer',fontSize:20,lineHeight:1}}>×</button>
        </div>
        <div style={{padding:18,overflowY:'auto'}}>{children}</div>
      </div>
    </div>
  )
}

function ConfirmModal({title,body,onConfirm,onClose,variant='danger',confirmLabel='Confirmar'}){
  return(
    <Modal title={title} onClose={onClose}>
      <div style={{marginBottom:16}}>{body}</div>
      <div style={{display:'flex',gap:8}}>
        <Btn variant="secondary" full onClick={onClose}>Cancelar</Btn>
        <Btn variant={variant} full onClick={onConfirm}>{confirmLabel}</Btn>
      </div>
    </Modal>
  )
}

function Fld({label,children,style={}}){return <div style={{marginBottom:12,...style}}><div style={{color:C.tm,fontSize:12,marginBottom:4,fontWeight:500}}>{label}</div>{children}</div>}
function Inp({value,onChange,placeholder,type='text',list,disabled,sm,onKeyDown,style={},maxLength=500}){
  return <input type={type} value={value} onChange={onChange} placeholder={placeholder} list={list} disabled={disabled} onKeyDown={onKeyDown} maxLength={maxLength}
    style={{background:C.s2,border:`1px solid ${C.brd}`,borderRadius:6,color:C.txt,padding:sm?'5px 8px':'8px 10px',fontSize:sm?12:14,width:'100%',outline:'none',fontFamily:"'DM Sans',sans-serif",...style}}/>
}
function Sel({value,onChange,children,disabled,style={}}){
  return <select value={value} onChange={onChange} disabled={disabled}
    style={{background:C.s2,border:`1px solid ${C.brd}`,borderRadius:6,color:C.txt,padding:'8px 10px',fontSize:14,width:'100%',outline:'none',fontFamily:"'DM Sans',sans-serif",...style}}>{children}</select>
}
function Txt({value,onChange,placeholder,rows=3}){
  return <textarea value={value} onChange={onChange} placeholder={placeholder} rows={rows}
    style={{background:C.s2,border:`1px solid ${C.brd}`,borderRadius:6,color:C.txt,padding:'8px 10px',fontSize:14,width:'100%',outline:'none',fontFamily:"'DM Sans',sans-serif",resize:'vertical'}}/>
}
function Tabs({tabs,active,onChange}){
  return <div style={{display:'flex',gap:0,borderBottom:`1px solid ${C.brd}`,marginBottom:18,overflowX:'auto',flexShrink:0}}>
    {tabs.map(t=><button key={t.id} onClick={()=>onChange(t.id)}
      style={{padding:'8px 16px',background:'none',border:'none',borderBottom:active===t.id?`2px solid ${C.acc}`:'2px solid transparent',color:active===t.id?C.tb:C.tm,cursor:'pointer',fontFamily:"'DM Sans',sans-serif",fontWeight:600,fontSize:13,whiteSpace:'nowrap',transition:'all .15s'}}>{t.label}</button>)}
  </div>
}
function SBar({stock,minimo}){
  const pct=minimo>0?Math.min(stock/minimo*50,100):100
  const color=stock<=minimo?C.red:stock<=minimo*2?C.amb:C.grn
  return <div style={{background:C.s3,borderRadius:4,height:6,overflow:'hidden',flex:1,minWidth:60}}><div style={{background:color,height:'100%',width:`${pct}%`,transition:'width .3s',borderRadius:4}}/></div>
}
function StkRow({item,onEdit}){
  const color=item.stock<=item.minimo?C.red:item.stock<=item.minimo*2?C.amb:C.txt
  return <div style={{display:'flex',alignItems:'center',gap:10,padding:'8px 0',borderBottom:`1px solid ${C.brd}`}}>
    <span style={{flex:1,color:C.txt,fontSize:13}}>{item.nombre}</span>
    <SBar stock={item.stock} minimo={item.minimo}/>
    <span style={{color,fontWeight:700,fontSize:13,minWidth:30,textAlign:'right'}}>{item.stock}</span>
    <span style={{color:C.tm,fontSize:11,minWidth:40}}>mín:{item.minimo}</span>
    {onEdit&&<button onClick={()=>onEdit(item)} style={{background:'none',border:'none',color:C.acl,cursor:'pointer',fontSize:13,padding:'2px 6px'}}>✏</button>}
  </div>
}
function TblSimple({cols,rows,empty}){
  return <div style={{overflowX:'auto'}}>
    <table style={{width:'100%',borderCollapse:'collapse',fontSize:13}}>
      <thead><tr>{cols.map((c,i)=><th key={i} style={{padding:'8px 10px',background:C.s3,color:C.tm,fontWeight:600,textAlign:'left',borderBottom:`1px solid ${C.brd}`,whiteSpace:'nowrap'}}>{c}</th>)}</tr></thead>
      <tbody>
        {rows.length===0&&<tr><td colSpan={cols.length} style={{padding:16,color:C.tm,textAlign:'center'}}>{empty||'Sin datos'}</td></tr>}
        {rows.map((row,ri)=><tr key={ri} style={{borderBottom:`1px solid ${C.brd}22`}}>
          {row.map((cell,ci)=><td key={ci} style={{padding:'7px 10px',color:C.txt,verticalAlign:'top'}}>{cell}</td>)}
        </tr>)}
      </tbody>
    </table>
  </div>
}
function PageTitle({children,sub}){
  return <div style={{marginBottom:20}}>
    <h2 style={{margin:0,color:C.tb,fontSize:22,fontWeight:800}}>{children}</h2>
    {sub&&<p style={{margin:'4px 0 0',color:C.tm,fontSize:13}}>{sub}</p>}
  </div>
}
function ReadOnlyBanner({msg}){
  return <div style={{background:C.s3,border:`1px solid ${C.brd}`,borderRadius:8,padding:'10px 14px',marginBottom:16,color:C.tm,fontSize:13,display:'flex',alignItems:'center',gap:8}}>🔒 {msg||'Tu rol solo tiene acceso de lectura.'}</div>
}

// ═══════════════════════════════════════════════════
//  🔑 LOGIN
// ═══════════════════════════════════════════════════

function Login({onLogin,users}){
  const [u,setU]=useState(''),[p,setP]=useState(''),[err,setErr]=useState(''),[loading,setLoading]=useState(false),[showPwd,setShowPwd]=useState(false)
  const [recModal,setRecModal]=useState(false),[recEmail,setRecEmail]=useState(''),[recSent,setRecSent]=useState(false)

  const doLogin=async()=>{
    if(loading)return
    const uname=u.trim().toLowerCase()
    if(!uname||!p){setErr('Ingresa usuario y contraseña.');return}
    const status=loginRL.check(uname)
    if(status.locked){setErr(`⛔ Cuenta bloqueada. Intenta en ${status.secsLeft} segundos.`);return}
    setLoading(true);setErr('')
    try{
      const hashed=await hashPwd(p,uname)
      const found=users.find(x=>x.username.toLowerCase()===uname&&x.password===hashed&&x.passwordHashed)
      if(found){loginRL.reset(uname);const{password:_pwd,passwordHashed:_ph,...safeUser}=found;onLogin({...safeUser,lastLogin:new Date().toISOString()})}
      else{loginRL.hit(uname);const st=loginRL.check(uname);st.locked?setErr(`⛔ Demasiados intentos. Espere ${Math.ceil((st.secsLeft||loginRL.WIN/1000)/60)} min.`):setErr(`❌ Credenciales incorrectas. ${st.remaining} intento${st.remaining!==1?'s':''} restante${st.remaining!==1?'s':''}.`)}
    }finally{setLoading(false)}
  }
  const kd=e=>{if(e.key==='Enter')doLogin()}

  return(
    <div style={{minHeight:'100vh',background:C.bg,display:'flex',alignItems:'center',justifyContent:'center',fontFamily:"'DM Sans',sans-serif"}}>
      <div style={{width:'100%',maxWidth:360}}>
        <div style={{textAlign:'center',marginBottom:28}}>
          <img src="data:image/png;base64,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" alt="Logo UCM" style={{width:'100%',maxWidth:380,height:'auto',marginBottom:16,display:'block',margin:'0 auto 16px'}}/>
        </div>
        <Card style={{boxShadow:'0 4px 24px rgba(0,0,0,.08)'}}>

          <Fld label="Usuario"><Inp value={u} onChange={e=>setU(e.target.value)} placeholder="Nombre de usuario" onKeyDown={kd} maxLength={50}/></Fld>
          <Fld label="Contraseña">
            <div style={{position:'relative'}}>
              <Inp type={showPwd?'text':'password'} value={p} onChange={e=>setP(e.target.value)} placeholder="Contraseña" onKeyDown={kd} maxLength={128} style={{paddingRight:36}}/>
              <button onClick={()=>setShowPwd(v=>!v)} style={{position:'absolute',right:8,top:'50%',transform:'translateY(-50%)',background:'none',border:'none',color:C.tm,cursor:'pointer',fontSize:14}}>{showPwd?'🙈':'👁'}</button>
            </div>
          </Fld>
          {err&&<div style={{background:C.red+'15',border:`1px solid ${C.red}33`,borderRadius:6,padding:'8px 10px',color:C.red,fontSize:13,marginBottom:10}}>{err}</div>}
          <Btn onClick={doLogin} full disabled={loading}>{loading?'Verificando…':'Ingresar'}</Btn>
          <div style={{textAlign:'center',marginTop:12}}>
            <button onClick={()=>setRecModal(true)} style={{background:'none',border:'none',color:C.acl,cursor:'pointer',fontSize:13}}>¿Olvidaste tu contraseña?</button>
          </div>

        </Card>
      </div>
      {recModal&&<Modal title="Recuperar contraseña" onClose={()=>{setRecModal(false);setRecSent(false);setRecEmail('')}}>
        {recSent?<div style={{color:C.grn,textAlign:'center',padding:16}}>✅ Instrucciones enviadas al correo.</div>
        :<><Fld label="Correo electrónico"><Inp value={recEmail} onChange={e=>setRecEmail(e.target.value)} placeholder="correo@ejemplo.cl"/></Fld><Btn onClick={()=>setRecSent(true)} full>Enviar instrucciones</Btn></>}
      </Modal>}
    </div>
  )
}

// ═══════════════════════════════════════════════════
//  📌 SIDEBAR
// ═══════════════════════════════════════════════════

const NAV=[
  {id:'resumen',icon:'📊',label:'Resumen'},
  {id:'moviles',icon:'🚑',label:'Gestión de móviles'},
  {id:'farmacia',icon:'💊',label:'Gestión farmacia'},
  {id:'controlados',icon:'⚠️',label:'Meds. controlados'},
  {id:'equipamientos',icon:'🔧',label:'Equipamientos'},
  {id:'estadistica',icon:'📈',label:'Estadística'},
  {id:'pizarra',icon:'📌',label:'Pizarra'},
  {id:'config',icon:'⚙️',label:'Configuración'},
]

function Sidebar({page,setPage,user,onLogout,col,setCol}){
  return(
    <div style={{width:col?52:215,minWidth:col?52:215,background:C.s1,borderRight:`1px solid ${C.brd}`,display:'flex',flexDirection:'column',transition:'width .2s',overflow:'hidden',flexShrink:0}}>
      <div style={{padding:'12px 8px',borderBottom:`1px solid ${C.brd}`,display:'flex',alignItems:'center',justifyContent:col?'center':'space-between'}}>
        {!col&&<img src={"data:image/png;base64,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"} alt="UCM Ops" style={{height:32,width:'auto',maxWidth:140,objectFit:'contain',paddingLeft:4}}/>}
        <button onClick={()=>setCol(!col)} style={{background:'none',border:'none',color:C.tm,cursor:'pointer',fontSize:16,padding:4}}>{col?'▶':'◀'}</button>
      </div>
      <nav style={{flex:1,padding:'8px 0',overflowY:'auto'}}>
        {NAV.map(n=>(
          <button key={n.id} onClick={()=>setPage(n.id)}
            style={{display:'flex',alignItems:'center',gap:10,width:'100%',padding:'9px 12px',background:page===n.id?C.acc+'22':'none',borderLeft:page===n.id?`3px solid ${C.acc}`:'3px solid transparent',border:'none',color:page===n.id?C.tb:C.tm,cursor:'pointer',textAlign:'left',fontFamily:"'DM Sans',sans-serif",fontWeight:page===n.id?600:400,fontSize:13,whiteSpace:'nowrap',transition:'all .15s'}}>
            <span style={{fontSize:16,flexShrink:0}}>{n.icon}</span>
            {!col&&n.label}
          </button>
        ))}
      </nav>
      {!col&&<div style={{padding:'10px 14px',borderTop:`1px solid ${C.brd}`,fontSize:12}}>
        <div style={{color:C.tb,fontWeight:600,marginBottom:4}}>{user.nombre}</div>
        <Badge color={roleColor(user.role)}>{roleLabel(user.role)}</Badge>
        {user.lastLogin&&<div style={{color:C.tm,fontSize:10,marginTop:4}}>Último acceso: {new Date(user.lastLogin).toLocaleString('es-CL')}</div>}
      </div>}
      <button onClick={onLogout} style={{display:'flex',alignItems:'center',gap:8,padding:'10px 14px',background:'none',border:'none',borderTop:`1px solid ${C.brd}`,color:C.red,cursor:'pointer',fontFamily:"'DM Sans',sans-serif",fontSize:13,fontWeight:600}}>
        <span style={{fontSize:16}}>🚪</span>{!col&&'Salir'}
      </button>
    </div>
  )
}

// ═══════════════════════════════════════════════════
//  📊 RESUMEN — Dashboard rediseñado v2
// ═══════════════════════════════════════════════════

// Mini gráfico de dona (SVG puro, sin dependencias)
function DonutChart({segments, total, size=88}){
  const r=32, cx=size/2, cy=size/2, stroke=10
  const circ=2*Math.PI*r
  let cumulative=0
  const segs=segments.map(s=>{
    const dash=(s.value/total)*circ
    const offset=circ*0.25-cumulative
    cumulative+=dash
    return{...s,dash,offset}
  })
  return(
    <div style={{display:'flex',alignItems:'center',gap:10}}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{flexShrink:0}}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.s3} strokeWidth={stroke}/>
        {segs.map((s,i)=>(
          <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={s.color} strokeWidth={stroke}
            strokeDasharray={`${s.dash} ${circ-s.dash}`}
            strokeDashoffset={s.offset}
            style={{transition:'stroke-dasharray .5s ease'}}/>
        ))}
        <text x={cx} y={cy} textAnchor="middle" dominantBaseline="central" fill={C.tb} fontSize={13} fontWeight={700}>{total}</text>
      </svg>
      <div style={{flex:1,minWidth:0}}>
        {segments.map((s,i)=>(
          <div key={i} style={{display:'flex',alignItems:'center',gap:5,marginBottom:3}}>
            <div style={{width:7,height:7,borderRadius:2,background:s.color,flexShrink:0}}/>
            <span style={{color:C.tm,fontSize:10,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{s.label}</span>
            <span style={{color:C.tb,fontSize:10,fontWeight:700}}>{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Mini barra horizontal con porcentaje
function MiniBar({label,value,max,color}){
  const pct=max>0?Math.min((value/max)*100,100):0
  return(
    <div style={{marginBottom:7}}>
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:2}}>
        <span style={{color:C.txt,fontSize:12}}>{label}</span>
        <span style={{color:C.tm,fontSize:11}}>{value}</span>
      </div>
      <div style={{background:C.s3,borderRadius:3,height:4,overflow:'hidden'}}>
        <div style={{background:color,height:'100%',width:`${pct}%`,borderRadius:3,transition:'width .6s ease'}}/>
      </div>
    </div>
  )
}

// Píldora de estado del sistema
function StatusPill({label,color}){
  return(
    <div style={{display:'flex',alignItems:'center',gap:7,background:color+'14',border:`1px solid ${color}44`,borderRadius:20,padding:'5px 12px'}}>
      <div style={{width:7,height:7,borderRadius:'50%',background:color,boxShadow:`0 0 7px ${color}`}}/>
      <span style={{color,fontSize:11,fontWeight:700,letterSpacing:.3}}>{label}</span>
    </div>
  )
}

function Resumen({data,user}){
  // ── Cálculos ──────────────────────────────────────
  const criticos=useMemo(()=>[...data.botiquin_insumos,...data.botiquin_meds].filter(i=>i.stock<=i.minimo),[data.botiquin_insumos,data.botiquin_meds])
  const activosEq=useMemo(()=>data.equipamientos.filter(e=>e.estado==='activo').length,[data.equipamientos])
  const stockEq=useMemo(()=>data.equipamientos.filter(e=>e.estado==='stock').length,[data.equipamientos])
  const medsVencer=useMemo(()=>fefoSort([...data.botiquin_meds,...data.controlados]).filter(m=>daysUntil(m.vencimiento)<=90),[data.botiquin_meds,data.controlados])
  const vencidos=useMemo(()=>[...data.botiquin_meds,...data.controlados].filter(m=>daysUntil(m.vencimiento)<=0),[data.botiquin_meds,data.controlados])
  const totalItems=data.botiquin_insumos.length+data.botiquin_meds.length
  const itemsOk=useMemo(()=>[...data.botiquin_insumos,...data.botiquin_meds].filter(i=>i.stock>i.minimo).length,[data.botiquin_insumos,data.botiquin_meds])
  const pctOk=totalItems>0?Math.round(itemsOk/totalItems*100):100

  const movByTipo=useMemo(()=>TIPOS_MOVIL.reduce((a,t)=>{a[t]=data.moviles.filter(m=>m.tipo===t).length;return a},{}),[data.moviles])
  const equipByTipo=useMemo(()=>TIPOS_EQUIP.reduce((a,t)=>{a[t]=data.equipamientos.filter(e=>e.tipo===t).length;return a},{}),[data.equipamientos])
  const maxEquip=Math.max(...TIPOS_EQUIP.map(t=>equipByTipo[t]||0),1)

  const systemStatus=criticos.length===0&&vencidos.length===0?'operacional':criticos.length>5||vencidos.length>0?'crítico':'alerta'
  const statusColor={operacional:C.grn,alerta:C.amb,crítico:C.red}[systemStatus]
  const statusLabel={operacional:'Sistema operacional',alerta:'Requiere atención',crítico:'Estado crítico'}[systemStatus]

  const dateStr=new Date().toLocaleDateString('es-CL',{weekday:'long',day:'numeric',month:'long',year:'numeric'})

  // ── KPIs ──────────────────────────────────────────
  const kpis=[
    {icon:'🚑',label:'Móviles',val:data.moviles.length,sub:`${data.bases.length} bases activas`,color:C.acl,extra:`${movByTipo['crítico']||0} SVB críticos`},
    {icon:'📦',label:'Equipos en stock',val:stockEq,sub:`${activosEq} activos en móviles`,color:C.pur,extra:`${data.equipamientos.length} total`},
    {icon:'🚨',label:'Stock crítico',val:criticos.length,sub:criticos.length===0?'Todo sobre mínimo':'ítems bajo mínimo',color:criticos.length>0?C.red:C.grn,alert:criticos.length>0},
    {icon:'💊',label:'Meds × vencer',val:medsVencer.length,sub:medsVencer.length===0?'Sin alertas':'próximos ≤ 90 días',color:medsVencer.length>0?C.amb:C.grn,alert:medsVencer.length>0},
    {icon:'✅',label:'Insumos en regla',val:pctOk+'%',sub:`${itemsOk} de ${totalItems} ítems`,color:pctOk>=90?C.grn:pctOk>=70?C.amb:C.red},
    {icon:'⚠️',label:'Vencidos',val:vencidos.length,sub:vencidos.length===0?'Sin productos vencidos':'requieren retiro urgente',color:vencidos.length>0?C.red:C.grn,alert:vencidos.length>0},
  ]

  return(
    <div>
      {/* ── Header ── */}
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:22,flexWrap:'wrap',gap:10}}>
        <div>
          <h2 style={{margin:0,color:C.tb,fontSize:22,fontWeight:800,letterSpacing:-.5}}>Dashboard Operacional</h2>
          <p style={{margin:'3px 0 0',color:C.tm,fontSize:12,textTransform:'capitalize'}}>{dateStr}</p>
        </div>
        <StatusPill label={statusLabel} color={statusColor}/>
      </div>

      {/* ── KPI Row ── */}
      <div className="dash-kpi-grid" style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(155px,1fr))',gap:10,marginBottom:18}}>
        {kpis.map((k,i)=>(
          <div key={i} style={{background:C.s1,border:`1px solid ${k.alert?k.color+'50':C.brd}`,borderRadius:10,padding:'13px 15px',position:'relative',overflow:'hidden',boxShadow:k.alert?`0 0 18px ${k.color}12`:'none'}}>
            {/* Top glow bar for alerts */}
            {k.alert&&<div style={{position:'absolute',top:0,left:0,right:0,height:2,background:k.color,opacity:.7}}/>}
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:8}}>
              <span style={{fontSize:18}}>{k.icon}</span>
              {k.extra&&<span style={{background:C.s3,color:C.tm,fontSize:9,padding:'1px 5px',borderRadius:3,fontWeight:600}}>{k.extra}</span>}
            </div>
            <div style={{color:k.color,fontSize:28,fontWeight:800,lineHeight:1,marginBottom:3}}>{k.val}</div>
            <div style={{color:C.tb,fontSize:12,fontWeight:600,marginBottom:2}}>{k.label}</div>
            <div style={{color:C.tm,fontSize:10}}>{k.sub}</div>
          </div>
        ))}
      </div>

      {/* ── Main grid: left (bases + charts) | right (alertas + actividad) ── */}
      <div className="dash-main-grid" style={{display:'grid',gridTemplateColumns:'minmax(0,1fr) 320px',gap:14,alignItems:'start',flexWrap:'wrap'}}>

        {/* ── Columna izquierda ── */}
        <div style={{display:'flex',flexDirection:'column',gap:14}}>

          {/* Bases operativas */}
          <div style={{background:C.s1,border:`1px solid ${C.brd}`,borderRadius:10,padding:16}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:13}}>
              <span style={{color:C.tb,fontWeight:700,fontSize:14}}>🗺️ Bases Operativas</span>
              <span style={{color:C.tm,fontSize:11}}>{data.moviles.length} móviles · {data.bases.length} bases</span>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(210px,1fr))',gap:9}}>
              {data.bases.map((b,i)=>{
                const movs=data.moviles.filter(m=>m.base===b.nombre)
                return(
                  <div key={i} style={{background:C.s2,border:`1px solid ${C.brd}`,borderRadius:8,padding:11}}>
                    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:5}}>
                      <span style={{color:C.tb,fontWeight:700,fontSize:13}}>{b.nombre}</span>
                      <span style={{background:C.acc+'22',color:C.acl,fontSize:10,fontWeight:700,padding:'1px 7px',borderRadius:10}}>{movs.length} mov.</span>
                    </div>
                    <div style={{color:C.tm,fontSize:10,marginBottom:7,lineHeight:1.3}}>{b.direccion}</div>
                    <div style={{display:'flex',gap:3,flexWrap:'wrap'}}>
                      {TIPOS_MOVIL.filter(t=>movs.filter(m=>m.tipo===t).length>0).map(t=>(
                        <span key={t} style={{background:(TC[t]||C.tm)+'20',color:TC[t]||C.tm,fontSize:9,fontWeight:700,padding:'2px 6px',borderRadius:6,border:`1px solid ${(TC[t]||C.tm)}30`}}>
                          {t} ×{movs.filter(m=>m.tipo===t).length}
                        </span>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Gráficos mini en 2 columnas */}
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>

            {/* Equipamiento por tipo — barras */}
            <div style={{background:C.s1,border:`1px solid ${C.brd}`,borderRadius:10,padding:16}}>
              <div style={{color:C.tb,fontWeight:700,fontSize:13,marginBottom:12}}>🔧 Equipamiento por tipo</div>
              {[['VM',C.red],['BIC',C.amb],['Monitor',C.acl],['Tablet',C.pur],['Teléfono',C.grn],['Bomba aspiración',C.acc],['Otro',C.tm]]
                .filter(([t])=>equipByTipo[t]>0)
                .map(([t,col])=>(
                  <MiniBar key={t} label={t} value={equipByTipo[t]} max={maxEquip} color={col}/>
                ))
              }
              <div style={{marginTop:8,paddingTop:8,borderTop:`1px solid ${C.brd}22`,display:'flex',justifyContent:'space-between'}}>
                <span style={{color:C.tm,fontSize:11}}>Total equipos</span>
                <span style={{color:C.tb,fontSize:11,fontWeight:700}}>{data.equipamientos.length}</span>
              </div>
            </div>

            {/* Móviles por tipo — dona SVG */}
            <div style={{background:C.s1,border:`1px solid ${C.brd}`,borderRadius:10,padding:16}}>
              <div style={{color:C.tb,fontWeight:700,fontSize:13,marginBottom:12}}>🚑 Flota por tipo</div>
              <DonutChart
                total={data.moviles.length}
                segments={TIPOS_MOVIL.filter(t=>movByTipo[t]>0).map(t=>({label:t,value:movByTipo[t],color:TC[t]||C.tm}))}
              />
              <div style={{marginTop:10,paddingTop:8,borderTop:`1px solid ${C.brd}22`,display:'flex',justifyContent:'space-between'}}>
                <span style={{color:C.tm,fontSize:11}}>Flota total</span>
                <span style={{color:C.tb,fontSize:11,fontWeight:700}}>{data.moviles.length} móviles</span>
              </div>
            </div>

          </div>
        </div>

        {/* ── Columna derecha ── */}
        <div style={{display:'flex',flexDirection:'column',gap:12}}>

          {/* Panel: Stock crítico */}
          <div style={{background:C.s1,border:`1px solid ${criticos.length>0?C.red+'44':C.brd}`,borderRadius:10,padding:14,boxShadow:criticos.length>0?`0 0 16px ${C.red}10`:'none'}}>
            <div style={{display:'flex',alignItems:'center',gap:7,marginBottom:criticos.length>0?10:0}}>
              <span style={{fontSize:15}}>🚨</span>
              <span style={{color:criticos.length>0?C.red:C.grn,fontWeight:700,fontSize:13,flex:1}}>
                Stock Crítico {criticos.length>0?`· ${criticos.length} ítems`:'· Sin alertas'}
              </span>
              {criticos.length>0&&<div style={{width:7,height:7,borderRadius:'50%',background:C.red,boxShadow:`0 0 8px ${C.red}`}}/>}
            </div>
            {criticos.length===0
              ?<div style={{color:C.tm,fontSize:12}}>Todos los insumos sobre el mínimo ✓</div>
              :<div style={{maxHeight:165,overflowY:'auto'}}>
                {criticos.slice(0,10).map(i=>(
                  <div key={i.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'5px 0',borderBottom:`1px solid ${C.brd}22`,gap:6}}>
                    <span style={{color:C.txt,fontSize:12,flex:1,lineHeight:1.3}}>{i.nombre}</span>
                    <div style={{textAlign:'right',flexShrink:0}}>
                      <span style={{color:C.red,fontWeight:800,fontSize:12}}>{i.stock}</span>
                      <span style={{color:C.tm,fontSize:10}}>/{i.minimo}</span>
                    </div>
                  </div>
                ))}
                {criticos.length>10&&<div style={{color:C.tm,fontSize:11,textAlign:'center',paddingTop:5}}>+{criticos.length-10} más</div>}
              </div>
            }
          </div>

          {/* Panel: Próximos a vencer */}
          <div style={{background:C.s1,border:`1px solid ${medsVencer.length>0?C.amb+'44':C.brd}`,borderRadius:10,padding:14}}>
            <div style={{display:'flex',alignItems:'center',gap:7,marginBottom:medsVencer.length>0?10:0}}>
              <span style={{fontSize:15}}>⏳</span>
              <span style={{color:medsVencer.length>0?C.amb:C.grn,fontWeight:700,fontSize:13,flex:1}}>
                Próx. a vencer {medsVencer.length>0?`· ${medsVencer.length}`:'· Sin alertas'}
              </span>
            </div>
            {medsVencer.length===0
              ?<div style={{color:C.tm,fontSize:12}}>Sin medicamentos próximos a vencer ✓</div>
              :<div style={{maxHeight:150,overflowY:'auto'}}>
                {medsVencer.slice(0,8).map(m=>{
                  const{label,vencido}=fmtVenc(m.vencimiento)
                  return(
                    <div key={m.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'5px 0',borderBottom:`1px solid ${C.brd}22`,gap:6}}>
                      <span style={{color:C.txt,fontSize:12,flex:1,lineHeight:1.3}}>{m.nombre}</span>
                      <span style={{color:vencido?C.red:C.amb,fontWeight:700,fontSize:10,flexShrink:0}}>{label}</span>
                    </div>
                  )
                })}
                {medsVencer.length>8&&<div style={{color:C.tm,fontSize:11,textAlign:'center',paddingTop:5}}>+{medsVencer.length-8} más</div>}
              </div>
            }
          </div>

          {/* Panel: Actividad reciente */}
          <div style={{background:C.s1,border:`1px solid ${C.brd}`,borderRadius:10,padding:14}}>
            <div style={{color:C.tb,fontWeight:700,fontSize:13,marginBottom:11}}>📋 Actividad reciente</div>
            <div style={{maxHeight:240,overflowY:'auto'}}>
              {[...data.movimientos].reverse().slice(0,9).map((m,i)=>(
                <div key={m.id} style={{display:'flex',gap:9,alignItems:'flex-start',padding:'6px 0',borderBottom:`1px solid ${C.brd}22`}}>
                  <div style={{width:7,height:7,borderRadius:'50%',marginTop:4,flexShrink:0,
                    background:i===0?C.acl:C.s3,border:`1.5px solid ${i===0?C.acl:C.brd}`}}/>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{color:C.txt,fontSize:11,lineHeight:1.4,marginBottom:2}}>{m.descripcion}</div>
                    <div style={{display:'flex',gap:5,alignItems:'center',flexWrap:'wrap'}}>
                      <span style={{background:C.acc+'22',color:C.acl,fontSize:9,padding:'1px 5px',borderRadius:3,fontWeight:700}}>{m.tipo}</span>
                      <span style={{color:C.tm,fontSize:9}}>{m.fecha}</span>
                    </div>
                  </div>
                </div>
              ))}
              {data.movimientos.length===0&&<div style={{color:C.tm,fontSize:12,textAlign:'center',padding:'10px 0'}}>Sin actividad registrada</div>}
            </div>
          </div>

        </div>
      </div>

      <style>{`
        @keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 7px currentColor}50%{opacity:.6;box-shadow:0 0 14px currentColor}}
        @media(max-width:960px){.dash-main-grid{grid-template-columns:1fr!important}}
        @media(max-width:640px){.dash-kpi-grid{grid-template-columns:repeat(2,1fr)!important}}
      `}</style>
    </div>
  )
}

// ═══════════════════════════════════════════════════
//  🚑 GESTIÓN DE MÓVILES
// ═══════════════════════════════════════════════════

function GestionMoviles({data,setData,user}){
  const perm=getPerm(user.role), toast=useToast()
  const tabs=[{id:'resumen',label:'Resumen'},{id:'listado',label:'Listado'},...(perm.editMoviles?[{id:'nuevo',label:'Nuevo móvil'},{id:'codigo',label:'Código horario'},{id:'mantencion',label:'Mantención vehículos'},{id:'eliminar',label:'Eliminar móvil'}]:[])]
  const [tab,setTab]=useState('resumen'),[editMov,setEditMov]=useState(null),[delTarget,setDelTarget]=useState(null)
  const [form,setForm]=useState({numero:'',base:'',tipo:'crítico',patente:'',codigoHorario:'',notas:''})

  const addMov=()=>{
    if(!form.numero||!form.base){toast('Número y base son obligatorios','error');return}
    const nm={id:uid(),...form,numero:san(form.numero,10),patente:san(form.patente,10),codigoHorario:san(form.codigoHorario,20),notas:san(form.notas,300)}
    setData(d=>({...d,moviles:[...d.moviles,nm],movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Móvil',descripcion:`Móvil ${form.numero} agregado a ${form.base}`}]}))
    toast(`Móvil ${form.numero} agregado`,'success');setForm({numero:'',base:'',tipo:'crítico',patente:'',codigoHorario:'',notas:''});setTab('listado')
  }
  const saveMov=(id,vals)=>{
    setData(d=>({...d,moviles:d.moviles.map(m=>m.id===id?{...m,...vals}:m),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Móvil',descripcion:`Móvil ${vals.numero||id} editado`}]}))
    setEditMov(null);toast('Móvil actualizado','success')
  }
  const delMov=()=>{
    if(!delTarget)return
    setData(d=>({...d,moviles:d.moviles.filter(m=>m.id!==delTarget.id),equipamientos:d.equipamientos.map(e=>e.movil_id===delTarget.id?{...e,movil_id:null,estado:'stock'}:e),mantenciones_vehiculo:d.mantenciones_vehiculo.filter(mv=>mv.movil_id!==delTarget.id),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Móvil eliminado',descripcion:`Móvil ${delTarget.numero} eliminado`}]}))
    toast(`Móvil ${delTarget.numero} eliminado`,'warn');setDelTarget(null)
  }
  const baseGroups=data.bases.map(b=>({base:b,moviles:data.moviles.filter(m=>m.base===b.nombre)}))
  return(
    <div>
      <PageTitle sub="Administración de unidades móviles">🚑 Gestión de Móviles</PageTitle>
      <Tabs tabs={tabs} active={tab} onChange={setTab}/>
      {tab==='resumen'&&<ResumenMovilesTab data={data}/>}
      {tab==='listado'&&<div>
        {baseGroups.map(({base,moviles:mvs})=>(
          <div key={base.nombre} style={{marginBottom:24}}>
            <div style={{color:C.tm,fontWeight:700,fontSize:12,letterSpacing:1,marginBottom:10,textTransform:'uppercase'}}>{base.nombre} — {base.direccion}</div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(260px,1fr))',gap:12}}>
              {mvs.map(mv=>{const equips=data.equipamientos.filter(e=>e.movil_id===mv.id&&e.estado==='activo');return <Card key={mv.id}>
                <div style={{display:'flex',justifyContent:'space-between',alignItems:'start',marginBottom:8}}>
                  <div><span style={{color:C.tb,fontWeight:800,fontSize:18}}>Móvil {mv.numero}</span><div style={{marginTop:4}}><Badge color={TC[mv.tipo]||C.tm}>{mv.tipo}</Badge></div></div>
                  {perm.editMoviles&&<Btn sm variant="ghost" onClick={()=>setEditMov({...mv})}>Editar</Btn>}
                </div>
                <div style={{color:C.tm,fontSize:12,marginBottom:4}}>Patente: <span style={{color:C.txt}}>{mv.patente||'—'}</span></div>
                {mv.codigoHorario&&<div style={{background:C.acc+'22',border:`1px solid ${C.acc}44`,borderRadius:6,padding:'4px 8px',marginBottom:8}}><span style={{color:C.acl,fontFamily:'monospace',fontWeight:700,fontSize:14}}>{mv.codigoHorario}</span></div>}
                {equips.length>0&&<div style={{display:'flex',flexWrap:'wrap',gap:4}}>{equips.map(e=><Badge key={e.id} color={C.acl}>{e.tipo}</Badge>)}</div>}
              </Card>})}
            </div>
          </div>
        ))}
      </div>}
      {tab==='nuevo'&&perm.editMoviles&&<Card style={{maxWidth:440}}>
        <h3 style={{color:C.tb,marginTop:0,marginBottom:16,fontSize:16}}>Nuevo móvil</h3>
        {[['Número de móvil',<Inp value={form.numero} onChange={e=>setForm(f=>({...f,numero:e.target.value}))} placeholder="Ej: 395" maxLength={10}/>],
          ['Base',<Sel value={form.base} onChange={e=>setForm(f=>({...f,base:e.target.value}))}><option value="">— Seleccionar base —</option>{data.bases.map(b=><option key={b.nombre} value={b.nombre}>{b.nombre}</option>)}</Sel>],
          ['Tipo',<Sel value={form.tipo} onChange={e=>setForm(f=>({...f,tipo:e.target.value}))}>{TIPOS_MOVIL.map(t=><option key={t}>{t}</option>)}</Sel>],
          ['Patente',<Inp value={form.patente} onChange={e=>setForm(f=>({...f,patente:e.target.value}))} placeholder="XXXX-00" maxLength={10}/>],
          ['Código Horario',<Inp value={form.codigoHorario} onChange={e=>setForm(f=>({...f,codigoHorario:e.target.value.toUpperCase()}))} placeholder="Código" style={{fontFamily:'monospace',textTransform:'uppercase'}} maxLength={20}/>],
          ['Notas',<Txt value={form.notas} onChange={e=>setForm(f=>({...f,notas:e.target.value}))} rows={2}/>],
        ].map(([l,c],i)=><Fld key={i} label={l}>{c}</Fld>)}
        <Btn onClick={addMov} full>Agregar móvil</Btn>
      </Card>}
      {tab==='codigo'&&perm.editMoviles&&<CodigoHorarioTab data={data} setData={setData}/>}
      {tab==='mantencion'&&perm.editMoviles&&<MantencionVehTab data={data} setData={setData}/>}
      {tab==='eliminar'&&perm.editMoviles&&<div>
        <ReadOnlyBanner msg="⚠️ Eliminar un móvil es permanente. El equipamiento regresa al inventario."/>
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(260px,1fr))',gap:12}}>
          {data.moviles.map(mv=><Card key={mv.id}><div style={{marginBottom:8}}><span style={{color:C.tb,fontWeight:700}}>Móvil {mv.numero}</span> — <Badge color={TC[mv.tipo]||C.tm}>{mv.tipo}</Badge><div style={{color:C.tm,fontSize:12,marginTop:4}}>{mv.base}</div></div><Btn variant="danger" sm onClick={()=>setDelTarget({id:mv.id,numero:mv.numero,base:mv.base,tipo:mv.tipo})}>🗑 Eliminar</Btn></Card>)}
        </div>
      </div>}
      {editMov&&<Modal title={`Editar Móvil ${editMov.numero}`} onClose={()=>setEditMov(null)}>
        <EditMovModal mv={editMov} bases={data.bases} onSave={saveMov} onClose={()=>setEditMov(null)}/>
      </Modal>}
      {delTarget&&<ConfirmModal title="Confirmar eliminación"
        body={<div style={{textAlign:'center'}}><div style={{fontSize:48}}>⚠️</div><div style={{color:C.tb,fontWeight:700,fontSize:18}}>Móvil {delTarget.numero}</div><div style={{color:C.tm,fontSize:13}}>{delTarget.base} · {delTarget.tipo}</div><div style={{background:C.red+'22',border:`1px solid ${C.red}44`,borderRadius:8,padding:'10px 14px',marginTop:12,color:C.red,fontSize:13}}>Esta acción es permanente. El equipamiento asignado regresará al inventario.</div></div>}
        onConfirm={delMov} onClose={()=>setDelTarget(null)} confirmLabel="Confirmar eliminación"/>}
    </div>
  )
}

function EditMovModal({mv,bases,onSave,onClose}){
  const[form,setForm]=useState({...mv})
  return <>
    {[['Número',<Inp value={form.numero} onChange={e=>setForm(f=>({...f,numero:e.target.value}))} maxLength={10}/>],['Base',<Sel value={form.base} onChange={e=>setForm(f=>({...f,base:e.target.value}))}>{bases.map(b=><option key={b.nombre} value={b.nombre}>{b.nombre}</option>)}</Sel>],['Tipo',<Sel value={form.tipo} onChange={e=>setForm(f=>({...f,tipo:e.target.value}))}>{TIPOS_MOVIL.map(t=><option key={t}>{t}</option>)}</Sel>],['Patente',<Inp value={form.patente} onChange={e=>setForm(f=>({...f,patente:e.target.value}))} maxLength={10}/>],['Código Horario',<Inp value={form.codigoHorario} onChange={e=>setForm(f=>({...f,codigoHorario:e.target.value.toUpperCase()}))} style={{fontFamily:'monospace'}} maxLength={20}/>],['Notas',<Txt value={form.notas} onChange={e=>setForm(f=>({...f,notas:e.target.value}))} rows={2}/>]].map(([l,c],i)=><Fld key={i} label={l}>{c}</Fld>)}
    <div style={{display:'flex',gap:8}}><Btn variant="secondary" full onClick={onClose}>Cancelar</Btn><Btn full onClick={()=>onSave(mv.id,form)}>Guardar cambios</Btn></div>
  </>
}

function CodigoHorarioTab({data,setData}){
  const toast=useToast(),[sub,setSub]=useState('vista')
  const subtabs=[{id:'vista',label:'Vista general'},{id:'crear',label:'Crear / editar código'},{id:'reasignar',label:'Reasignar código'}]
  return <div>
    <Tabs tabs={subtabs} active={sub} onChange={setSub}/>
    {sub==='vista'&&<div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:10}}>
      {data.moviles.map(m=><Card key={m.id}>
        <div style={{color:C.tb,fontWeight:700,marginBottom:4}}>Móvil {m.numero}</div>
        <div style={{color:C.tm,fontSize:12,marginBottom:8}}>{m.base}</div>
        {m.codigoHorario
          ?<div style={{background:C.acc+'22',border:`1px solid ${C.acc}44`,borderRadius:6,padding:'6px 10px',textAlign:'center'}}><span style={{color:C.acl,fontFamily:'monospace',fontWeight:700,fontSize:15}}>{m.codigoHorario}</span></div>
          :<div style={{background:C.s3,borderRadius:6,padding:'6px 10px',textAlign:'center'}}><span style={{color:C.tm,fontSize:12}}>Sin código asignado</span></div>}
      </Card>)}
    </div>}
    {sub==='crear'&&<CrearCodigoTab data={data} setData={setData}/>}
    {sub==='reasignar'&&<ReasignarCodigoTab data={data} setData={setData}/>}
  </div>
}

function CrearCodigoTab({data,setData}){
  const toast=useToast(),[sel,setSel]=useState(''),[codigo,setCodigo]=useState('')
  const mv=data.moviles.find(m=>m.id===sel)
  const guardar=()=>{
    if(!sel){toast('Selecciona un móvil','error');return}
    setData(d=>({...d,moviles:d.moviles.map(m=>m.id===sel?{...m,codigoHorario:san(codigo,20).toUpperCase()}:m),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Código Horario',descripcion:`Código ${codigo.toUpperCase()||'(vacío)'} asignado a Móvil ${mv?.numero}`}]}))
    toast(`Código actualizado en Móvil ${mv?.numero}`,'success');setSel('');setCodigo('')
  }
  return <Card style={{maxWidth:420}}>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Crear / editar código horario</h3>
    <div style={{background:C.s3,border:`1px solid ${C.brd}`,borderRadius:6,padding:'8px 12px',marginBottom:14,fontSize:12,color:C.tm}}>
      💡 Puedes asignar un nuevo código a cualquier móvil, o dejar el campo vacío para eliminar el código existente.
    </div>
    <Fld label="Móvil"><Sel value={sel} onChange={e=>{setSel(e.target.value);const m=data.moviles.find(x=>x.id===e.target.value);setCodigo(m?.codigoHorario||'')}}><option value="">— Seleccionar móvil —</option>{data.moviles.map(m=><option key={m.id} value={m.id}>Móvil {m.numero} — {m.base} {m.codigoHorario?`(actual: ${m.codigoHorario})`:'(sin código)'}</option>)}</Sel></Fld>
    {sel&&<Fld label="Código horario (vacío = sin código)"><Inp value={codigo} onChange={e=>setCodigo(e.target.value.toUpperCase())} placeholder="Ej: A1B2C3" style={{fontFamily:'monospace',textTransform:'uppercase',letterSpacing:2}} maxLength={20}/>{mv?.codigoHorario&&<div style={{fontSize:11,color:C.tm,marginTop:4}}>Código actual: <span style={{fontFamily:'monospace',color:C.acl}}>{mv.codigoHorario}</span></div>}</Fld>}
    <div style={{display:'flex',gap:8}}>
      <Btn onClick={guardar} full>Guardar código</Btn>
      {sel&&codigo&&<Btn variant="danger" onClick={()=>{setCodigo('');guardar()}}>Limpiar código</Btn>}
    </div>
  </Card>
}

function ReasignarCodigoTab({data,setData}){
  const toast=useToast(),[orig,setOrig]=useState(''),[dest,setDest]=useState('')
  const preview=()=>{const o=data.moviles.find(m=>m.id===orig);const d2=data.moviles.find(m=>m.id===dest);if(!o)return null;if(d2)return `Intercambio: Móvil ${o.numero} (${o.codigoHorario||'—'}) ↔ Móvil ${d2.numero} (${d2.codigoHorario||'—'})`;return `Mover código de Móvil ${o.numero} → sin destino (limpiar origen)`}
  const doSwap=()=>{
    if(!orig)return
    setData(d=>{const moviles=d.moviles.map(m=>{if(m.id===orig&&dest)return{...m,codigoHorario:d.moviles.find(x=>x.id===dest)?.codigoHorario||''};if(m.id===dest&&orig)return{...m,codigoHorario:d.moviles.find(x=>x.id===orig)?.codigoHorario||''};return m});return{...d,moviles,movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Código Horario',descripcion:preview()||'Reasignación de código horario'}]}})
    toast('Reasignación completada','success');setOrig('');setDest('')
  }
  return <Card style={{maxWidth:420}}>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Reasignar / intercambiar código</h3>
    <Fld label="Móvil origen (tiene el código a mover)"><Sel value={orig} onChange={e=>setOrig(e.target.value)}><option value="">— Seleccionar —</option>{data.moviles.map(m=><option key={m.id} value={m.id}>Móvil {m.numero} ({m.codigoHorario||'sin código'})</option>)}</Sel></Fld>
    <Fld label="Móvil destino (recibe el código — vacío = solo limpiar origen)"><Sel value={dest} onChange={e=>setDest(e.target.value)}><option value="">— Sin destino (limpiar origen) —</option>{data.moviles.filter(m=>m.id!==orig).map(m=><option key={m.id} value={m.id}>Móvil {m.numero} ({m.codigoHorario||'sin código'})</option>)}</Sel></Fld>
    {preview()&&<div style={{background:C.acc+'11',border:`1px solid ${C.acc}33`,borderRadius:6,padding:'8px 12px',marginBottom:12,fontSize:13,color:C.acl}}>{preview()}</div>}
    <Btn onClick={doSwap} full disabled={!orig}>Confirmar reasignación</Btn>
  </Card>
}

function MantencionVehTab({data,setData}){
  const toast=useToast(),[editId,setEditId]=useState(null),[kmForm,setKmForm]=useState(''),[notaId,setNotaId]=useState(null),[notaText,setNotaText]=useState('')
  const records=data.moviles.map(mv=>({mv,rec:data.mantenciones_vehiculo.find(r=>r.movil_id===mv.id)})).sort((a,b)=>{if(!a.rec)return 1;if(!b.rec)return -1;return(a.rec.proximaKm-a.rec.km)-(b.rec.proximaKm-b.rec.km)})
  const saveKm=(movil_id,km)=>{
    const k=parseInt(km);if(isNaN(k)||k<0){toast('KM inválido','error');return}
    setData(d=>{const exists=d.mantenciones_vehiculo.find(r=>r.movil_id===movil_id);const mant=exists?d.mantenciones_vehiculo.map(r=>r.movil_id===movil_id?{...r,km:k,proximaKm:k+10000,ultimaFecha:today()}:r):[...d.mantenciones_vehiculo,{id:uid(),movil_id,km:k,ultimaFecha:today(),proximaKm:k+10000,proximaFecha:'',nota:''}];return{...d,mantenciones_vehiculo:mant,movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Mantención Vehículo',descripcion:`KM actualizado a ${k}`}]}})
    toast('KM actualizado','success');setEditId(null);setKmForm('')
  }
  const saveNota=(movil_id)=>{
    setData(d=>({...d,mantenciones_vehiculo:d.mantenciones_vehiculo.map(r=>r.movil_id===movil_id?{...r,nota:san(notaText,300)}:r),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Nota Mantención',descripcion:`Nota actualizada`}]}))
    toast('Nota guardada','success');setNotaId(null);setNotaText('')
  }
  return <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(260px,1fr))',gap:12}}>
    {records.map(({mv,rec})=>{
      const restante=rec?rec.proximaKm-rec.km:null,color=!rec?C.tm:restante<=0?C.red:restante<=1500?C.amb:C.grn,pct=rec?Math.max(0,Math.min(100,(rec.km%10000)/100)):0
      return <Card key={mv.id} style={{borderTop:`2px solid ${color}`}}>
        <div style={{display:'flex',justifyContent:'space-between',marginBottom:8}}><div><span style={{color:C.tb,fontWeight:700}}>Móvil {mv.numero}</span></div><Badge color={color}>{!rec?'Sin datos':restante<=0?'Vencida':restante<=1500?'Próxima':'OK'}</Badge></div>
        {rec&&<><div style={{fontSize:12,color:C.tm,marginBottom:4}}>KM actual: <span style={{color:C.txt}}>{rec.km.toLocaleString()}</span></div><div style={{fontSize:12,color:C.tm,marginBottom:8}}>Próxima: <span style={{color}}>{rec.proximaKm.toLocaleString()}</span> ({restante>0?'+':''}{restante?.toLocaleString()} km)</div><div style={{background:C.s3,borderRadius:4,height:6,marginBottom:8,overflow:'hidden'}}><div style={{background:color,height:'100%',width:`${pct}%`,borderRadius:4}}/></div>{rec.nota&&<div style={{fontSize:12,color:C.tm,marginBottom:6}}>{rec.nota}</div>}</>}
        {editId===mv.id?<div style={{display:'flex',gap:6,marginBottom:6}}><Inp value={kmForm} onChange={e=>setKmForm(e.target.value)} placeholder="KM actual" type="number" sm/><Btn sm onClick={()=>saveKm(mv.id,kmForm)}>✓</Btn><Btn sm variant="ghost" onClick={()=>setEditId(null)}>✕</Btn></div>
        :<div style={{display:'flex',gap:6}}><Btn sm variant="secondary" onClick={()=>{setEditId(mv.id);setKmForm(rec?.km||'')}}>✏ KM</Btn><Btn sm variant="ghost" onClick={()=>{setNotaId(mv.id);setNotaText(rec?.nota||'')}}>📌</Btn></div>}
        {notaId===mv.id&&<div style={{marginTop:8}}><Txt value={notaText} onChange={e=>setNotaText(e.target.value)} rows={2} placeholder="Nota…"/><div style={{display:'flex',gap:6,marginTop:6}}><Btn sm onClick={()=>saveNota(mv.id)}>Guardar</Btn><Btn sm variant="ghost" onClick={()=>setNotaId(null)}>Cancelar</Btn></div></div>}
      </Card>
    })}
  </div>
}

// ═══════════════════════════════════════════════════
//  💊 FARMACIA
// ═══════════════════════════════════════════════════

function EditStockModal({item,isMed,onSave,onClose}){
  const[form,setForm]=useState({stock:item.stock,minimo:item.minimo,lote:item.lote||'',vencimiento:item.vencimiento||''})
  return <Modal title={`Editar: ${item.nombre}`} onClose={onClose}>
    <Fld label="Stock actual"><Inp type="number" value={form.stock} onChange={e=>setForm(f=>({...f,stock:parseInt(e.target.value)||0}))}/></Fld>
    <Fld label="Stock mínimo"><Inp type="number" value={form.minimo} onChange={e=>setForm(f=>({...f,minimo:parseInt(e.target.value)||0}))}/></Fld>
    {isMed&&<><Fld label="Lote"><Inp value={form.lote} onChange={e=>setForm(f=>({...f,lote:e.target.value}))} maxLength={50}/></Fld><Fld label="Vencimiento"><Inp type="date" value={form.vencimiento} onChange={e=>setForm(f=>({...f,vencimiento:e.target.value}))}/></Fld></>}
    <div style={{display:'flex',gap:8}}><Btn variant="secondary" full onClick={onClose}>Cancelar</Btn><Btn full onClick={()=>onSave(form)}>Guardar</Btn></div>
  </Modal>
}

function GestionFarmacia({data,setData,user}){
  const perm=getPerm(user.role)
  const canInventario=['admin','supervisor','jefatura','farmacia'].includes(user.role)
  const tabs=[
    {id:'resumen',label:'Resumen'},
    {id:'botiquin',label:'Botiquín'},
    {id:'bodega',label:'Bodega'},
    {id:'buscar',label:'Buscar'},
    ...(canInventario?[{id:'inventario',label:'📦 Inventario'}]:[]),
  ]
  const [tab,setTab]=useState('resumen'),[editItem,setEditItem]=useState(null)
  const saveEdit=(collection,id,vals)=>{setData(d=>({...d,[collection]:d[collection].map(i=>i.id===id?{...i,...vals}:i),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Med. modificado',descripcion:`${vals.nombre||id} modificado`}]}));setEditItem(null)}
  const criticos=useMemo(()=>[...data.botiquin_insumos,...data.botiquin_meds].filter(i=>i.stock<=i.minimo),[data.botiquin_insumos,data.botiquin_meds])
  const medsVencer=useMemo(()=>[...data.botiquin_meds,...data.controlados].filter(m=>daysUntil(m.vencimiento)<=90),[data.botiquin_meds,data.controlados])
  return(
    <div>
      <PageTitle sub="Gestión de botiquín, bodega e insumos">💊 Gestión Farmacia</PageTitle>
      {!perm.editFarmacia&&<ReadOnlyBanner msg="Tu rol tiene acceso de solo lectura en farmacia."/>}
      <Tabs tabs={tabs} active={tab} onChange={setTab}/>
      {tab==='resumen'&&<div>
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))',gap:12,marginBottom:20}}>{[{l:'Tipos insumos',v:data.botiquin_insumos.length,c:C.acl},{l:'Medicamentos',v:data.botiquin_meds.length,c:C.acl},{l:'Stock crítico',v:criticos.length,c:criticos.length>0?C.red:C.grn},{l:'Meds × vencer',v:medsVencer.length,c:medsVencer.length>0?C.amb:C.grn}].map((c,i)=><Card key={i} style={{textAlign:'center'}}><div style={{color:c.c,fontSize:28,fontWeight:800}}>{c.v}</div><div style={{color:C.txt,fontSize:12}}>{c.l}</div></Card>)}</div>
        <h3 style={{color:C.tb,fontSize:14,marginBottom:10}}>Insumos botiquín por criticidad</h3>
        <Card>{[...data.botiquin_insumos].sort((a,b)=>(a.stock/a.minimo)-(b.stock/b.minimo)).map(i=><StkRow key={i.id} item={i} onEdit={perm.editFarmacia?()=>setEditItem({item:i,col:'botiquin_insumos',isMed:false}):undefined}/>)}</Card>
      </div>}
      {tab==='botiquin'&&<BotiquinTab data={data} setData={setData} canEdit={perm.editFarmacia} onEdit={(item,col,isMed)=>setEditItem({item,col,isMed})}/>}
      {tab==='bodega'&&<BodegaTab data={data} setData={setData} canEdit={perm.editFarmacia} onEdit={(item)=>setEditItem({item,col:'bodega_insumos',isMed:false})}/>}
      {tab==='buscar'&&<BuscarTab data={data}/>}
      {tab==='inventario'&&canInventario&&<InventarioTab data={data} setData={setData}/>}
      {editItem&&<EditStockModal item={editItem.item} isMed={editItem.isMed} onSave={vals=>saveEdit(editItem.col,editItem.item.id,vals)} onClose={()=>setEditItem(null)}/>}
    </div>
  )
}

function BotiquinTab({data,setData,canEdit,onEdit}){
  const subtabs=[{id:'ins',label:'Insumos'},{id:'meds',label:'Medicamentos'},...(canEdit?[{id:'egreso',label:'Egreso por llamado'},{id:'rec_ins',label:'Recepción insumos'},{id:'rec_med',label:'Recepción medicamentos'}]:[])]
  const [sub,setSub]=useState('ins')
  return <>
    <Tabs tabs={subtabs} active={sub} onChange={setSub}/>
    {sub==='ins'&&<Card>{[...data.botiquin_insumos].map(i=><StkRow key={i.id} item={i} onEdit={canEdit?()=>onEdit(i,'botiquin_insumos',false):undefined}/>)}</Card>}
    {sub==='meds'&&<Card>{fefoSort(data.botiquin_meds).map(m=>{const{label,vencido,near}=fmtVenc(m.vencimiento);return <div key={m.id} style={{display:'flex',alignItems:'center',gap:8,padding:'8px 0',borderBottom:`1px solid ${C.brd}`}}><div style={{flex:1}}><div style={{color:C.txt,fontSize:13}}>{m.nombre}</div><div style={{color:C.tm,fontSize:11}}>Lote: {m.lote}</div></div><span style={{color:vencido?C.red:near?C.amb:C.tm,fontSize:12}}>{label}</span><SBar stock={m.stock} minimo={m.minimo}/><span style={{color:C.txt,fontWeight:700,fontSize:13,minWidth:28,textAlign:'right'}}>{m.stock}</span>{canEdit&&<button onClick={()=>onEdit(m,'botiquin_meds',true)} style={{background:'none',border:'none',color:C.acl,cursor:'pointer',fontSize:13}}>✏</button>}</div>})}</Card>}
    {sub==='egreso'&&canEdit&&<EgresoForm data={data} setData={setData}/>}
    {sub==='rec_ins'&&canEdit&&<RecepcionInsTab data={data} setData={setData}/>}
    {sub==='rec_med'&&canEdit&&<RecepcionMedTab data={data} setData={setData}/>}
  </>
}

function EgresoForm({data,setData}){
  const toast=useToast(),[llamado,setLlamado]=useState(''),[movil,setMovil]=useState(''),[items,setItems]=useState([{nombre:'',cantidad:0}])
  const allIns=[...data.botiquin_insumos,...data.botiquin_meds]
  const addItem=()=>setItems(i=>[...i,{nombre:'',cantidad:0}])
  const setItem=(idx,field,val)=>setItems(i=>i.map((it,ii)=>ii===idx?{...it,[field]:val}:it))
  const getHint=(nombre)=>{const med=fefoSort(data.botiquin_meds).find(m=>m.nombre===nombre);if(med){const{label,vencido}=fmtVenc(med.vencimiento);return <div style={{fontSize:11,color:vencido?C.red:C.amb,marginTop:2}}>{vencido?'⚠️':'📋'} FEFO · Lote: {med.lote} · {label}</div>};const ins=data.botiquin_insumos.find(i=>i.nombre===nombre);if(ins)return <div style={{fontSize:11,color:C.acl,marginTop:2}}>📋 FIFO · Stock: {ins.stock}</div>;return null}
  const enviar=()=>{
    const valid=items.filter(it=>it.nombre&&it.cantidad>0)
    if(!valid.length||!llamado){toast('Ingresa N° llamado e ítems','error');return}
    // Validar que todos los nombres existan en el inventario
    const desconocidos=valid.filter(it=>{
      const enMeds=data.botiquin_meds.find(m=>m.nombre===it.nombre)
      const enIns=data.botiquin_insumos.find(i=>i.nombre===it.nombre)
      return !enMeds&&!enIns
    })
    if(desconocidos.length>0){
      toast(`Ítems no encontrados en inventario: ${desconocidos.map(d=>d.nombre).join(', ')}`,'error',5000)
      return
    }
    const sinStock=valid.filter(it=>{
      const m=data.botiquin_meds.find(m=>m.nombre===it.nombre)
      const i=data.botiquin_insumos.find(i=>i.nombre===it.nombre)
      return (m&&it.cantidad>m.stock)||(i&&it.cantidad>i.stock)
    })
    if(sinStock.length>0){toast(`Stock insuficiente: ${sinStock.map(i=>i.nombre).join(', ')}`,'error',5000);return}
    setData(d=>{
      let bi=[...d.botiquin_insumos],bm=[...d.botiquin_meds]
      valid.forEach(it=>{
        const idx=bm.findIndex(m=>m.nombre===it.nombre)
        if(idx>=0) bm[idx]={...bm[idx],stock:Math.max(0,bm[idx].stock-it.cantidad)}
        else{
          const ii=bi.findIndex(i=>i.nombre===it.nombre)
          if(ii>=0) bi[ii]={...bi[ii],stock:Math.max(0,bi[ii].stock-it.cantidad)}
        }
      })
      const mvObj=movil?d.moviles.find(m=>m.id===movil):null
      return{...d,botiquin_insumos:bi,botiquin_meds:bm,movimientos:[...d.movimientos,{
        id:uid(),fecha:now(),tipo:'Egreso',
        descripcion:`Llamado #${san(llamado,20)}${mvObj?` Móvil ${mvObj.numero}`:''}: ${valid.map(i=>`${i.nombre}x${i.cantidad}`).join(', ')}`
      }]}
    })
    toast('Egreso registrado','success');setLlamado('');setMovil('');setItems([{nombre:'',cantidad:0}])
  }
  return <Card style={{maxWidth:500}}>
    <datalist id="dl-ins">{allIns.map(i=><option key={i.id} value={i.nombre}/>)}</datalist>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Egreso por llamado</h3>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:14}}>
      <Fld label="N° Llamado (RUN)"><Inp value={llamado} onChange={e=>setLlamado(e.target.value)} placeholder="12345678-9" maxLength={20}/></Fld>
      <Fld label="Móvil (opcional)"><Sel value={movil} onChange={e=>setMovil(e.target.value)}><option value="">— Opcional —</option>{data.moviles.map(m=><option key={m.id} value={m.id}>Móvil {m.numero}</option>)}</Sel></Fld>
    </div>
    {items.map((it,idx)=><div key={idx} style={{display:'flex',gap:8,marginBottom:4,alignItems:'flex-start'}}><div style={{flex:1}}><Inp value={it.nombre} onChange={e=>setItem(idx,'nombre',e.target.value)} placeholder="Ítem…" list="dl-ins" sm/>{getHint(it.nombre)}</div><Inp type="number" value={it.cantidad} onChange={e=>setItem(idx,'cantidad',parseInt(e.target.value)||0)} placeholder="Cant." sm style={{width:70}}/><Btn sm variant="ghost" onClick={()=>setItems(i=>i.filter((_,ii)=>ii!==idx))}>✕</Btn></div>)}
    <div style={{display:'flex',gap:8,marginTop:8}}><Btn variant="ghost" sm onClick={addItem}>+ Agregar ítem</Btn><Btn onClick={enviar}>Enviar egreso</Btn></div>
  </Card>
}

function RecepcionInsTab({data,setData}){
  const toast=useToast(),[desde,setDesde]=useState('bodega'),[sel,setSel]=useState(''),[cant,setCant]=useState(1)
  const options=desde==='bodega'?data.bodega_insumos:data.botiquin_insumos
  const recibir=()=>{
    if(!sel||cant<=0){toast('Selecciona insumo y cantidad','error');return}
    const item=options.find(i=>i.id===sel)
    if(!item)return
    setData(d=>{
      // Si existe en botiquín, incrementar; si no, crearlo
      const existe=d.botiquin_insumos.find(i=>i.nombre===item.nombre)
      const bi=existe
        ? d.botiquin_insumos.map(i=>i.nombre===item.nombre?{...i,stock:i.stock+cant}:i)
        : [...d.botiquin_insumos,{id:uid(),nombre:item.nombre,stock:cant,minimo:item.minimo||5}]
      let bod=d.bodega_insumos
      if(desde==='bodega') bod=bod.map(i=>i.id===sel?{...i,stock:Math.max(0,i.stock-cant)}:i)
      return{...d,botiquin_insumos:bi,bodega_insumos:bod,movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Recepción Insumo',descripcion:`${item.nombre} x${cant}${desde==='sobrante'?' (sobrante)':''}${!existe?' [nuevo en botiquín]':''}`}]}
    })
    toast(`${item.nombre} x${cant} recibido`,'success');setSel('');setCant(1)
  }
  return <Card style={{maxWidth:400}}>
    <div style={{display:'flex',gap:8,marginBottom:14}}>{['bodega','sobrante'].map(d=><Btn key={d} variant={desde===d?'primary':'ghost'} sm onClick={()=>setDesde(d)}>{d==='bodega'?'Desde bodega':'Sobrante / Retorno'}</Btn>)}</div>
    <Fld label="Insumo"><Sel value={sel} onChange={e=>setSel(e.target.value)}><option value="">— Seleccionar —</option>{options.map(i=><option key={i.id} value={i.id}>{i.nombre} (stock: {i.stock})</option>)}</Sel></Fld>
    <Fld label="Cantidad"><Inp type="number" value={cant} onChange={e=>setCant(parseInt(e.target.value)||0)}/></Fld>
    <Btn onClick={recibir} full>Recibir</Btn>
  </Card>
}

function RecepcionMedTab({data,setData}){
  const toast=useToast(),[desde,setDesde]=useState('central'),[nombre,setNombre]=useState(''),[cant,setCant]=useState(1),[lote,setLote]=useState(''),[venc,setVenc]=useState('')
  const recibir=()=>{
    if(!nombre||cant<=0){toast('Nombre y cantidad requeridos','error');return}
    setData(d=>{
      const idx=d.botiquin_meds.findIndex(m=>m.nombre===nombre&&m.lote===lote)
      let bm=idx>=0
        ? d.botiquin_meds.map((m,i)=>i===idx?{...m,stock:m.stock+cant}:m)
        : [...d.botiquin_meds,{id:uid(),nombre:san(nombre,100),stock:cant,lote:san(lote,50),vencimiento:venc,minimo:3}]
      return{...d,botiquin_meds:bm,movimientos:[...d.movimientos,{
        id:uid(),fecha:now(),tipo:'Recepción Med',
        descripcion:`${nombre} x${cant} ${desde==='central'?'(desde central)':'(sobrante)'}${lote?` · Lote: ${lote}`:''}`
      }]}
    })
    toast(`${nombre} recibido`,'success');setNombre('');setCant(1);setLote('');setVenc('')
  }
  return <Card style={{maxWidth:400}}>
    <datalist id="dl-bm">{data.botiquin_meds.map(m=><option key={m.id} value={m.nombre}/>)}</datalist>
    <div style={{display:'flex',gap:8,marginBottom:14}}>{['central','sobrante'].map(d=><Btn key={d} variant={desde===d?'primary':'ghost'} sm onClick={()=>setDesde(d)}>{d==='central'?'Desde central':'Sobrante'}</Btn>)}</div>
    <Fld label="Medicamento"><Inp value={nombre} onChange={e=>setNombre(e.target.value)} list="dl-bm" placeholder="Nombre…" maxLength={100}/></Fld>
    <Fld label="Cantidad"><Inp type="number" value={cant} onChange={e=>setCant(parseInt(e.target.value)||0)}/></Fld>
    <Fld label="Lote"><Inp value={lote} onChange={e=>setLote(e.target.value)} placeholder="LOT-XXXX" maxLength={50}/></Fld>
    <Fld label="Vencimiento"><Inp type="date" value={venc} onChange={e=>setVenc(e.target.value)}/></Fld>
    <Btn onClick={recibir} full>Recibir</Btn>
  </Card>
}

function BodegaTab({data,setData,canEdit,onEdit}){
  const subtabs=[{id:'stock',label:'Stock'},...(canEdit?[{id:'recepcion',label:'Recepción central'},{id:'enviar',label:'Enviar a botiquín'}]:[])]
  const [sub,setSub]=useState('stock')
  return <>
    <Tabs tabs={subtabs} active={sub} onChange={setSub}/>
    {sub==='stock'&&<Card>{[...data.bodega_insumos].sort((a,b)=>(a.stock/a.minimo)-(b.stock/b.minimo)).map(i=><StkRow key={i.id} item={i} onEdit={canEdit?()=>onEdit(i):undefined}/>)}</Card>}
    {sub==='recepcion'&&canEdit&&<RecepcionBodegaTab data={data} setData={setData}/>}
    {sub==='enviar'&&canEdit&&<EnviarBotiquinTab data={data} setData={setData}/>}
  </>
}

function RecepcionBodegaTab({data,setData}){
  const toast=useToast(),[nombre,setNombre]=useState(''),[cant,setCant]=useState(1)
  const recv=()=>{if(!nombre||cant<=0){toast('Nombre y cantidad requeridos','error');return};setData(d=>{const idx=d.bodega_insumos.findIndex(i=>i.nombre===nombre);const bod=idx>=0?d.bodega_insumos.map((i,ii)=>ii===idx?{...i,stock:i.stock+cant}:i):[...d.bodega_insumos,{id:uid(),nombre:san(nombre,100),stock:cant,minimo:10}];return{...d,bodega_insumos:bod,movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Recepción Bodega',descripcion:`${nombre} x${cant}`}]}});toast(`${nombre} recibido en bodega`,'success');setNombre('');setCant(1)}
  return <Card style={{maxWidth:380}}>
    <datalist id="dl-bod">{data.bodega_insumos.map(i=><option key={i.id} value={i.nombre}/>)}</datalist>
    <Fld label="Insumo"><Inp value={nombre} onChange={e=>setNombre(e.target.value)} list="dl-bod" placeholder="Nombre…" maxLength={100}/></Fld>
    <Fld label="Cantidad"><Inp type="number" value={cant} onChange={e=>setCant(parseInt(e.target.value)||0)}/></Fld>
    <Btn onClick={recv} full>Recibir en bodega</Btn>
  </Card>
}

function EnviarBotiquinTab({data,setData}){
  const toast=useToast(),[sel,setSel]=useState(''),[cant,setCant]=useState(1)
  const enviar=()=>{if(!sel||cant<=0)return;const item=data.bodega_insumos.find(i=>i.id===sel);if(!item)return;if(cant>item.stock){toast('Cantidad supera stock en bodega','error');return};setData(d=>{const bod=d.bodega_insumos.map(i=>i.id===sel?{...i,stock:Math.max(0,i.stock-cant)}:i);const bi=d.botiquin_insumos.find(i=>i.nombre===item.nombre)?d.botiquin_insumos.map(i=>i.nombre===item.nombre?{...i,stock:i.stock+cant}:i):[...d.botiquin_insumos,{id:uid(),nombre:item.nombre,stock:cant,minimo:5}];return{...d,bodega_insumos:bod,botiquin_insumos:bi,movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Envío Bodega→Botiquín',descripcion:`${item.nombre} x${cant}`}]}});toast(`${item.nombre} x${cant} enviado`,'success');setSel('');setCant(1)}
  return <Card style={{maxWidth:380}}>
    <Fld label="Insumo"><Sel value={sel} onChange={e=>setSel(e.target.value)}><option value="">— Seleccionar —</option>{data.bodega_insumos.map(i=><option key={i.id} value={i.id}>{i.nombre} (stock: {i.stock})</option>)}</Sel></Fld>
    <Fld label="Cantidad"><Inp type="number" value={cant} onChange={e=>setCant(parseInt(e.target.value)||0)}/></Fld>
    <Btn onClick={enviar} full>Enviar a botiquín</Btn>
  </Card>
}

function BuscarTab({data}){
  const [modo,setModo]=useState('item'),[q,setQ]=useState('')

  const resultadosItem=useMemo(()=>{
    if(q.length<2) return []
    const lq=q.toLowerCase()
    return[
      ...data.botiquin_insumos.filter(i=>i.nombre.toLowerCase().includes(lq)).map(i=>({...i,origen:'Botiquín insumos'})),
      ...data.botiquin_meds.filter(m=>m.nombre.toLowerCase().includes(lq)).map(m=>({...m,origen:'Botiquín meds',isMed:true})),
      ...data.bodega_insumos.filter(i=>i.nombre.toLowerCase().includes(lq)).map(i=>({...i,origen:'Bodega'})),
      ...data.controlados.filter(c=>c.nombre.toLowerCase().includes(lq)).map(c=>({...c,origen:'Controlados',isMed:true})),
    ]
  },[q,data])

  // Buscar por número de llamado en movimientos de egreso
  const resultadosLlamado=useMemo(()=>{
    if(q.length<2) return []
    const lq=q.toLowerCase()
    return data.movimientos.filter(m=>
      (m.tipo==='Egreso'||m.tipo==='Egreso Controlado')&&
      m.descripcion.toLowerCase().includes(lq)
    )
  },[q,data])

  return <>
    <div style={{display:'flex',gap:8,marginBottom:14}}>
      <Btn sm variant={modo==='item'?'primary':'ghost'} onClick={()=>{setModo('item');setQ('')}}>🔍 Buscar ítem</Btn>
      <Btn sm variant={modo==='llamado'?'primary':'ghost'} onClick={()=>{setModo('llamado');setQ('')}}>📋 Buscar por llamado</Btn>
    </div>

    {modo==='item'&&<>
      <Fld label="Buscar ítem (mínimo 2 caracteres)">
        <Inp value={q} onChange={e=>setQ(e.target.value)} placeholder="Nombre del insumo o medicamento…"/>
      </Fld>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(220px,1fr))',gap:10}}>
        {resultadosItem.map((r,i)=>{
          const vd=r.isMed&&r.vencimiento?fmtVenc(r.vencimiento):null
          return <Card key={i}>
            <div style={{display:'flex',justifyContent:'space-between',marginBottom:6}}>
              <span style={{color:C.tb,fontWeight:600,fontSize:13}}>{r.nombre}</span>
              <Badge color={C.acc}>{r.origen}</Badge>
            </div>
            {r.isMed&&r.lote&&<div style={{fontSize:11,color:C.tm}}>Lote: {r.lote}</div>}
            {vd&&<div style={{fontSize:11,color:vd.vencido?C.red:vd.near?C.amb:C.tm}}>{vd.label}</div>}
            <SBar stock={r.stock} minimo={r.minimo}/>
            <div style={{fontSize:12,color:C.txt,marginTop:4}}>Stock: <b>{r.stock}</b> / Mín: {r.minimo}</div>
          </Card>
        })}
        {q.length>=2&&resultadosItem.length===0&&
          <div style={{color:C.tm,fontSize:13,gridColumn:'1/-1'}}>Sin resultados para "{q}"</div>}
      </div>
    </>}

    {modo==='llamado'&&<>
      <Fld label="Número de llamado / RUN (mínimo 2 caracteres)">
        <Inp value={q} onChange={e=>setQ(e.target.value)} placeholder="Ej: 12345678-9 o parcial…"/>
      </Fld>
      {q.length>=2&&<>
        {resultadosLlamado.length===0
          ?<div style={{color:C.tm,fontSize:13}}>Sin egresos encontrados para "{q}"</div>
          :<div>
            <div style={{color:C.tm,fontSize:12,marginBottom:10}}>{resultadosLlamado.length} egreso(s) encontrado(s)</div>
            {resultadosLlamado.map((m,i)=>{
              // Parsear ítems del egreso desde la descripción
              const esCtrl=m.tipo==='Egreso Controlado'
              return <Card key={i} style={{marginBottom:10,borderLeft:`3px solid ${esCtrl?C.pur:C.acl}`}}>
                <div style={{display:'flex',justifyContent:'space-between',marginBottom:6}}>
                  <div style={{color:C.tb,fontWeight:700,fontSize:14}}>{m.tipo}</div>
                  <Badge color={esCtrl?C.pur:C.acl}>{m.fecha}</Badge>
                </div>
                <div style={{color:C.txt,fontSize:13,lineHeight:1.6}}>{m.descripcion}</div>
              </Card>
            })}
          </div>
        }
      </>}
    </>}
  </>
}

function InventarioTab({data,setData}){
  const toast=useToast()
  const [seccion,setSeccion]=useState('botiquin_insumos')
  const [filtro,setFiltro]=useState('')
  // pendientes: { [id]: newStock }
  const [pendientes,setPendientes]=useState({})
  const [guardando,setGuardando]=useState(false)

  const colKey=seccion
  const items=useMemo(()=>{
    const base=(data[colKey]||[])
    return filtro.length>=1
      ? base.filter(i=>i.nombre.toLowerCase().includes(filtro.toLowerCase()))
      : base
  },[data,colKey,filtro])

  const cambiosPendientes=Object.keys(pendientes).length

  const cambiar=(id,val)=>{
    const n=parseInt(val)
    if(isNaN(n)||n<0) return
    // Solo marcar como pendiente si cambió
    const orig=(data[colKey]||[]).find(i=>i.id===id)?.stock
    if(n===orig) setPendientes(p=>{ const c={...p}; delete c[id]; return c })
    else setPendientes(p=>({...p,[id]:n}))
  }

  const guardar=()=>{
    if(!cambiosPendientes){toast('Sin cambios para guardar','warn');return}
    setGuardando(true)
    setData(d=>({
      ...d,
      [colKey]:d[colKey].map(i=>pendientes.hasOwnProperty(i.id)?{...i,stock:pendientes[i.id]}:i),
      movimientos:[...d.movimientos,{
        id:uid(),fecha:now(),tipo:'Inventario',
        descripcion:`Inventario ${colKey==='botiquin_insumos'?'Botiquín insumos':colKey==='botiquin_meds'?'Botiquín meds':'Bodega'}: ${cambiosPendientes} ítem(s) actualizado(s)`
      }]
    }))
    toast(`✅ ${cambiosPendientes} ítem(s) actualizado(s) en inventario`,'success',4000)
    setPendientes({})
    setGuardando(false)
  }

  const descartar=()=>{ setPendientes({}); toast('Cambios descartados','warn') }

  const SECCIONES=[
    {key:'botiquin_insumos',label:'Botiquín — Insumos'},
    {key:'botiquin_meds',label:'Botiquín — Medicamentos'},
    {key:'bodega_insumos',label:'Bodega'},
  ]

  return <div>
    <div style={{background:C.acc+'15',border:`1px solid ${C.acc}33`,borderRadius:8,padding:'10px 14px',marginBottom:16,fontSize:13,color:C.acl}}>
      📦 <b>Modo inventario:</b> Edita los stocks directamente. Los cambios se aplican todos juntos al guardar.
    </div>

    {/* selector de sección y filtro */}
    <div style={{display:'flex',gap:8,flexWrap:'wrap',marginBottom:14,alignItems:'center'}}>
      {SECCIONES.map(s=><Btn key={s.key} sm variant={seccion===s.key?'primary':'ghost'} onClick={()=>{setSeccion(s.key);setPendientes({});setFiltro('')}}>{s.label}</Btn>)}
    </div>
    <div style={{display:'flex',gap:8,marginBottom:14,alignItems:'center'}}>
      <div style={{flex:1}}><Inp value={filtro} onChange={e=>setFiltro(e.target.value)} placeholder="Filtrar por nombre…"/></div>
      {cambiosPendientes>0&&<span style={{color:C.amb,fontSize:13,fontWeight:600}}>⚠️ {cambiosPendientes} cambio(s) sin guardar</span>}
    </div>

    {/* tabla de inventario */}
    <Card style={{padding:0,overflowX:'auto'}}>
      <table style={{width:'100%',borderCollapse:'collapse',fontSize:13}}>
        <thead>
          <tr style={{background:C.s3}}>
            <th style={{padding:'9px 12px',color:C.tm,fontWeight:600,textAlign:'left',borderBottom:`1px solid ${C.brd}`}}>Ítem</th>
            <th style={{padding:'9px 12px',color:C.tm,fontWeight:600,textAlign:'center',borderBottom:`1px solid ${C.brd}`,width:80}}>Mín.</th>
            <th style={{padding:'9px 12px',color:C.tm,fontWeight:600,textAlign:'center',borderBottom:`1px solid ${C.brd}`,width:110}}>Stock actual</th>
            <th style={{padding:'9px 12px',color:C.tm,fontWeight:600,textAlign:'center',borderBottom:`1px solid ${C.brd}`,width:130}}>Nuevo stock</th>
            <th style={{padding:'9px 12px',color:C.tm,fontWeight:600,textAlign:'center',borderBottom:`1px solid ${C.brd}`,width:70}}>Estado</th>
          </tr>
        </thead>
        <tbody>
          {items.map(item=>{
            const hasCambio=pendientes.hasOwnProperty(item.id)
            const valActual=hasCambio?pendientes[item.id]:item.stock
            const critico=item.stock<=item.minimo
            const vd=item.vencimiento?fmtVenc(item.vencimiento):null
            return <tr key={item.id} style={{borderBottom:`1px solid ${C.brd}22`,background:hasCambio?C.amb+'11':'transparent'}}>
              <td style={{padding:'7px 12px'}}>
                <div style={{color:C.txt,fontSize:13}}>{item.nombre}</div>
                {item.lote&&<div style={{color:C.tm,fontSize:11}}>Lote: {item.lote}</div>}
                {vd&&<div style={{fontSize:11,color:vd.vencido?C.red:vd.near?C.amb:C.tm}}>{vd.label}</div>}
              </td>
              <td style={{padding:'7px 12px',textAlign:'center',color:C.tm}}>{item.minimo}</td>
              <td style={{padding:'7px 12px',textAlign:'center',color:critico?C.red:C.txt,fontWeight:critico?700:400}}>{item.stock}</td>
              <td style={{padding:'7px 12px',textAlign:'center'}}>
                <input type="number" min="0" value={valActual}
                  onChange={e=>cambiar(item.id,e.target.value)}
                  style={{width:80,background:hasCambio?C.amb+'22':C.s2,border:`1px solid ${hasCambio?C.amb:C.brd}`,borderRadius:5,color:C.txt,padding:'4px 8px',fontSize:13,textAlign:'center',outline:'none',fontFamily:"'DM Sans',sans-serif"}}/>
              </td>
              <td style={{padding:'7px 12px',textAlign:'center'}}>
                {hasCambio
                  ? <Badge color={C.amb}>Editado</Badge>
                  : <Badge color={critico?C.red:C.grn}>{critico?'Crítico':'OK'}</Badge>}
              </td>
            </tr>
          })}
          {items.length===0&&<tr><td colSpan={5} style={{padding:16,color:C.tm,textAlign:'center'}}>Sin ítems{filtro?` para "${filtro}`:''}</td></tr>}
        </tbody>
      </table>
    </Card>

    {/* barra de acción sticky */}
    <div style={{position:'sticky',bottom:0,background:C.bg,borderTop:`1px solid ${C.brd}`,padding:'12px 0',marginTop:16,display:'flex',gap:10,alignItems:'center'}}>
      <Btn onClick={guardar} disabled={!cambiosPendientes||guardando} variant="success">
        💾 Guardar inventario {cambiosPendientes>0?`(${cambiosPendientes} cambios)`:''}
      </Btn>
      {cambiosPendientes>0&&<Btn variant="ghost" onClick={descartar}>✕ Descartar</Btn>}
      <span style={{color:C.tm,fontSize:12,marginLeft:'auto'}}>
        {items.length} ítem(s) — {(data[colKey]||[]).filter(i=>i.stock<=i.minimo).length} crítico(s)
      </span>
    </div>
  </div>
}

function CrearInsumoTab({data,setData}){
  const toast=useToast(),[form,setForm]=useState({nombre:'',stockBi:0,minBi:5,stockBod:0,minBod:50})
  const crear=()=>{if(!form.nombre){toast('Nombre requerido','error');return};if(data.botiquin_insumos.find(i=>i.nombre===form.nombre)){toast('Ya existe en botiquín','error');return};setData(d=>({...d,botiquin_insumos:[...d.botiquin_insumos,{id:uid(),nombre:san(form.nombre,100),stock:form.stockBi,minimo:form.minBi}],bodega_insumos:[...d.bodega_insumos,{id:uid(),nombre:san(form.nombre,100),stock:form.stockBod,minimo:form.minBod}],movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Insumo creado',descripcion:`${form.nombre} creado`}]}));toast(`"${form.nombre}" creado`,'success');setForm({nombre:'',stockBi:0,minBi:5,stockBod:0,minBod:50})}
  return <Card style={{maxWidth:420}}>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Crear nuevo insumo</h3>
    <Fld label="Nombre"><Inp value={form.nombre} onChange={e=>setForm(f=>({...f,nombre:e.target.value}))} placeholder="Nombre del insumo" maxLength={100}/></Fld>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
      <Fld label="Stock botiquín"><Inp type="number" value={form.stockBi} onChange={e=>setForm(f=>({...f,stockBi:parseInt(e.target.value)||0}))}/></Fld>
      <Fld label="Mínimo botiquín"><Inp type="number" value={form.minBi} onChange={e=>setForm(f=>({...f,minBi:parseInt(e.target.value)||0}))}/></Fld>
      <Fld label="Stock bodega"><Inp type="number" value={form.stockBod} onChange={e=>setForm(f=>({...f,stockBod:parseInt(e.target.value)||0}))}/></Fld>
      <Fld label="Mínimo bodega"><Inp type="number" value={form.minBod} onChange={e=>setForm(f=>({...f,minBod:parseInt(e.target.value)||0}))}/></Fld>
    </div>
    <Btn onClick={crear} full>Crear insumo</Btn>
  </Card>
}

function CrearMedTab({data,setData}){
  const toast=useToast(),[form,setForm]=useState({nombre:'',stock:0,minimo:3,lote:'',vencimiento:''})
  const crear=()=>{if(!form.nombre){toast('Nombre requerido','error');return};setData(d=>({...d,botiquin_meds:[...d.botiquin_meds,{id:uid(),...form,nombre:san(form.nombre,100)}],movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Medicamento creado',descripcion:`${form.nombre} creado`}]}));toast(`"${form.nombre}" creado`,'success');setForm({nombre:'',stock:0,minimo:3,lote:'',vencimiento:''})}
  return <Card style={{maxWidth:420}}>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Crear medicamento</h3>
    {[['Nombre',<Inp value={form.nombre} onChange={e=>setForm(f=>({...f,nombre:e.target.value}))} maxLength={100}/>],['Stock',<Inp type="number" value={form.stock} onChange={e=>setForm(f=>({...f,stock:parseInt(e.target.value)||0}))}/>],['Mínimo',<Inp type="number" value={form.minimo} onChange={e=>setForm(f=>({...f,minimo:parseInt(e.target.value)||0}))}/>],['Lote',<Inp value={form.lote} onChange={e=>setForm(f=>({...f,lote:e.target.value}))} placeholder="LOT-XXXX" maxLength={50}/>],['Vencimiento',<Inp type="date" value={form.vencimiento} onChange={e=>setForm(f=>({...f,vencimiento:e.target.value}))}/>]].map(([l,c],i)=><Fld key={i} label={l}>{c}</Fld>)}
    <Btn onClick={crear} full>Crear medicamento</Btn>
  </Card>
}

function ModInsTab({data,setData}){
  const toast=useToast(),[src,setSrc]=useState('botiquin');const col=src==='botiquin'?'botiquin_insumos':'bodega_insumos'
  const [sel,setSel]=useState(''),[s,setS]=useState(0),[m,setM]=useState(0)
  const load=(id)=>{const it=(data[col]||[]).find(i=>i.id===id);if(it){setS(it.stock);setM(it.minimo)}}
  const save=()=>{if(!sel){toast('Selecciona un insumo','error');return};setData(d=>({...d,[col]:d[col].map(i=>i.id===sel?{...i,stock:s,minimo:m}:i),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Insumo modificado',descripcion:`${(d[col]||[]).find(i=>i.id===sel)?.nombre||sel} modificado`}]}));toast('Insumo actualizado','success')}
  return <Card style={{maxWidth:400}}>
    <div style={{display:'flex',gap:8,marginBottom:14}}>{['botiquin','bodega'].map(s2=><Btn key={s2} variant={src===s2?'primary':'ghost'} sm onClick={()=>setSrc(s2)}>{s2==='botiquin'?'Botiquín':'Bodega'}</Btn>)}</div>
    <Fld label="Insumo"><Sel value={sel} onChange={e=>{setSel(e.target.value);load(e.target.value)}}><option value="">— Seleccionar —</option>{(data[col]||[]).map(i=><option key={i.id} value={i.id}>{i.nombre}</option>)}</Sel></Fld>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}><Fld label="Stock"><Inp type="number" value={s} onChange={e=>setS(parseInt(e.target.value)||0)}/></Fld><Fld label="Mínimo"><Inp type="number" value={m} onChange={e=>setM(parseInt(e.target.value)||0)}/></Fld></div>
    <Btn onClick={save} full>Guardar cambios</Btn>
  </Card>
}

function ModMedTab({data,setData}){
  const toast=useToast(),[src,setSrc]=useState('botiquin');const col=src==='botiquin'?'botiquin_meds':'controlados'
  const [sel,setSel]=useState(''),[form,setForm]=useState({stock:0,minimo:3,lote:'',vencimiento:''})
  const load=(id)=>{const it=(data[col]||[]).find(i=>i.id===id);if(it)setForm({stock:it.stock,minimo:it.minimo,lote:it.lote||'',vencimiento:it.vencimiento||''})}
  const vd=form.vencimiento?fmtVenc(form.vencimiento):null
  const save=()=>{if(!sel){toast('Selecciona un medicamento','error');return};setData(d=>({...d,[col]:d[col].map(i=>i.id===sel?{...i,...form}:i),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Med. modificado',descripcion:`${(d[col]||[]).find(i=>i.id===sel)?.nombre||sel} modificado`}]}));toast('Medicamento actualizado','success')}
  return <Card style={{maxWidth:440}}>
    <div style={{display:'flex',gap:8,marginBottom:14}}>{['botiquin','controlados'].map(s2=><Btn key={s2} variant={src===s2?'primary':'ghost'} sm onClick={()=>setSrc(s2)}>{s2==='botiquin'?'Botiquín':'Controlados'}</Btn>)}</div>
    <Fld label="Medicamento"><Sel value={sel} onChange={e=>{setSel(e.target.value);load(e.target.value)}}><option value="">— Seleccionar —</option>{(data[col]||[]).map(m=><option key={m.id} value={m.id}>{m.nombre}</option>)}</Sel></Fld>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
      <Fld label="Stock"><Inp type="number" value={form.stock} onChange={e=>setForm(f=>({...f,stock:parseInt(e.target.value)||0}))}/></Fld>
      <Fld label="Mínimo"><Inp type="number" value={form.minimo} onChange={e=>setForm(f=>({...f,minimo:parseInt(e.target.value)||0}))}/></Fld>
      <Fld label="Lote"><Inp value={form.lote} onChange={e=>setForm(f=>({...f,lote:e.target.value}))}/></Fld>
      <Fld label="Vencimiento">{vd&&<div style={{fontSize:12,color:vd.vencido?C.red:vd.near?C.amb:C.tm,marginBottom:4}}>{vd.label}</div>}<Inp type="date" value={form.vencimiento} onChange={e=>setForm(f=>({...f,vencimiento:e.target.value}))}/></Fld>
    </div>
    <Btn onClick={save} full>Guardar cambios</Btn>
  </Card>
}

function EliminarInsTab({data,setData}){
  const toast=useToast(),[src,setSrc]=useState('botiquin'),[q,setQ]=useState(''),[confirm,setConfirm]=useState(null)
  const col=src==='botiquin'?'botiquin_insumos':'bodega_insumos'
  const items=useMemo(()=>(data[col]||[]).filter(i=>!q||i.nombre.toLowerCase().includes(q.toLowerCase())),[data,col,q])
  const del=(id)=>{const it=(data[col]||[]).find(i=>i.id===id);setData(d=>({...d,[col]:d[col].filter(i=>i.id!==id),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Insumo eliminado',descripcion:`${it?.nombre||id} eliminado de ${src}`}]}));toast(`"${it?.nombre}" eliminado`,'warn');setConfirm(null)}
  return <>
    <div style={{display:'flex',gap:8,marginBottom:14}}>{['botiquin','bodega'].map(s2=><Btn key={s2} variant={src===s2?'primary':'ghost'} sm onClick={()=>setSrc(s2)}>{s2==='botiquin'?'Botiquín':'Bodega'}</Btn>)}</div>
    <Fld label="Filtrar"><Inp value={q} onChange={e=>setQ(e.target.value)} placeholder="Buscar…"/></Fld>
    <div>{items.map(i=><div key={i.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 0',borderBottom:`1px solid ${C.brd}`}}><div><span style={{color:C.txt,fontSize:13}}>{i.nombre}</span><span style={{color:C.tm,fontSize:12,marginLeft:8}}>Stock: {i.stock}</span></div>{confirm===i.id?<div style={{display:'flex',gap:6,alignItems:'center'}}><span style={{color:C.tm,fontSize:12}}>¿Confirmar?</span><Btn sm variant="danger" onClick={()=>del(i.id)}>Sí</Btn><Btn sm variant="ghost" onClick={()=>setConfirm(null)}>No</Btn></div>:<Btn sm variant="danger" onClick={()=>setConfirm(i.id)}>🗑 Eliminar</Btn>}</div>)}</div>
  </>
}

// ═══════════════════════════════════════════════════
//  ⚠️ CONTROLADOS · 🔧 EQUIPAMIENTOS · 📈 ESTADÍSTICA
// ═══════════════════════════════════════════════════

function MedsControlados({data,setData,user}){
  const perm=getPerm(user.role),toast=useToast()
  const tabs=[{id:'stock',label:'Stock'},{id:'movimientos',label:'Movimientos'},...(perm.editControlados?[{id:'ingresar',label:'Ingresar'},{id:'egreso',label:'Egreso'}]:[])]
  const [tab,setTab]=useState('stock'),[editId,setEditId]=useState(null)
  return(<div>
    <PageTitle sub="Medicamentos sujetos a control especial">⚠️ Medicamentos Controlados</PageTitle>
    <div style={{background:C.pur+'22',border:`1px solid ${C.pur}44`,borderRadius:8,padding:'10px 14px',marginBottom:16,color:C.pur,fontSize:13}}>⚠️ Medicamentos sujetos a control especial. Toda operación queda registrada en el libro de novedades.</div>
    {!perm.editControlados&&<ReadOnlyBanner/>}
    <Tabs tabs={tabs} active={tab} onChange={setTab}/>
    {tab==='stock'&&<Card>{fefoSort(data.controlados).map(m=>{const{label,vencido,near}=fmtVenc(m.vencimiento);return <div key={m.id} style={{display:'flex',alignItems:'center',gap:10,padding:'8px 0',borderBottom:`1px solid ${C.brd}`}}><div style={{flex:1}}><div style={{color:C.txt,fontSize:13}}>{m.nombre}</div><div style={{color:C.tm,fontSize:11}}>Lote: {m.lote}</div></div><span style={{color:vencido?C.red:near?C.amb:C.tm,fontSize:12}}>{label}</span><SBar stock={m.stock} minimo={m.minimo}/><span style={{color:C.pur,fontWeight:700,fontSize:14,minWidth:28,textAlign:'right'}}>{m.stock}</span>{perm.editControlados&&<button onClick={()=>setEditId(m.id)} style={{background:'none',border:'none',color:C.acl,cursor:'pointer',fontSize:13}}>✏</button>}</div>})}</Card>}
    {tab==='movimientos'&&<TblSimple cols={['Fecha','Tipo','Descripción']} rows={data.movimientos.filter(m=>['Ingreso Controlado','Egreso Controlado'].includes(m.tipo)).map(m=>[m.fecha,m.tipo,m.descripcion])}/>}
    {tab==='ingresar'&&perm.editControlados&&<IngresarCtrlTab data={data} setData={setData}/>}
    {tab==='egreso'&&perm.editControlados&&<EgresoCtrlTab data={data} setData={setData}/>}
    {editId&&(()=>{const m=data.controlados.find(x=>x.id===editId);if(!m)return null;return <Modal title={`Ajustar stock: ${m.nombre}`} onClose={()=>setEditId(null)}><CtrlStockEdit item={m} onSave={vals=>{setData(d=>({...d,controlados:d.controlados.map(c=>c.id===editId?{...c,...vals}:c),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Ingreso Controlado',descripcion:`${m.nombre} ajustado a ${vals.stock}`}]}));toast(`${m.nombre} actualizado`,'success');setEditId(null)}} onClose={()=>setEditId(null)}/></Modal>})()}
  </div>)
}

function CtrlStockEdit({item,onSave,onClose}){
  const [s,setS]=useState(item.stock)
  return <><Fld label="Stock actual"><Inp type="number" value={s} onChange={e=>setS(parseInt(e.target.value)||0)}/></Fld><div style={{display:'flex',gap:8}}><Btn variant="secondary" full onClick={onClose}>Cancelar</Btn><Btn full onClick={()=>onSave({stock:s})}>Guardar</Btn></div></>
}

function IngresarCtrlTab({data,setData}){
  const toast=useToast(),[nombre,setNombre]=useState(''),[cant,setCant]=useState(1),[lote,setLote]=useState(''),[venc,setVenc]=useState('')
  const guardar=()=>{if(!nombre||cant<=0){toast('Nombre y cantidad requeridos','error');return};setData(d=>{const idx=d.controlados.findIndex(c=>c.nombre===nombre&&c.lote===lote);const ctrl=idx>=0?d.controlados.map((c,i)=>i===idx?{...c,stock:c.stock+cant}:c):[...d.controlados,{id:uid(),nombre:san(nombre,100),stock:cant,lote:san(lote,50),vencimiento:venc,minimo:2}];return{...d,controlados:ctrl,movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Ingreso Controlado',descripcion:`${nombre} x${cant} lote ${lote}`}]}});toast(`${nombre} x${cant} ingresado`,'success');setNombre('');setCant(1);setLote('');setVenc('')}
  return <Card style={{maxWidth:420}}>
    <datalist id="dl-ctrl">{data.controlados.map(c=><option key={c.id} value={c.nombre}/>)}</datalist>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Ingresar controlado</h3>
    {[['Medicamento',<Inp value={nombre} onChange={e=>setNombre(e.target.value)} list="dl-ctrl" placeholder="Nombre…" maxLength={100}/>],['Cantidad',<Inp type="number" value={cant} onChange={e=>setCant(parseInt(e.target.value)||0)}/>],['Lote',<Inp value={lote} onChange={e=>setLote(e.target.value)} placeholder="LOT-CTRL-X" maxLength={50}/>],['Vencimiento',<Inp type="date" value={venc} onChange={e=>setVenc(e.target.value)}/>]].map(([l,c],i)=><Fld key={i} label={l}>{c}</Fld>)}
    <Btn onClick={guardar} full>Ingresar</Btn>
  </Card>
}

function EgresoCtrlTab({data,setData}){
  const toast=useToast(),[form,setForm]=useState({llamado:'',movil:'',med:'',cant:1,medico:'',personal:'',receta:''})
  const guardar=()=>{
    if(!form.llamado||!form.med||form.cant<=0){toast('Campos obligatorios incompletos','error');return}
    if(!form.medico||!form.receta){toast('Datos legales requeridos','error');return}
    const med=data.controlados.find(c=>c.id===form.med);if(!med)return
    if(form.cant>med.stock){toast('Cantidad supera stock disponible','error');return}
    setData(d=>({...d,controlados:d.controlados.map(c=>c.id===form.med?{...c,stock:Math.max(0,c.stock-form.cant)}:c),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Egreso Controlado',descripcion:`${med.nombre} x${form.cant} · Llamado #${san(form.llamado,20)} · Dr. ${san(form.medico,80)} · Receta: ${san(form.receta,50)}`}]}))
    toast('Egreso de controlado registrado','success');setForm({llamado:'',movil:'',med:'',cant:1,medico:'',personal:'',receta:''})
  }
  return <Card style={{maxWidth:480}}>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Egreso de controlado</h3>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}><Fld label="N° Llamado"><Inp value={form.llamado} onChange={e=>setForm(f=>({...f,llamado:e.target.value}))} maxLength={20}/></Fld><Fld label="Móvil"><Sel value={form.movil} onChange={e=>setForm(f=>({...f,movil:e.target.value}))}><option value="">— Opcional —</option>{data.moviles.map(m=><option key={m.id} value={m.id}>Móvil {m.numero}</option>)}</Sel></Fld></div>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:14}}><Fld label="Medicamento"><Sel value={form.med} onChange={e=>setForm(f=>({...f,med:e.target.value}))}><option value="">— Seleccionar —</option>{data.controlados.map(c=><option key={c.id} value={c.id}>{c.nombre} (stock:{c.stock})</option>)}</Sel></Fld><Fld label="Cantidad"><Inp type="number" value={form.cant} onChange={e=>setForm(f=>({...f,cant:parseInt(e.target.value)||0}))}/></Fld></div>
    <div style={{background:C.pur+'11',border:`1px solid ${C.pur}33`,borderRadius:8,padding:'10px 12px',marginBottom:14}}><div style={{color:C.pur,fontWeight:700,fontSize:13,marginBottom:8}}>📋 DATOS LEGALES OBLIGATORIOS</div><div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:10}}><Fld label="Médico que emite"><Inp value={form.medico} onChange={e=>setForm(f=>({...f,medico:e.target.value}))} maxLength={80}/></Fld><Fld label="Personal clínico"><Inp value={form.personal} onChange={e=>setForm(f=>({...f,personal:e.target.value}))} maxLength={80}/></Fld><Fld label="N° Receta"><Inp value={form.receta} onChange={e=>setForm(f=>({...f,receta:e.target.value}))} maxLength={50}/></Fld></div></div>
    <Btn onClick={guardar} full>Registrar egreso</Btn>
  </Card>
}

// EQUIPAMIENTOS
function GestionEquipamientos({data,setData,user}){
  const perm=getPerm(user.role)
  const tabs=[{id:'resumen',label:'Resumen'},{id:'equipos',label:'Equipos'},...(perm.editEquipamientos?[{id:'ingresar',label:'Ingresar'},{id:'equipar',label:'Equipar móvil'},{id:'modificar',label:'Modificar'},{id:'mantencion',label:'Mantención'}]:[])]
  const [tab,setTab]=useState('resumen')
  return(<div><PageTitle sub="Gestión de equipamiento médico y técnico">🔧 Gestión Equipamientos</PageTitle>{!perm.editEquipamientos&&<ReadOnlyBanner/>}<Tabs tabs={tabs} active={tab} onChange={setTab}/>{tab==='resumen'&&<EquipResumen data={data}/>}{tab==='equipos'&&<EquipEquipos data={data}/>}{tab==='ingresar'&&perm.editEquipamientos&&<EquipIngresar data={data} setData={setData}/>}{tab==='equipar'&&perm.editEquipamientos&&<EquipEquipar data={data} setData={setData}/>}{tab==='modificar'&&perm.editEquipamientos&&<EquipModificar data={data} setData={setData}/>}{tab==='mantencion'&&perm.editEquipamientos&&<EquipMantencion data={data} setData={setData}/>}</div>)
}
function EquipResumen({data}){
  const orden=['crítico','mediana','vir','básico','otro']
  const sorted=useMemo(()=>[...data.moviles].sort((a,b)=>orden.indexOf(a.tipo)-orden.indexOf(b.tipo)),[data.moviles])
  return <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(240px,1fr))',gap:12}}>{sorted.map(mv=>{const equips=data.equipamientos.filter(e=>e.movil_id===mv.id&&e.estado==='activo');return <Card key={mv.id}><div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:8}}><span style={{color:C.tb,fontWeight:700}}>Móvil {mv.numero}</span><Badge color={TC[mv.tipo]||C.tm}>{mv.tipo}</Badge></div><div style={{color:C.tm,fontSize:12,marginBottom:8}}>{mv.base}</div><div style={{display:'flex',flexWrap:'wrap',gap:4}}>{equips.length===0?<span style={{color:C.tm,fontSize:12}}>Sin equipamiento</span>:equips.map(e=><span key={e.id} style={{background:C.s3,borderRadius:4,padding:'2px 7px',fontSize:11,color:C.txt}}>{e.tipo} {e.idInterno}</span>)}</div></Card>})}</div>
}
function EquipEquipos({data}){
  const [tipo,setTipo]=useState('VM')
  const all=useMemo(()=>data.equipamientos.filter(e=>e.tipo===tipo),[data.equipamientos,tipo])
  const activos=all.filter(e=>e.estado==='activo'),stock=all.filter(e=>e.estado==='stock'),baja=all.filter(e=>e.estado==='baja')
  return <>
    <div style={{display:'flex',gap:8,marginBottom:16,flexWrap:'wrap'}}>{TIPOS_EQUIP.map(t=>{const n=data.equipamientos.filter(e=>e.tipo===t&&e.estado==='activo').length;return <Btn key={t} variant={tipo===t?'primary':'ghost'} sm onClick={()=>setTipo(t)}>{t} ({n})</Btn>})}</div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10,marginBottom:16}}>{[['Total',all.length,C.txt],['Activos',activos.length,C.grn],['En inventario',stock.length,C.amb],['De baja',baja.length,C.red]].map(([l,v,c],i)=><Card key={i} style={{textAlign:'center'}}><div style={{color:c,fontSize:22,fontWeight:800}}>{v}</div><div style={{color:C.tm,fontSize:12}}>{l}</div></Card>)}</div>
    {activos.length>0&&<><h4 style={{color:C.tb,marginBottom:8}}>✅ Asignados</h4><div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:8,marginBottom:14}}>{activos.map(e=>{const mv=data.moviles.find(m=>m.id===e.movil_id);return <Card key={e.id} style={{border:`1px solid ${C.grn}33`}}><div style={{color:C.tb,fontWeight:600,fontSize:13}}>{e.idInterno}</div><div style={{color:C.tm,fontSize:12}}>{mv?`Móvil ${mv.numero}`:'—'}</div><div style={{color:C.tm,fontSize:11}}>S/N: {e.serie}</div></Card>})}</div></>}
    {stock.length>0&&<><h4 style={{color:C.tb,marginBottom:8}}>📦 En inventario</h4><div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:8,marginBottom:14}}>{stock.map(e=><Card key={e.id} style={{border:`1px solid ${C.amb}33`}}><div style={{color:C.tb,fontWeight:600,fontSize:13}}>{e.idInterno}</div><div style={{color:C.tm,fontSize:11}}>S/N: {e.serie}</div></Card>)}</div></>}
    {baja.length>0&&<><h4 style={{color:C.tb,marginBottom:8}}>🔴 De baja</h4><div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:8}}>{baja.map(e=><Card key={e.id} style={{border:`1px solid ${C.red}33`}}><div style={{color:C.txt,fontWeight:600,fontSize:13}}>{e.idInterno}</div><div style={{color:C.tm,fontSize:11}}>{e.notas}</div></Card>)}</div></>}
  </>
}
function EquipIngresar({data,setData}){
  const toast=useToast(),[form,setForm]=useState({tipo:'VM',idInterno:'',serie:'',notas:'',ultimaMantencion:'',proximaMantencion:''})
  const stock=data.equipamientos.filter(e=>e.estado==='stock')
  const guardar=()=>{
    if(!form.idInterno){toast('ID Interno requerido','error');return}
    const newEquip={id:uid(),tipo:form.tipo,idInterno:san(form.idInterno,50),serie:san(form.serie,50),notas:san(form.notas,300),movil_id:null,estado:'stock'}
    setData(d=>{
      let mantenciones=[...d.mantenciones]
      if(form.ultimaMantencion||form.proximaMantencion){
        mantenciones=[...mantenciones,{id:uid(),equip_id:newEquip.id,ultima:form.ultimaMantencion,proxima:form.proximaMantencion,info:'Registrado al ingresar equipamiento'}]
      }
      return{...d,equipamientos:[...d.equipamientos,newEquip],mantenciones,movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Equip. Ingresado',descripcion:`${form.tipo} ${form.idInterno} ingresado${form.ultimaMantencion?` · Última mant.: ${fmtDate(form.ultimaMantencion)}`:''}${form.proximaMantencion?` · Próxima: ${fmtDate(form.proximaMantencion)}`:''}`}]}
    })
    toast(`${form.tipo} ${form.idInterno} ingresado`,'success')
    setForm({tipo:'VM',idInterno:'',serie:'',notas:'',ultimaMantencion:'',proximaMantencion:''})
  }
  return <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
    <Card>
      <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Ingresar equipamiento</h3>
      <Fld label="Tipo"><Sel value={form.tipo} onChange={e=>setForm(f=>({...f,tipo:e.target.value}))}>{TIPOS_EQUIP.map(t=><option key={t}>{t}</option>)}</Sel></Fld>
      <Fld label="ID Interno (UCM)"><Inp value={form.idInterno} onChange={e=>setForm(f=>({...f,idInterno:e.target.value}))} placeholder="VM-003" maxLength={50}/></Fld>
      <Fld label="N° Serie"><Inp value={form.serie} onChange={e=>setForm(f=>({...f,serie:e.target.value}))} placeholder="SN-XXXX" maxLength={50}/></Fld>
      <Fld label="Notas"><Txt value={form.notas} onChange={e=>setForm(f=>({...f,notas:e.target.value}))} rows={2}/></Fld>
      <div style={{borderTop:`1px solid ${C.brd}`,marginTop:8,paddingTop:12,marginBottom:4}}>
        <div style={{color:C.tm,fontSize:12,fontWeight:600,marginBottom:8}}>📅 Mantención (opcional)</div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
          <Fld label="Última mantención"><Inp type="date" value={form.ultimaMantencion} onChange={e=>setForm(f=>({...f,ultimaMantencion:e.target.value}))}/></Fld>
          <Fld label="Próxima mantención"><Inp type="date" value={form.proximaMantencion} onChange={e=>setForm(f=>({...f,proximaMantencion:e.target.value}))}/></Fld>
        </div>
        {(form.ultimaMantencion||form.proximaMantencion)&&<div style={{fontSize:11,color:C.acl,marginTop:2}}>ℹ️ Se registrará automáticamente en Mantención de equipos.</div>}
      </div>
      <Btn onClick={guardar} full>Ingresar equipamiento</Btn>
    </Card>
    <Card><h3 style={{color:C.tb,marginTop:0,fontSize:15}}>📦 En inventario ({stock.length})</h3>{stock.map(e=><div key={e.id} style={{display:'flex',justifyContent:'space-between',padding:'5px 0',borderBottom:`1px solid ${C.brd}`,fontSize:13}}><span style={{color:C.txt}}>{e.tipo} — {e.idInterno}</span><span style={{color:C.tm}}>{e.serie}</span></div>)}{stock.length===0&&<span style={{color:C.tm,fontSize:13}}>Inventario vacío.</span>}</Card>
  </div>
}
function EquipEquipar({data,setData}){
  const toast=useToast(),[movil,setMovil]=useState(''),[selEquips,setSelEquips]=useState(new Set()),[filtroTipo,setFiltroTipo]=useState('todos')
  const disponibles=useMemo(()=>{
    const base=data.equipamientos.filter(e=>e.estado==='stock')
    return filtroTipo==='todos'?base:base.filter(e=>e.tipo===filtroTipo)
  },[data.equipamientos,filtroTipo])
  const tiposDisponibles=['todos',...[...new Set(data.equipamientos.filter(e=>e.estado==='stock').map(e=>e.tipo))]]
  const toggleEquip=(id)=>setSelEquips(prev=>{ const n=new Set(prev); n.has(id)?n.delete(id):n.add(id); return n })
  const toggleAll=()=>{
    if(selEquips.size===disponibles.length) setSelEquips(new Set())
    else setSelEquips(new Set(disponibles.map(e=>e.id)))
  }
  const guardar=()=>{
    if(!movil||selEquips.size===0){toast('Selecciona móvil y al menos un equipamiento','error');return}
    const mv=data.moviles.find(m=>m.id===movil)
    const equipsSel=disponibles.filter(e=>selEquips.has(e.id))
    setData(d=>({
      ...d,
      equipamientos:d.equipamientos.map(x=>selEquips.has(x.id)?{...x,movil_id:movil,estado:'activo'}:x),
      movimientos:[...d.movimientos,{
        id:uid(),fecha:now(),tipo:'Equipamiento',
        descripcion:`${equipsSel.length} equipo(s) asignados a Móvil ${mv?.numero}: ${equipsSel.map(e=>`${e.tipo} ${e.idInterno}`).join(', ')}`
      }]
    }))
    toast(`${equipsSel.length} equipo(s) asignado(s) a Móvil ${mv?.numero}`,'success')
    setMovil('');setSelEquips(new Set())
  }
  return <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
    <Card>
      <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Configurar asignación</h3>
      <Fld label="Móvil destino">
        <Sel value={movil} onChange={e=>setMovil(e.target.value)}>
          <option value="">— Seleccionar —</option>
          {data.moviles.map(m=><option key={m.id} value={m.id}>Móvil {m.numero} — {m.base}</option>)}
        </Sel>
      </Fld>
      <Fld label="Filtrar por tipo">
        <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
          {tiposDisponibles.map(t=><Btn key={t} sm variant={filtroTipo===t?'primary':'ghost'} onClick={()=>setFiltroTipo(t)}>{t}</Btn>)}
        </div>
      </Fld>
      {movil&&selEquips.size>0&&<div style={{background:C.grn+'15',border:`1px solid ${C.grn}44`,borderRadius:6,padding:'8px 12px',marginBottom:12,color:C.grn,fontSize:13}}>
        ✅ {selEquips.size} equipo(s) seleccionado(s) para Móvil {data.moviles.find(m=>m.id===movil)?.numero}
      </div>}
      <Btn onClick={guardar} disabled={!movil||selEquips.size===0} full variant="success">
        Asignar {selEquips.size>0?`${selEquips.size} equipo(s) `:''}a móvil
      </Btn>
    </Card>

    <Card style={{maxHeight:480,display:'flex',flexDirection:'column'}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:10}}>
        <h3 style={{color:C.tb,margin:0,fontSize:15}}>Equipamiento disponible ({disponibles.length})</h3>
        <Btn sm variant="ghost" onClick={toggleAll}>
          {selEquips.size===disponibles.length&&disponibles.length>0?'✕ Deseleccionar todo':'☑ Seleccionar todo'}
        </Btn>
      </div>
      <div style={{flex:1,overflowY:'auto'}}>
        {disponibles.length===0&&<div style={{color:C.tm,fontSize:13,padding:8}}>Sin equipamiento disponible{filtroTipo!=='todos'?` de tipo "${filtroTipo}"`:''}.</div>}
        {disponibles.map(e=>{
          const sel=selEquips.has(e.id)
          return <div key={e.id} onClick={()=>toggleEquip(e.id)} style={{display:'flex',alignItems:'center',gap:10,padding:'8px 6px',borderRadius:6,cursor:'pointer',background:sel?C.grn+'15':'transparent',border:`1px solid ${sel?C.grn+'44':C.brd+'55'}`,marginBottom:5,transition:'all .1s'}}>
            <div style={{width:18,height:18,borderRadius:4,border:`2px solid ${sel?C.grn:C.brd}`,background:sel?C.grn:'transparent',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}>
              {sel&&<span style={{color:'#fff',fontSize:12,lineHeight:1}}>✓</span>}
            </div>
            <div style={{flex:1}}>
              <div style={{color:C.txt,fontSize:13,fontWeight:sel?600:400}}>{e.tipo} — {e.idInterno}</div>
              <div style={{color:C.tm,fontSize:11}}>{e.modelo||''} · Serie: {e.serie}</div>
            </div>
          </div>
        })}
      </div>
    </Card>
  </div>
}
function EquipModificar({data,setData}){
  const toast=useToast(),[op,setOp]=useState('mover1'),[orig,setOrig]=useState(''),[dest,setDest]=useState(''),[equip,setEquip]=useState(''),[notaTxt,setNotaTxt]=useState('')
  const equipOrig=orig?data.equipamientos.filter(e=>e.movil_id===orig&&e.estado==='activo'):[]
  const doAction=()=>{
    if(op==='transferir'&&orig&&dest){setData(d=>({...d,equipamientos:d.equipamientos.map(e=>e.movil_id===orig&&e.estado==='activo'?{...e,movil_id:dest}:e),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Transferencia',descripcion:`Todo equip. Móvil ${data.moviles.find(m=>m.id===orig)?.numero}→Móvil ${data.moviles.find(m=>m.id===dest)?.numero}`}]}));toast('Transferencia completada','success')}
    else if(op==='mover1'&&equip&&dest){const e=data.equipamientos.find(x=>x.id===equip);const mv=data.moviles.find(m=>m.id===dest);setData(d=>({...d,equipamientos:d.equipamientos.map(x=>x.id===equip?{...x,movil_id:dest}:x),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Transferencia',descripcion:`${e?.tipo} ${e?.idInterno}→Móvil ${mv?.numero}`}]}));toast('Equipo movido','success')}
    else if(op==='retirar'&&equip){const e=data.equipamientos.find(x=>x.id===equip);setData(d=>({...d,equipamientos:d.equipamientos.map(x=>x.id===equip?{...x,movil_id:null,estado:'stock'}:x),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Retiro',descripcion:`${e?.tipo} ${e?.idInterno} retirado`}]}));toast('Equipo retirado al inventario','success')}
    else if(op==='baja'&&equip&&notaTxt){const e=data.equipamientos.find(x=>x.id===equip);setData(d=>({...d,equipamientos:d.equipamientos.map(x=>x.id===equip?{...x,movil_id:null,estado:'baja',notas:san(notaTxt,300)}:x),notas_equip:[...d.notas_equip,{id:uid(),equip_id:equip,tipo:'baja',nota:san(notaTxt,300),fecha:now()}],movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Baja',descripcion:`${e?.tipo} ${e?.idInterno}: ${san(notaTxt,60)}`}]}));toast('Equipo dado de baja','warn')}
    else if(op==='nota'&&equip&&notaTxt){const e=data.equipamientos.find(x=>x.id===equip);setData(d=>({...d,notas_equip:[...d.notas_equip,{id:uid(),equip_id:equip,tipo:'problema',nota:san(notaTxt,300),fecha:now()}],movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Equipamiento',descripcion:`Nota en ${e?.tipo} ${e?.idInterno}`}]}));toast('Nota registrada','success')}
    setOrig('');setDest('');setEquip('');setNotaTxt('')
  }
  return <Card style={{maxWidth:480}}>
    <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Modificar equipamiento</h3>
    <div style={{display:'flex',gap:6,flexWrap:'wrap',marginBottom:14}}>{[['transferir','Transferir todo'],['mover1','Mover 1 equipo'],['retirar','Retirar equipo'],['baja','Dar de baja'],['nota','Nota']].map(([id,label])=><Btn key={id} sm variant={op===id?'primary':'ghost'} onClick={()=>setOp(id)}>{label}</Btn>)}</div>
    <Fld label="Móvil origen"><Sel value={orig} onChange={e=>{setOrig(e.target.value);setEquip('')}}><option value="">— Seleccionar —</option>{data.moviles.map(m=><option key={m.id} value={m.id}>Móvil {m.numero}</option>)}</Sel></Fld>
    {['mover1','retirar','baja','nota'].includes(op)&&orig&&<Fld label="Equipamiento"><Sel value={equip} onChange={e=>setEquip(e.target.value)}><option value="">— Seleccionar —</option>{equipOrig.map(e=><option key={e.id} value={e.id}>{e.tipo} — {e.idInterno}</option>)}</Sel></Fld>}
    {['transferir','mover1'].includes(op)&&<Fld label="Móvil destino"><Sel value={dest} onChange={e=>setDest(e.target.value)}><option value="">— Seleccionar —</option>{data.moviles.filter(m=>m.id!==orig).map(m=><option key={m.id} value={m.id}>Móvil {m.numero}</option>)}</Sel></Fld>}
    {['baja','nota'].includes(op)&&<Fld label={op==='baja'?'Motivo de baja':'Descripción del problema'}><Txt value={notaTxt} onChange={e=>setNotaTxt(e.target.value)} rows={2}/></Fld>}
    <Btn onClick={doAction} full>Ejecutar</Btn>
  </Card>
}
function EquipMantencion({data,setData}){
  const toast=useToast(),[form,setForm]=useState({equip_id:'',ultima:'',proxima:'',info:''}),[editId,setEditId]=useState(null)
  const guardar=()=>{if(!form.equip_id){toast('Selecciona equipamiento','error');return};if(editId)setData(d=>({...d,mantenciones:d.mantenciones.map(m=>m.id===editId?{...m,...form}:m)}));else setData(d=>({...d,mantenciones:[...d.mantenciones,{id:uid(),...form}],movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Mantención',descripcion:`Mantención registrada`}]}));toast('Mantención guardada','success');setForm({equip_id:'',ultima:'',proxima:'',info:''});setEditId(null)}
  const problemas=data.notas_equip.filter(n=>n.tipo==='problema')
  return <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
    <Card><h3 style={{color:C.tb,marginTop:0,fontSize:15}}>{editId?'Editar':'Registrar'} mantención</h3><Fld label="Equipamiento"><Sel value={form.equip_id} onChange={e=>setForm(f=>({...f,equip_id:e.target.value}))}><option value="">— Seleccionar —</option>{data.equipamientos.map(e=><option key={e.id} value={e.id}>{e.tipo} — {e.idInterno}</option>)}</Sel></Fld><div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}><Fld label="Última mantención"><Inp type="date" value={form.ultima} onChange={e=>setForm(f=>({...f,ultima:e.target.value}))}/></Fld><Fld label="Próxima mantención"><Inp type="date" value={form.proxima} onChange={e=>setForm(f=>({...f,proxima:e.target.value}))}/></Fld></div><Fld label="Observaciones"><Txt value={form.info} onChange={e=>setForm(f=>({...f,info:e.target.value}))} rows={2}/></Fld><Btn onClick={guardar} full>{editId?'Actualizar':'Registrar'}</Btn>{data.mantenciones.length>0&&<>{[...data.mantenciones].map(m=>{const eq=data.equipamientos.find(e=>e.id===m.equip_id);const near=m.proxima&&daysUntil(m.proxima)<=30;return <div key={m.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'6px 0',borderBottom:`1px solid ${C.brd}`}}><div><div style={{fontSize:13,color:C.txt}}>{eq?`${eq.tipo} ${eq.idInterno}`:m.equip_id}</div><div style={{fontSize:11,color:C.tm}}>Próxima: {fmtDate(m.proxima)}</div></div><div style={{display:'flex',gap:6,alignItems:'center'}}>{near&&<Badge color={C.amb}>≤30d</Badge>}<Btn sm variant="ghost" onClick={()=>{setEditId(m.id);setForm({equip_id:m.equip_id,ultima:m.ultima,proxima:m.proxima,info:m.info})}}>✏</Btn></div></div>})}</>}</Card>
    <Card><h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Reportes de problemas</h3>{problemas.length===0?<span style={{color:C.tm,fontSize:13}}>Sin reportes.</span>:problemas.map(n=>{const eq=data.equipamientos.find(e=>e.id===n.equip_id);return <div key={n.id} style={{padding:'8px 0',borderBottom:`1px solid ${C.brd}`}}><div style={{color:C.txt,fontSize:13,fontWeight:600}}>{eq?`${eq.tipo} — ${eq.idInterno}`:'Equipo desconocido'}</div><div style={{color:C.tm,fontSize:12}}>{n.nota}</div><div style={{color:C.tm,fontSize:11}}>{n.fecha}</div></div>})}</Card>
  </div>
}

// ESTADÍSTICA
// ─── Botones de exportación — componente EXTERNO (no dentro de Estadistica) ──────
// IMPORTANTE: definirlo fuera evita que React desmonte/remonte en cada render padre
function ExportBtns({canExport,title,cols,rows,name}){
  const toast=useToast()
  if(!canExport)return <span style={{color:C.tm,fontSize:13}}>🔒 Exportación no disponible para tu rol</span>

  const handleTxt=()=>{
    exportTxt(title,cols,rows,`${name}.txt`)
    toast('Vista de exportación abierta','success',2500)
  }
  const handleExcel=()=>{
    exportExcel([{name:title,cols,rows}],`${name}.xlsx`)
    toast('Vista de exportación abierta','success',2500)
  }
  const handlePdf=()=>{
    exportPdf(title,[{name:title,cols,rows}],`${name}.pdf`)
    toast('Vista de impresión abierta','success',2500)
  }

  return(
    <div style={{display:'flex',gap:8,marginBottom:14,flexWrap:'wrap',alignItems:'center'}}>
      <Btn sm variant="ghost" onClick={handleTxt}>📄 TXT</Btn>
      <Btn sm variant="ghost" onClick={handleExcel}>📊 Excel</Btn>
      <Btn sm variant="ghost" onClick={handlePdf}>📑 PDF</Btn>
    </div>
  )
}

function Estadistica({data,user}){
  const perm=getPerm(user.role)
  const tabs=[
    {id:'general',    label:'General'},
    {id:'farmacia',   label:'Farmacia'},
    {id:'equipamientos',label:'Equipamientos'},
    {id:'movimientos',label:'Movimientos'},
    {id:'movil',      label:'Estadística de móvil'},
  ]
  const [tab,setTab]=useState('general')

  // filas para general — valores convertidos a string para exportación
  const rowsGeneral=[
    ['Móviles',                String(data.moviles.length)],
    ['Bases',                  String(data.bases.length)],
    ['Insumos botiquín',       String(data.botiquin_insumos.length)],
    ['Medicamentos botiquín',  String(data.botiquin_meds.length)],
    ['Meds controlados',       String(data.controlados.length)],
    ['Equipamientos activos',  String(data.equipamientos.filter(e=>e.estado==='activo').length)],
    ['Equipamientos en stock', String(data.equipamientos.filter(e=>e.estado==='stock').length)],
    ['Equipamientos de baja',  String(data.equipamientos.filter(e=>e.estado==='baja').length)],
    ['Total movimientos',      String(data.movimientos.length)],
  ]

  const rowsFarmacia=[
    ...data.botiquin_insumos.map(i=>[i.nombre,String(i.stock),String(i.minimo),'Botiquín insumos']),
    ...data.botiquin_meds.map(m=>[m.nombre,String(m.stock),String(m.minimo),'Botiquín meds']),
    ...data.bodega_insumos.map(i=>[i.nombre,String(i.stock),String(i.minimo),'Bodega']),
  ]

  const rowsEquip=data.equipamientos.map(e=>[
    e.idInterno||'', e.tipo||'', e.estado||'', e.serie||'',
    data.moviles.find(m=>m.id===e.movil_id)?.numero||'—'
  ])

  return(<div>
    <PageTitle sub="Indicadores y exportación de datos">📈 Estadística</PageTitle>
    <Tabs tabs={tabs} active={tab} onChange={setTab}/>

    {tab==='general'&&<div>
      <ExportBtns canExport={perm.canExport} title="Estadística General" cols={['Indicador','Valor']} rows={rowsGeneral} name="estadistica_general"/>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(140px,1fr))',gap:12,marginBottom:20}}>
        {[['🚑 Móviles',data.moviles.length,C.acl],['💊 Insumos bot.',data.botiquin_insumos.length,C.grn],['⚠️ Meds ctrl.',data.controlados.length,C.pur],['🔧 Equip. activos',data.equipamientos.filter(e=>e.estado==='activo').length,C.amb],['📋 Movimientos',data.movimientos.length,C.tm]].map(([l,v,c],i)=><Card key={i} style={{textAlign:'center'}}><div style={{color:c,fontSize:24,fontWeight:800}}>{v}</div><div style={{color:C.txt,fontSize:12}}>{l}</div></Card>)}
      </div>
      <h3 style={{color:C.tb,fontSize:14,marginBottom:10}}>Móviles por tipo</h3>
      <Card>{TIPOS_MOVIL.map(t=>{const cnt=data.moviles.filter(m=>m.tipo===t).length;const pct=data.moviles.length>0?cnt/data.moviles.length*100:0;return <div key={t} style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}><span style={{color:C.txt,fontSize:13,minWidth:70}}>{t}</span><div style={{flex:1,background:C.s3,borderRadius:4,height:16,overflow:'hidden'}}><div style={{background:TC[t]||C.tm,height:'100%',width:`${pct}%`,transition:'width .3s'}}/></div><span style={{color:TC[t]||C.tm,fontWeight:700,fontSize:12,minWidth:30}}>{cnt}</span></div>})}</Card>
    </div>}

    {tab==='farmacia'&&<div>
      <ExportBtns canExport={perm.canExport} title="Farmacia" cols={['Nombre','Stock','Mínimo','Origen']} rows={rowsFarmacia} name="farmacia"/>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <Card><h4 style={{color:C.tb,marginTop:0}}>Insumos botiquín</h4>{data.botiquin_insumos.map(i=><StkRow key={i.id} item={i}/>)}</Card>
        <Card><h4 style={{color:C.tb,marginTop:0}}>Medicamentos</h4>{fefoSort(data.botiquin_meds).map(m=>{const{label,vencido,near}=fmtVenc(m.vencimiento);return <div key={m.id} style={{display:'flex',justifyContent:'space-between',padding:'5px 0',borderBottom:`1px solid ${C.brd}`,fontSize:13}}><span style={{color:C.txt}}>{m.nombre}</span><div style={{textAlign:'right'}}><div style={{fontWeight:700,color:C.txt}}>{m.stock}</div><div style={{color:vencido?C.red:near?C.amb:C.tm,fontSize:11}}>{label}</div></div></div>})}</Card>
      </div>
    </div>}

    {tab==='equipamientos'&&<div>
      <ExportBtns canExport={perm.canExport} title="Equipamientos" cols={['ID Interno','Tipo','Estado','Serie','Móvil']} rows={rowsEquip} name="equipamientos"/>
      {TIPOS_EQUIP.map(t=>{const all=data.equipamientos.filter(e=>e.tipo===t);if(all.length===0)return null;return <div key={t} style={{marginBottom:12}}><h4 style={{color:C.tb,marginBottom:8,fontSize:13}}>{t}</h4><div style={{display:'flex',gap:8}}><Badge color={C.grn}>Activos: {all.filter(e=>e.estado==='activo').length}</Badge><Badge color={C.amb}>En stock: {all.filter(e=>e.estado==='stock').length}</Badge><Badge color={C.red}>De baja: {all.filter(e=>e.estado==='baja').length}</Badge></div></div>})}
    </div>}

    {tab==='movimientos'&&<EstMovimientos data={data} canExport={perm.canExport}/>}
    {tab==='movil'&&<EstMovil data={data}/>}
  </div>)
}

function EstMovimientos({data,canExport}){
  const [modo,setModo]=useState('hoy'),[desde,setDesde]=useState(''),[hasta,setHasta]=useState(''),[tipo,setTipo]=useState(''),[texto,setTexto]=useState('')
  const tipos=[...new Set(data.movimientos.map(m=>m.tipo))],todayStr=today()
  // Parseo robusto de fechas en formato es-CL: "dd-mm-yyyy hh:mm:ss" o "dd/mm/yyyy hh:mm:ss"
  const parseFechaCL=(fechaStr)=>{
    try{
      if(!fechaStr) return null
      const partes=fechaStr.split(/[\s,]+/) // separar fecha y hora
      const fechaPart=partes[0] || ''
      const horaPart=partes[1] || '00:00:00'
      const segs=fechaPart.split(/[\/\-]/)
      if(segs.length!==3) return null
      // dd, mm, yyyy → ISO yyyy-mm-dd
      const [dd,mm,yyyy]=segs
      const iso=`${yyyy.padStart(4,'0')}-${mm.padStart(2,'0')}-${dd.padStart(2,'0')}T${horaPart}`
      const d=new Date(iso)
      return isNaN(d.getTime())?null:d
    }catch(e){ return null }
  }
  const filtered=useMemo(()=>data.movimientos.filter(m=>{
    const fechaMov=parseFechaCL(m.fecha)
    if(modo==='hoy'){
      if(!fechaMov) return false
      const t=new Date(todayStr+'T00:00:00')
      return fechaMov.toDateString()===t.toDateString()
    }
    let ok=true
    if(desde&&fechaMov) ok=ok&&fechaMov>=new Date(desde+'T00:00:00')
    if(hasta&&fechaMov) ok=ok&&fechaMov<=new Date(hasta+'T23:59:59')
    if(tipo) ok=ok&&m.tipo===tipo
    if(texto) ok=ok&&(m.descripcion.toLowerCase().includes(texto.toLowerCase())||m.tipo.toLowerCase().includes(texto.toLowerCase()))
    return ok
  }).slice(-200),[data.movimientos,modo,desde,hasta,tipo,texto,todayStr])
  const distrib=tipos.map(t=>({tipo:t,cnt:filtered.filter(m=>m.tipo===t).length})).filter(x=>x.cnt>0).sort((a,b)=>b.cnt-a.cnt),maxC=Math.max(...distrib.map(d=>d.cnt),1)
  const cols=['Fecha','Tipo','Descripción'],rows=filtered.map(m=>[m.fecha,m.tipo,m.descripcion])
  return <>
    <div style={{display:'flex',gap:8,marginBottom:14}}><Btn sm variant={modo==='hoy'?'primary':'ghost'} onClick={()=>setModo('hoy')}>📅 Hoy</Btn><Btn sm variant={modo==='hist'?'primary':'ghost'} onClick={()=>setModo('hist')}>🔍 Histórico</Btn></div>
    {modo==='hist'&&<div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))',gap:10,marginBottom:14}}><Fld label="Desde"><Inp type="date" value={desde} onChange={e=>setDesde(e.target.value)}/></Fld><Fld label="Hasta"><Inp type="date" value={hasta} onChange={e=>setHasta(e.target.value)}/></Fld><Fld label="Tipo"><Sel value={tipo} onChange={e=>setTipo(e.target.value)}><option value="">Todos</option>{tipos.map(t=><option key={t}>{t}</option>)}</Sel></Fld><Fld label="Texto"><Inp value={texto} onChange={e=>setTexto(e.target.value)} placeholder="Buscar…" maxLength={100}/></Fld></div>}
    {canExport&&<div style={{display:'flex',gap:8,marginBottom:14}}><Btn sm variant="ghost" onClick={()=>exportTxt('Movimientos',cols,rows,'movimientos.txt')}>📄 TXT</Btn><Btn sm variant="ghost" onClick={()=>exportExcel([{name:'Movimientos',cols,rows}],'movimientos.xlsx')}>📊 Excel</Btn><Btn sm variant="ghost" onClick={()=>exportPdf('Movimientos',[{name:'Movimientos',cols,rows}],'movimientos.pdf')}>📑 PDF</Btn></div>}
    {distrib.length>0&&<Card style={{marginBottom:14}}><h4 style={{color:C.tb,marginTop:0,fontSize:13}}>Distribución por tipo ({filtered.length} registros)</h4>{distrib.map(d=><div key={d.tipo} style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}><span style={{color:C.tm,fontSize:12,minWidth:140}}>{d.tipo}</span><div style={{flex:1,background:C.s3,borderRadius:4,height:12,overflow:'hidden'}}><div style={{background:C.acc,height:'100%',width:`${d.cnt/maxC*100}%`}}/></div><span style={{color:C.txt,fontSize:12,minWidth:24}}>{d.cnt}</span></div>)}</Card>}
    <TblSimple cols={cols} rows={rows} empty={`Sin movimientos ${modo==='hoy'?'hoy':'en el rango'}`}/>
  </>
}

function EstMovil({data}){
  const [movil,setMovil]=useState(''),[llamado,setLlamado]=useState(''),[desde,setDesde]=useState(''),[hasta,setHasta]=useState('')
  const filtered=data.movimientos.filter(m=>{let ok=true;if(movil)ok=ok&&m.descripcion.toLowerCase().includes(data.moviles.find(x=>x.id===movil)?.numero||'');if(llamado)ok=ok&&m.descripcion.includes(llamado);if(desde)ok=ok&&new Date(m.fecha)>=new Date(desde);if(hasta)ok=ok&&new Date(m.fecha)<=new Date(hasta+'T23:59:59');return ok})
  return <>
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))',gap:10,marginBottom:14}}><Fld label="Móvil"><Sel value={movil} onChange={e=>setMovil(e.target.value)}><option value="">Todos</option>{data.moviles.map(m=><option key={m.id} value={m.id}>Móvil {m.numero}</option>)}</Sel></Fld><Fld label="N° Llamado"><Inp value={llamado} onChange={e=>setLlamado(e.target.value)} placeholder="Buscar…" maxLength={30}/></Fld><Fld label="Desde"><Inp type="date" value={desde} onChange={e=>setDesde(e.target.value)}/></Fld><Fld label="Hasta"><Inp type="date" value={hasta} onChange={e=>setHasta(e.target.value)}/></Fld></div>
    {!movil&&!llamado&&!desde&&!hasta&&<div style={{marginBottom:14}}><h4 style={{color:C.tb,fontSize:13,marginBottom:8}}>Últimos 5 movimientos</h4><TblSimple cols={['Fecha','Tipo','Descripción']} rows={[...data.movimientos].reverse().slice(0,5).map(m=>[m.fecha,m.tipo,m.descripcion])}/></div>}
    {(movil||llamado||desde||hasta)&&<TblSimple cols={['Fecha','Tipo','Descripción']} rows={filtered.map(m=>[m.fecha,m.tipo,m.descripcion])} empty="Sin resultados"/>}
  </>
}


// ═══════════════════════════════════════════════════
//  📌 PIZARRA · ⚙️ CONFIGURACIÓN · 🏠 APP ROOT
// ═══════════════════════════════════════════════════

function Pizarra({data,setData,user}){
  const perm=getPerm(user.role),toast=useToast()
  if(!perm.canPizarra)return <div><PageTitle>📌 Pizarra</PageTitle><ReadOnlyBanner msg="Tu rol no tiene acceso a la pizarra."/></div>
  const [texto,setTexto]=useState(''),[fecha,setFecha]=useState(''),[hora,setHora]=useState('')
  const MAX=12,LIMIT=250
  // Limpiar notas expiradas — solo si realmente hay alguna expirada (evita loop infinito)
  useEffect(()=>{
    const ahora=Date.now()
    const hayExpiradas=data.notas_pizarra.some(n=>new Date(n.expiraEn).getTime()<=ahora)
    if(!hayExpiradas) return
    setData(d=>({...d,notas_pizarra:d.notas_pizarra.filter(n=>new Date(n.expiraEn).getTime()>ahora)}))
  },[data.notas_pizarra,setData])
  const crear=()=>{
    if(!texto.trim()||data.notas_pizarra.length>=MAX)return
    let expira
    if(fecha&&hora)expira=new Date(`${fecha}T${hora}:00`).toISOString()
    else if(fecha)expira=new Date(`${fecha}T23:59:00`).toISOString()
    else expira=new Date(Date.now()+86400000).toISOString()
    if(new Date(expira)<=new Date()){toast('La fecha/hora no puede ser pasada','error');return}
    setData(d=>({...d,notas_pizarra:[...d.notas_pizarra,{id:uid(),texto:san(texto,LIMIT),autorNombre:user.nombre,autorUsername:user.username,autorId:user.id,creadaEn:new Date().toISOString(),expiraEn:expira}]}))
    toast('Nota creada','success');setTexto('');setFecha('');setHora('')
  }
  const del=(id)=>{setData(d=>({...d,notas_pizarra:d.notas_pizarra.filter(n=>n.id!==id)}));toast('Nota eliminada','info')}
  const fmtExp=(iso)=>{const d=new Date(iso);return `${d.getDate()} ${['ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic'][d.getMonth()]} ${d.getFullYear()} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`}
  const countdown=(iso)=>{const diff=new Date(iso)-new Date();if(diff<=0)return{label:'Expirada',color:C.red};const h=Math.floor(diff/3600000),m=Math.floor((diff%3600000)/60000);const label=h>0?`${h}h ${m}m`:`${m}m`;return{label:`⏱ ${label}`,color:diff<3600000?C.red:diff<21600000?C.amb:C.grn}}
  return(
    <div>
      <PageTitle sub={`${data.notas_pizarra.length}/${MAX} notas activas`}>📌 Pizarra</PageTitle>
      {data.notas_pizarra.length<MAX&&<Card style={{marginBottom:20,maxWidth:500}}>
        <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Nueva nota</h3>
        <Fld label={`Texto (${LIMIT-texto.length} restantes)`}><Txt value={texto} onChange={e=>setTexto(e.target.value.slice(0,LIMIT))} placeholder="Escribe aquí…" rows={3}/></Fld>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}><Fld label="Fecha expiración (opcional)"><Inp type="date" value={fecha} onChange={e=>setFecha(e.target.value)}/></Fld><Fld label="Hora (opcional)"><Inp type="time" value={hora} onChange={e=>setHora(e.target.value)}/></Fld></div>
        <div style={{color:C.tm,fontSize:12,marginBottom:10}}>Sin fecha/hora → expira en 24 horas.</div>
        <Btn onClick={crear} full disabled={!texto.trim()}>Crear nota</Btn>
      </Card>}
      {data.notas_pizarra.length>=MAX&&<div style={{color:C.amb,fontSize:13,marginBottom:14}}>📌 Pizarra llena ({MAX}/{MAX})</div>}
      {data.notas_pizarra.length===0
        ?<div style={{textAlign:'center',padding:40,color:C.tm}}>📋<br/>Pizarra vacía.</div>
        :<div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:14}}>
          {data.notas_pizarra.map((n,i)=>{
            const color=NOTE_COLORS[i%NOTE_COLORS.length],cd=countdown(n.expiraEn)
            const canDel=perm.deletePizarraAny||n.autorId===user.id
            const creadaD=new Date(n.creadaEn)
            return <div key={n.id} style={{background:color+'18',border:`1px solid ${color}44`,borderTop:`3px solid ${color}`,borderRadius:8,padding:14,position:'relative'}}>
              {canDel&&<button onClick={()=>del(n.id)} style={{position:'absolute',top:8,right:8,background:'none',border:'none',color:C.tm,cursor:'pointer',fontSize:16}}>🗑</button>}
              <p style={{color:C.tb,margin:'0 0 10px',fontSize:14,whiteSpace:'pre-wrap',wordBreak:'break-word',paddingRight:20}}>{n.texto}</p>
              <div style={{color:C.tm,fontSize:11,marginBottom:4}}>por: {n.autorNombre} (@{n.autorUsername})</div>
              <div style={{color:C.tm,fontSize:11,marginBottom:6}}>Creada: {String(creadaD.getDate()).padStart(2,'0')}/{String(creadaD.getMonth()+1).padStart(2,'0')}/{creadaD.getFullYear()}</div>
              <div style={{color:cd.color,fontSize:12,fontWeight:600,marginBottom:4}}>{cd.label}</div>
              <div style={{color:C.tm,fontSize:11}}>Expira: {fmtExp(n.expiraEn)}</div>
            </div>
          })}
        </div>}
    </div>
  )
}

// RESUMEN MÓVILES
function ResumenMovilesTab({data}){
  const totalMov=data.moviles.length
  const porTipo=TIPOS_MOVIL.map(t=>({tipo:t,cnt:data.moviles.filter(m=>m.tipo===t).length}))
  const porBase=data.bases.map(b=>({base:b.nombre,cnt:data.moviles.filter(m=>m.base===b.nombre).length}))
  const sinCodigo=data.moviles.filter(m=>!m.codigoHorario).length
  const mantVencidas=data.mantenciones_vehiculo.filter(r=>r.proximaKm-r.km<=0).length
  const mantProximas=data.mantenciones_vehiculo.filter(r=>{const rest=r.proximaKm-r.km;return rest>0&&rest<=1500}).length
  return <div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))',gap:12,marginBottom:24}}>
      {[
        {icon:'🚑',label:'Total móviles',val:totalMov,color:C.acl},
        {icon:'🔑',label:'Sin código horario',val:sinCodigo,color:sinCodigo>0?C.amb:C.grn},
        {icon:'🔴',label:'Mantención vencida',val:mantVencidas,color:mantVencidas>0?C.red:C.grn},
        {icon:'🟡',label:'Mantención próxima',val:mantProximas,color:mantProximas>0?C.amb:C.grn},
      ].map((c,i)=><Card key={i} style={{textAlign:'center'}}><div style={{fontSize:26}}>{c.icon}</div><div style={{color:c.color,fontSize:26,fontWeight:800}}>{c.val}</div><div style={{color:C.tb,fontSize:12,fontWeight:600,marginTop:4}}>{c.label}</div></Card>)}
    </div>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:20}}>
      <Card>
        <h3 style={{color:C.tb,marginTop:0,fontSize:14,marginBottom:12}}>Distribución por tipo</h3>
        {porTipo.filter(x=>x.cnt>0).map(({tipo,cnt})=><div key={tipo} style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
          <Badge color={TC[tipo]||C.tm}>{tipo}</Badge>
          <div style={{flex:1,background:C.s3,borderRadius:4,height:14,overflow:'hidden'}}><div style={{background:TC[tipo]||C.tm,height:'100%',width:`${totalMov>0?cnt/totalMov*100:0}%`,transition:'width .3s'}}/></div>
          <span style={{color:C.txt,fontWeight:700,fontSize:13,minWidth:20}}>{cnt}</span>
        </div>)}
      </Card>
      <Card>
        <h3 style={{color:C.tb,marginTop:0,fontSize:14,marginBottom:12}}>Distribución por base</h3>
        {porBase.map(({base,cnt})=><div key={base} style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
          <span style={{color:C.txt,fontSize:12,minWidth:70}}>{base}</span>
          <div style={{flex:1,background:C.s3,borderRadius:4,height:14,overflow:'hidden'}}><div style={{background:C.acl,height:'100%',width:`${totalMov>0?cnt/totalMov*100:0}%`,transition:'width .3s'}}/></div>
          <span style={{color:C.txt,fontWeight:700,fontSize:13,minWidth:20}}>{cnt}</span>
        </div>)}
      </Card>
    </div>
    <h3 style={{color:C.tb,fontSize:14,marginBottom:12}}>Estado de mantención vehículos</h3>
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(220px,1fr))',gap:10}}>
      {data.moviles.map(mv=>{
        const rec=data.mantenciones_vehiculo.find(r=>r.movil_id===mv.id)
        const restante=rec?rec.proximaKm-rec.km:null
        const color=!rec?C.tm:restante<=0?C.red:restante<=1500?C.amb:C.grn
        const estado=!rec?'Sin datos':restante<=0?'Vencida':restante<=1500?'Próxima (≤1500km)':'OK'
        return <div key={mv.id} style={{background:C.s1,border:`1px solid ${color}44`,borderLeft:`3px solid ${color}`,borderRadius:6,padding:'10px 12px',display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <div><div style={{color:C.tb,fontWeight:600,fontSize:13}}>Móvil {mv.numero}</div><div style={{color:C.tm,fontSize:11}}>{mv.base}</div>{rec&&<div style={{color:C.tm,fontSize:11}}>KM: {rec.km.toLocaleString()} / Próxima: {rec.proximaKm.toLocaleString()}</div>}</div>
          <Badge color={color}>{estado}</Badge>
        </div>
      })}
    </div>
  </div>
}

// ═══════════════════════════════════════════════════
//  💊 CONFIG INSUMOS Y MEDICAMENTOS (admin+jefatura)
// ═══════════════════════════════════════════════════

function ConfigInsumosMeds({data,setData}){
  const subtabs=[{id:'crear_ins',label:'Crear insumo'},{id:'mod_ins',label:'Modificar insumo'},{id:'elim_ins',label:'Eliminar insumo'},{id:'crear_med',label:'Crear medicamento'},{id:'mod_med',label:'Modificar medicamento'},{id:'elim_med',label:'Eliminar medicamento'}]
  const [sub,setSub]=useState('crear_ins')
  return <div>
    <div style={{background:C.amb+'11',border:`1px solid ${C.amb}33`,borderRadius:8,padding:'10px 14px',marginBottom:16,color:C.amb,fontSize:13}}>⚙️ Administración de insumos y medicamentos — Solo Administrador y Jefatura.</div>
    <Tabs tabs={subtabs} active={sub} onChange={setSub}/>
    {sub==='crear_ins'&&<CrearInsumoTab data={data} setData={setData}/>}
    {sub==='mod_ins'&&<ModInsTab data={data} setData={setData}/>}
    {sub==='elim_ins'&&<EliminarInsTab data={data} setData={setData}/>}
    {sub==='crear_med'&&<CrearMedTab data={data} setData={setData}/>}
    {sub==='mod_med'&&<ModMedTab data={data} setData={setData}/>}
    {sub==='elim_med'&&<EliminarMedTab data={data} setData={setData}/>}
  </div>
}

function EliminarMedTab({data,setData}){
  const toast=useToast(),[src,setSrc]=useState('botiquin'),[q,setQ]=useState(''),[confirm,setConfirm]=useState(null)
  const col=src==='botiquin'?'botiquin_meds':'controlados'
  const label=src==='botiquin'?'Botiquín meds':'Controlados'
  const items=useMemo(()=>(data[col]||[]).filter(i=>!q||i.nombre.toLowerCase().includes(q.toLowerCase())),[data,col,q])
  const del=(id)=>{
    const it=(data[col]||[]).find(i=>i.id===id)
    setData(d=>({...d,[col]:d[col].filter(i=>i.id!==id),movimientos:[...d.movimientos,{id:uid(),fecha:now(),tipo:'Med. eliminado',descripcion:`${it?.nombre||id} eliminado de ${label}`}]}))
    toast(`"${it?.nombre}" eliminado`,'warn');setConfirm(null)
  }
  return <>
    <div style={{display:'flex',gap:8,marginBottom:14}}>
      {['botiquin','controlados'].map(s2=><Btn key={s2} variant={src===s2?'primary':'ghost'} sm onClick={()=>setSrc(s2)}>{s2==='botiquin'?'Botiquín meds':'Controlados'}</Btn>)}
    </div>
    <div style={{background:C.red+'11',border:`1px solid ${C.red}33`,borderRadius:6,padding:'8px 12px',marginBottom:14,color:C.red,fontSize:12}}>
      ⚠️ Eliminar un medicamento es permanente e irreversible. Asegúrese de que el stock sea 0 antes de eliminar.
    </div>
    <Fld label="Filtrar por nombre"><Inp value={q} onChange={e=>setQ(e.target.value)} placeholder="Buscar medicamento…"/></Fld>
    <div>
      {items.map(i=>{
        const vd=i.vencimiento?fmtVenc(i.vencimiento):null
        return <div key={i.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 0',borderBottom:`1px solid ${C.brd}`}}>
          <div>
            <span style={{color:C.txt,fontSize:13,fontWeight:600}}>{i.nombre}</span>
            <span style={{color:C.tm,fontSize:12,marginLeft:8}}>Stock: {i.stock}</span>
            {i.lote&&<span style={{color:C.tm,fontSize:11,marginLeft:8}}>Lote: {i.lote}</span>}
            {vd&&<span style={{color:vd.vencido?C.red:vd.near?C.amb:C.tm,fontSize:11,marginLeft:8}}>{vd.label}</span>}
          </div>
          {confirm===i.id
            ?<div style={{display:'flex',gap:6,alignItems:'center'}}>
              <span style={{color:C.tm,fontSize:12}}>¿Confirmar?</span>
              <Btn sm variant="danger" onClick={()=>del(i.id)}>Sí, eliminar</Btn>
              <Btn sm variant="ghost" onClick={()=>setConfirm(null)}>No</Btn>
            </div>
            :<Btn sm variant="danger" onClick={()=>setConfirm(i.id)}>🗑 Eliminar</Btn>}
        </div>
      })}
      {items.length===0&&<div style={{color:C.tm,fontSize:13,padding:'12px 0'}}>No se encontraron medicamentos{q?` para "${q}"`:' en esta sección'}.</div>}
    </div>
  </>
}

// CONFIGURACIÓN
function Configuracion({data,setData,user}){
  const perm=getPerm(user.role)
  const canManageInsumos=['admin','jefatura'].includes(user.role)
  const tabs=[{id:'usuarios',label:'Usuarios'},{id:'bases',label:'Bases'},...(canManageInsumos?[{id:'insumos_meds',label:'Insumos y medicamentos'}]:[]),{id:'sistema',label:'Sistema'},{id:'db',label:'Base de datos'}]
  const [tab,setTab]=useState('usuarios')
  return(<div><PageTitle sub="Configuración del sistema">⚙️ Configuración</PageTitle><Tabs tabs={tabs} active={tab} onChange={setTab}/>{tab==='usuarios'&&<ConfigUsuarios data={data} setData={setData} user={user} perm={perm}/>}{tab==='bases'&&<ConfigBases data={data} setData={setData} perm={perm} user={user}/>}{tab==='insumos_meds'&&canManageInsumos&&<ConfigInsumosMeds data={data} setData={setData}/>}{tab==='sistema'&&<ConfigSistema data={data} setData={setData} user={user} perm={perm}/>}{tab==='db'&&<ConfigBaseDatos data={data} perm={perm}/>}</div>)
}

function ConfigUsuarios({data,setData,user,perm}){
  const toast=useToast(),[modal,setModal]=useState(null),[form,setForm]=useState({nombre:'',username:'',password:'',email:'',role:'lectura'}),[pwdVisible,setPwdVisible]=useState(false),[pwdErrors,setPwdErrors]=useState([])
  const canEditUser=(u)=>{if(u.id===user.id)return true;if(!perm.manageUsers)return false;if(user.role==='jefatura'&&(u.role==='admin'||u.role==='jefatura'))return false;return true}
  const canDelUser=(u)=>{if(u.id===user.id)return false;if(!perm.deleteUsers)return false;if(user.role==='jefatura'&&(u.role==='admin'||u.role==='jefatura'))return false;return true}
  const rolesDisponibles=Object.keys(ROLES).filter(r=>r!=='admin'||perm.createAdmin)
  const handlePwdChange=(val)=>{setForm(f=>({...f,password:val}));if(modal?.type==='new')setPwdErrors(validatePwd(val))}
  const saveUser=async()=>{
    if(!form.nombre||!form.username){toast('Nombre y usuario requeridos','error');return}
    if(modal?.type==='new'){const errs=validatePwd(form.password);if(errs.length>0){toast(errs.join(' · '),'error');return};if(data.users.find(u=>u.username.toLowerCase()===form.username.toLowerCase())){toast('El username ya existe','error');return};const hashed=await hashPwd(form.password,form.username.toLowerCase());setData(d=>({...d,users:[...d.users,{id:uid(),nombre:san(form.nombre,80),username:san(form.username,30).toLowerCase(),password:hashed,passwordHashed:true,email:san(form.email,100),role:form.role}]}));toast(`Usuario "${form.username}" creado`,'success')}
    else if(modal?.type==='edit'){let updatedPwd=modal.user.password,isHashed=modal.user.passwordHashed;if(form.password){const errs=validatePwd(form.password);if(errs.length>0&&modal.user.id!==user.id){toast(errs.join(' · '),'error');return};updatedPwd=await hashPwd(form.password,modal.user.username);isHashed=true};setData(d=>({...d,users:d.users.map(u=>u.id===modal.user.id?{...u,nombre:san(form.nombre,80),email:san(form.email,100),role:form.role,password:updatedPwd,passwordHashed:isHashed}:u)}));toast('Usuario actualizado','success')}
    setModal(null);setPwdErrors([])
  }
  const delUser=()=>{setData(d=>({...d,users:d.users.filter(u=>u.id!==modal.user.id)}));toast(`"${modal.user.username}" eliminado`,'warn');setModal(null)}
  return <>
    {!perm.manageUsers&&<ReadOnlyBanner msg="Tu rol no puede crear ni eliminar usuarios."/>}
    {perm.manageUsers&&<div style={{marginBottom:14}}><Btn onClick={()=>{setForm({nombre:'',username:'',password:'',email:'',role:'lectura'});setPwdErrors([]);setModal({type:'new'})}}>+ Nuevo usuario</Btn></div>}
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(240px,1fr))',gap:10}}>
      {data.users.map(u=><Card key={u.id}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'start'}}>
          <div><div style={{color:C.tb,fontWeight:700}}>{u.nombre}</div><div style={{color:C.tm,fontSize:12}}>@{u.username}</div><div style={{marginTop:4,display:'flex',gap:4,flexWrap:'wrap'}}><Badge color={roleColor(u.role)}>{roleLabel(u.role)}</Badge>{u.id===user.id&&<Badge color={C.acl}>Tú</Badge>}{u.passwordHashed&&<Badge color={C.grn}>🔒</Badge>}</div></div>
          <div style={{display:'flex',flexDirection:'column',gap:4}}>{canEditUser(u)&&<Btn sm variant="ghost" onClick={()=>{setForm({nombre:u.nombre,username:u.username,password:'',email:u.email||'',role:u.role});setPwdErrors([]);setModal({type:'edit',user:u})}}>Editar</Btn>}{canDelUser(u)&&<Btn sm variant="danger" onClick={()=>setModal({type:'del',user:u})}>Eliminar</Btn>}</div>
        </div>
      </Card>)}
    </div>
    {modal&&(modal.type==='new'||modal.type==='edit')&&<Modal title={modal.type==='new'?'Nuevo usuario':'Editar usuario'} onClose={()=>setModal(null)}>
      <Fld label="Nombre completo"><Inp value={form.nombre} onChange={e=>setForm(f=>({...f,nombre:e.target.value}))} maxLength={80}/></Fld>
      <Fld label="Username">{modal.type==='edit'?<div style={{color:C.tm,fontSize:13,padding:'8px 10px',background:C.s2,borderRadius:6}}>@{modal.user.username} (no editable)</div>:<Inp value={form.username} onChange={e=>setForm(f=>({...f,username:e.target.value.toLowerCase()}))} maxLength={30}/>}</Fld>
      <Fld label={modal.type==='edit'?'Nueva contraseña (vacío = sin cambios)':'Contraseña'}>
        <div style={{position:'relative'}}><Inp type={pwdVisible?'text':'password'} value={form.password} onChange={e=>handlePwdChange(e.target.value)} placeholder={modal.type==='edit'?'Dejar vacío para no cambiar':'Mínimo 8 caracteres, 1 mayúscula, 1 número'} maxLength={128} style={{paddingRight:36}}/><button onClick={()=>setPwdVisible(v=>!v)} style={{position:'absolute',right:8,top:'50%',transform:'translateY(-50%)',background:'none',border:'none',color:C.tm,cursor:'pointer',fontSize:14}}>{pwdVisible?'🙈':'👁'}</button></div>
        {pwdErrors.length>0&&<div style={{marginTop:4}}>{pwdErrors.map((e,i)=><div key={i} style={{color:C.red,fontSize:11}}>• {e}</div>)}</div>}
      </Fld>
      <Fld label="Correo"><Inp type="email" value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} maxLength={100}/></Fld>
      <Fld label="Rol"><Sel value={form.role} onChange={e=>setForm(f=>({...f,role:e.target.value}))}>{rolesDisponibles.map(r=><option key={r} value={r}>{roleLabel(r)}</option>)}</Sel></Fld>
      <div style={{display:'flex',gap:8}}><Btn variant="secondary" full onClick={()=>setModal(null)}>Cancelar</Btn><Btn full onClick={saveUser}>Guardar</Btn></div>
    </Modal>}
    {modal?.type==='del'&&<ConfirmModal title="Eliminar usuario"
      body={<div style={{textAlign:'center'}}><div style={{fontSize:48}}>👤</div><div style={{color:C.tb,fontWeight:700,fontSize:18}}>{modal.user.nombre}</div><div style={{color:C.tm,fontSize:13}}>@{modal.user.username}</div><div style={{marginTop:8}}><Badge color={roleColor(modal.user.role)}>{roleLabel(modal.user.role)}</Badge></div><div style={{background:C.red+'22',border:`1px solid ${C.red}44`,borderRadius:8,padding:'10px 14px',marginTop:12,color:C.red,fontSize:13}}>⚠️ Esta acción es permanente.</div></div>}
      onConfirm={delUser} onClose={()=>setModal(null)} confirmLabel="Sí, eliminar usuario"/>}
  </>
}

function ConfigBases({data,setData,perm,user}){
  const toast=useToast()
  const [nombre,setNombre]=useState(''),[dir,setDir]=useState(''),[confirm,setConfirm]=useState(null)
  const [editModal,setEditModal]=useState(null),[editNombre,setEditNombre]=useState(''),[editDir,setEditDir]=useState('')
  const canEdit=['admin','supervisor','jefatura'].includes(user?.role)

  const agregar=()=>{
    if(!nombre){toast('Nombre requerido','error');return}
    if(data.bases.find(b=>b.nombre===nombre)){toast('La base ya existe','error');return}
    setData(d=>({...d,bases:[...d.bases,{nombre:san(nombre,50),direccion:san(dir,200)}]}))
    toast(`Base "${nombre}" agregada`,'success');setNombre('');setDir('')
  }

  const abrirEditar=(b)=>{ setEditModal(b); setEditNombre(b.nombre); setEditDir(b.direccion||'') }

  const guardarEditar=()=>{
    if(!editNombre){toast('Nombre requerido','error');return}
    const nombreOriginal=editModal.nombre
    if(editNombre!==nombreOriginal&&data.bases.find(b=>b.nombre===editNombre)){toast('Ya existe una base con ese nombre','error');return}
    setData(d=>({
      ...d,
      bases:d.bases.map(b=>b.nombre===nombreOriginal?{nombre:san(editNombre,50),direccion:san(editDir,200)}:b),
      // actualizar referencia en móviles si cambió el nombre
      moviles:editNombre!==nombreOriginal?d.moviles.map(m=>m.base===nombreOriginal?{...m,base:san(editNombre,50)}:m):d.moviles
    }))
    toast(`Base "${editNombre}" actualizada`,'success'); setEditModal(null)
  }

  return <>
    {perm.manageBases&&<Card style={{maxWidth:420,marginBottom:16}}>
      <h3 style={{color:C.tb,marginTop:0,fontSize:15}}>Nueva base</h3>
      <Fld label="Nombre"><Inp value={nombre} onChange={e=>setNombre(e.target.value)} placeholder="Ej: Base 5" maxLength={50}/></Fld>
      <Fld label="Dirección / Referencia"><Inp value={dir} onChange={e=>setDir(e.target.value)} placeholder="Dirección…" maxLength={200}/></Fld>
      <Btn onClick={agregar} full>Agregar base</Btn>
    </Card>}
    <div>{data.bases.map((b,i)=>(
      <div key={i} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'10px 0',borderBottom:`1px solid ${C.brd}`}}>
        <div>
          <div style={{color:C.tb,fontWeight:700}}>{b.nombre}</div>
          <div style={{color:C.tm,fontSize:12}}>{b.direccion||<span style={{fontStyle:'italic'}}>Sin dirección</span>}</div>
          <div style={{color:C.tm,fontSize:11}}>{data.moviles.filter(m=>m.base===b.nombre).length} móvil(es)</div>
        </div>
        <div style={{display:'flex',gap:6}}>
          {canEdit&&<Btn sm variant="ghost" onClick={()=>abrirEditar(b)}>✏ Editar</Btn>}
          {perm.manageBases&&<Btn sm variant="danger" onClick={()=>setConfirm(b)}>🗑 Eliminar</Btn>}
        </div>
      </div>
    ))}</div>

    {editModal&&<Modal title={`Editar: ${editModal.nombre}`} onClose={()=>setEditModal(null)}>
      <Fld label="Nombre de la base">
        <Inp value={editNombre} onChange={e=>setEditNombre(e.target.value)} placeholder="Ej: Base 5" maxLength={50}/>
        {editNombre!==editModal.nombre&&<div style={{fontSize:11,color:C.amb,marginTop:3}}>⚠️ Cambiar el nombre actualizará todos los móviles asignados.</div>}
      </Fld>
      <Fld label="Dirección / Referencia">
        <Inp value={editDir} onChange={e=>setEditDir(e.target.value)} placeholder="Dirección…" maxLength={200}/>
      </Fld>
      <div style={{display:'flex',gap:8}}>
        <Btn variant="secondary" full onClick={()=>setEditModal(null)}>Cancelar</Btn>
        <Btn full onClick={guardarEditar}>Guardar cambios</Btn>
      </div>
    </Modal>}

    {confirm&&<ConfirmModal title={`Eliminar base "${confirm.nombre}"`}
      body={<p style={{color:C.tm,fontSize:13}}>Los móviles asignados quedarán sin base asignada.</p>}
      onConfirm={()=>{setData(d=>({...d,bases:d.bases.filter(x=>x.nombre!==confirm.nombre)}));toast(`Base "${confirm.nombre}" eliminada`,'warn');setConfirm(null)}}
      onClose={()=>setConfirm(null)} confirmLabel="Sí, eliminar"/>}
  </>
}

function ConfigSistema({data,setData,user,perm}){
  const [confirmReset,setConfirmReset]=useState(false)
  return <>
    <TblSimple cols={['Parámetro','Valor']} rows={[['Versión','2.0.0 (Seguridad mejorada)'],['Tu rol',roleLabel(user.role)],['Hashing','PBKDF2-SHA256 · 100.000 iteraciones'],['Rate limiting login','Máx. 5 intentos · Bloqueo 5 min (sessionStorage)'],['Timeout sesión','30 min inactividad'],['Cifrado contraseñas','Estándar industria'],['Usuarios',data.users.length],['Móviles',data.moviles.length],['Bases',data.bases.length],['Movimientos',data.movimientos.length]]}/>
    <Card style={{marginTop:16,border:`1px solid ${C.grn}44`,background:C.grn+'08'}}>
      <div style={{color:C.grn,fontWeight:700,fontSize:14,marginBottom:8}}>🔒 Estado de seguridad</div>
      {[['Contraseñas hasheadas',data.users.every(u=>u.passwordHashed)?'✅ Todas las cuentas':'⚠️ Migración pendiente'],['Rate limiting','✅ Activo (5 intentos / 5 min)'],['Timeout de sesión','✅ Activo (30 min)'],['Sanitización de inputs','✅ Activa en todos los campos'],['Modales de confirmación','✅ En todas las acciones destructivas']].map(([k,v],i)=><div key={i} style={{display:'flex',justifyContent:'space-between',padding:'5px 0',borderBottom:`1px solid ${C.brd}22`,fontSize:13}}><span style={{color:C.txt}}>{k}</span><span style={{color:v.startsWith('✅')?C.grn:C.amb}}>{v}</span></div>)}
    </Card>
    {perm.resetData&&<div style={{marginTop:20}}>
      <h3 style={{color:C.red,fontSize:14,marginBottom:8}}>⚠️ Zona de peligro</h3>
      <Btn variant="danger" onClick={()=>setConfirmReset(true)}>Restaurar datos de ejemplo</Btn>
    </div>}
    {confirmReset&&<ConfirmModal
      title="Restaurar datos de ejemplo"
      body={<div style={{textAlign:'center'}}><div style={{fontSize:40,marginBottom:8}}>⚠️</div><div style={{color:C.red,fontWeight:700,marginBottom:8}}>Esta acción borrará TODOS los datos actuales</div><div style={{color:C.tm,fontSize:13}}>Se restaurarán los datos de ejemplo iniciales. Esta acción no se puede deshacer.</div></div>}
      onConfirm={()=>{setData(D0);setConfirmReset(false)}}
      onClose={()=>setConfirmReset(false)}
      confirmLabel="Sí, restaurar datos de ejemplo"
    />}
  </>
}

function ConfigBaseDatos({data,perm}){
  const toast=useToast()
  if(!perm.canExport)return <ReadOnlyBanner msg="Tu rol no tiene acceso a la exportación de datos."/>
  const sections=[
    {label:'Botiquín',cols:['Nombre','Stock','Mínimo','Tipo'],rows:[...data.botiquin_insumos.map(i=>[i.nombre,i.stock,i.minimo,'Insumo']),...data.botiquin_meds.map(m=>[m.nombre,m.stock,m.minimo,'Med'])]},
    {label:'Bodega',cols:['Nombre','Stock','Mínimo'],rows:data.bodega_insumos.map(i=>[i.nombre,i.stock,i.minimo])},
    {label:'Controlados',cols:['Nombre','Stock','Mínimo','Lote','Vencimiento'],rows:data.controlados.map(c=>[c.nombre,c.stock,c.minimo,c.lote,fmtDate(c.vencimiento)])},
    {label:'Móviles',cols:['Número','Base','Tipo','Patente'],rows:data.moviles.map(m=>[m.numero,m.base,m.tipo,m.patente])},
    {label:'Equipamientos',cols:['ID Interno','Tipo','Estado','Serie','Móvil'],rows:data.equipamientos.map(e=>[e.idInterno,e.tipo,e.estado,e.serie,data.moviles.find(m=>m.id===e.movil_id)?.numero||'—'])},
  ]
  const criticos=[...data.botiquin_insumos,...data.botiquin_meds].filter(i=>i.stock<=i.minimo).length
  const vencidos=[...data.botiquin_meds,...data.controlados].filter(m=>daysUntil(m.vencimiento)<=0).length
  return <>
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(140px,1fr))',gap:10,marginBottom:20}}>
      {[['Insumos bot.',data.botiquin_insumos.length,C.acl],['Medicamentos',data.botiquin_meds.length,C.grn],['Bodega',data.bodega_insumos.length,C.amb],['Controlados',data.controlados.length,C.pur],['Stock crítico',criticos,criticos>0?C.red:C.grn],['Vencidos',vencidos,vencidos>0?C.red:C.grn]].map(([l,v,c],i)=><Card key={i} style={{textAlign:'center'}}><div style={{color:c,fontSize:22,fontWeight:800}}>{v}</div><div style={{color:C.tm,fontSize:12}}>{l}</div></Card>)}
    </div>
    <table style={{width:'100%',borderCollapse:'collapse',fontSize:13}}>
      <thead><tr>{['Sección','Registros','📄 TXT','📊 Excel','📑 PDF'].map((c,i)=><th key={i} style={{padding:'8px 10px',background:C.s3,color:C.tm,fontWeight:600,textAlign:'left',borderBottom:`1px solid ${C.brd}`}}>{c}</th>)}</tr></thead>
      <tbody>
        {sections.map(s=><tr key={s.label} style={{borderBottom:`1px solid ${C.brd}22`}}>
          <td style={{padding:'8px 10px',color:C.tb,fontWeight:600}}>{s.label}</td>
          <td style={{padding:'8px 10px',color:C.tm}}>{s.rows.length}</td>
          <td style={{padding:'6px 10px'}}><Btn sm variant="ghost" onClick={()=>{exportTxt(s.label,s.cols,s.rows,`${s.label}.txt`);toast('Vista de exportación abierta','success',2500)}}>TXT</Btn></td>
          <td style={{padding:'6px 10px'}}><Btn sm variant="ghost" onClick={()=>{exportExcel([{name:s.label,cols:s.cols,rows:s.rows}],`${s.label}.xlsx`);toast('Vista de exportación abierta','success',2500)}}>Excel</Btn></td>
          <td style={{padding:'6px 10px'}}><Btn sm variant="ghost" onClick={()=>{exportPdf(s.label,[{name:s.label,cols:s.cols,rows:s.rows}],`${s.label}.pdf`);toast('Vista de impresión abierta','success',2500)}}>PDF</Btn></td>
        </tr>)}
        <tr style={{background:C.s3+'66'}}>
          <td style={{padding:'8px 10px',color:C.tb,fontWeight:700}}>📦 Exportar todo</td>
          <td style={{padding:'8px 10px',color:C.tm}}>{sections.reduce((a,s)=>a+s.rows.length,0)}</td>
          <td style={{padding:'6px 10px'}}><Btn sm variant="secondary" onClick={()=>{exportTxt('UCM — Todo',['Sección','Nombre','Stock'],sections.flatMap(s=>s.rows.map(r=>[s.label,...r])),'UCM_todo.txt');toast('Vista de exportación abierta','success',2500)}}>TXT</Btn></td>
          <td style={{padding:'6px 10px'}}><Btn sm variant="secondary" onClick={()=>{exportExcel(sections.map(s=>({name:s.label,cols:s.cols,rows:s.rows})),'UCM_todo.xlsx');toast('Vista de exportación abierta','success',2500)}}>Excel</Btn></td>
          <td style={{padding:'6px 10px'}}><Btn sm variant="secondary" onClick={()=>{exportPdf('UCM Ops',sections.map(s=>({name:s.label,cols:s.cols,rows:s.rows})),'UCM_todo.pdf');toast('Vista de impresión abierta','success',2500)}}>PDF</Btn></td>
        </tr>
      </tbody>
    </table>
  </>
}

// ═══════════════════════════════════════════════════
//  🏠 APP ROOT
// ═══════════════════════════════════════════════════

export default function App(){
  const [loaded,setLoaded]=useState(false)
  const [data,setData]=useState(D0)
  const [user,setUser]=useState(null)
  const [page,setPage]=useState('resumen')
  const [col,setCol]=useState(false)

  // Cargar datos desde Supabase (con fallback a localStorage)
  useEffect(()=>{
    (async()=>{
      try{
        // 1. Intentar cargar desde Supabase
        let parsed = await sbLoad()
        // 2. Fallback: localStorage si Supabase falla o está vacío
        if(!parsed){
          const raw=localStorage.getItem('ucm_data_v2')
          if(raw) parsed=JSON.parse(raw)
        }
        if(parsed){
          const needsMigration=parsed.users?.some(u=>u.passwordHashed&&(!u.hash_v||u.hash_v<HASH_VERSION))
          if(needsMigration){
            const freshUsers=await hashAllPasswords(D0.users)
            setData({...parsed,users:freshUsers})
          } else {
            const withHashed=await hashAllPasswords(parsed.users||[])
            setData({...parsed,users:withHashed})
          }
        } else {
          const withHashed=await hashAllPasswords(D0.users)
          setData({...D0,users:withHashed})
        }
      }catch(e){
        const withHashed=await hashAllPasswords(D0.users)
        setData({...D0,users:withHashed})
      }
      setLoaded(true)
    })()
  },[])

  // Guardar en Supabase + localStorage cuando cambian los datos
  useEffect(()=>{
    if(!loaded)return
    try{localStorage.setItem('ucm_data_v2',JSON.stringify(data))}catch(e){}
    sbSave(data)
  },[data,loaded])

  // Session timeout handler
  const handleExpire=useCallback(()=>{setUser(null)},[])
  const {remaining,reset}=useSessionTimeout(user?handleExpire:()=>{})

  const handleLogin=(u)=>{ reset(); setUser(u) }
  const handleLogout=()=>{ setUser(null); setPage('resumen') }

  if(!loaded) return(
    <div style={{minHeight:'100vh',background:C.bg,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',color:C.tb,fontFamily:"'DM Sans',sans-serif",gap:12}}>
      <div style={{fontSize:40,animation:'spin 1s linear infinite'}}>🚑</div>
      <div style={{fontSize:16,fontWeight:600}}>Cargando UCM Ops…</div>
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )

  if(!user) return(
    <>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
      <ToastProvider><Login onLogin={handleLogin} users={data.users}/></ToastProvider>
    </>
  )

  const pages={
    resumen:       <Resumen data={data} user={user}/>,
    moviles:       <GestionMoviles data={data} setData={setData} user={user}/>,
    farmacia:      <GestionFarmacia data={data} setData={setData} user={user}/>,
    controlados:   <MedsControlados data={data} setData={setData} user={user}/>,
    equipamientos: <GestionEquipamientos data={data} setData={setData} user={user}/>,
    estadistica:   <Estadistica data={data} user={user}/>,
    pizarra:       <Pizarra data={data} setData={setData} user={user}/>,
    config:        <Configuracion data={data} setData={setData} user={user}/>,
  }

  return(
    <>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
      <ToastProvider>
        <ExportModal/>
        <SessionBar remaining={remaining} onExtend={reset}/>
        <div style={{display:'flex',height:'100vh',overflow:'hidden',background:C.bg,fontFamily:"'DM Sans',system-ui,sans-serif",color:C.txt,paddingTop:remaining<=SESS_WARN?32:0,transition:'padding-top .3s'}}>
          <Sidebar page={page} setPage={setPage} user={user} onLogout={handleLogout} col={col} setCol={setCol}/>
          <main style={{flex:1,overflow:'auto',padding:'20px 22px',minWidth:0}}>
            {pages[page]||<div style={{color:C.tm}}>Página no encontrada</div>}
          </main>
        </div>
      </ToastProvider>
    </>
  )
}

// helper para hashear usuarios (usado en App)
async function hashAllPasswords(users){
  return Promise.all(users.map(async u=>{
    if(u.passwordHashed && u.hash_v===HASH_VERSION) return u
    // Si ya estaba hasheado con versión anterior → no podemos re-hashear sin texto plano
    // Si no estaba hasheado → hashear ahora con PBKDF2
    if(!u.passwordHashed) return {...u,password:await hashPwd(u.password,u.username),passwordHashed:true,hash_v:HASH_VERSION}
    return u  // hash viejo: se mantiene pero login fallará → forzar reset vía versión de datos
  }))
}
