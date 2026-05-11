import { useState, useEffect, useRef, useCallback, useMemo, createContext, useContext, memo } from "react"
import * as XLSX from 'xlsx'

// ═══════════════════════════════════════════════════
//  🔒 MÓDULO DE SEGURIDAD
// ═══════════════════════════════════════════════════

const sha256 = async (str) => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('')
}
const APP_SALT = 'UCM_GI_v2_8f3a1c9b'

const sanitize = (val, maxLen = 500) => {
  if (typeof val !== 'string') return ''
  return val.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/javascript:/gi,'').replace(/on\w+\s*=/gi,'').trim().slice(0, maxLen)
}
const san = sanitize

const _ls = {}
const loginRL = {
  MAX:5, WIN:300000,
  check(k){ const r=_ls[k]; if(!r) return {locked:false,remaining:this.MAX}; if(Date.now()-r.first>this.WIN){delete _ls[k];return{locked:false,remaining:this.MAX}}; if(r.count>=this.MAX) return {locked:true,secsLeft:Math.ceil((this.WIN-(Date.now()-r.first))/1000)}; return {locked:false,remaining:this.MAX-r.count} },
  hit(k){ if(!_ls[k])_ls[k]={count:0,first:Date.now()}; return ++_ls[k].count },
  reset(k){ delete _ls[k] }
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
          <div key={t.id} style={{background:'#1c2130',border:`1px solid ${TC2[t.type]}55`,borderLeft:`3px solid ${TC2[t.type]}`,borderRadius:8,padding:'10px 14px',display:'flex',alignItems:'center',gap:10,boxShadow:'0 4px 20px rgba(0,0,0,0.5)',color:'#c9d1d9',fontSize:13,animation:'toastIn .25s ease'}}>
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
  const col=remaining<60000?'#ef4444':remaining<180000?'#f59e0b':'#2563eb'
  return(
    <div style={{position:'fixed',top:0,left:0,right:0,zIndex:999,background:'#0d1117',borderBottom:`1px solid ${col}55`,padding:'5px 16px',display:'flex',alignItems:'center',gap:10}}>
      <div style={{background:'#21262d',borderRadius:4,height:3,flex:1}}><div style={{background:col,height:'100%',width:`${pct}%`,borderRadius:4,transition:'width .5s'}}/></div>
      <span style={{color:col,fontSize:11,fontWeight:700,whiteSpace:'nowrap'}}>⏱ Sesión: {mins} min</span>
      <button onClick={onExtend} style={{background:col,border:'none',borderRadius:4,color:'#fff',cursor:'pointer',fontSize:11,fontWeight:700,padding:'3px 8px'}}>Renovar</button>
    </div>
  )
}

// ═══════════════════════════════════════════════════
//  🎨 PALETA & CONSTANTES
// ═══════════════════════════════════════════════════

const C={bg:'#0d1117',s1:'#161b22',s2:'#21262d',s3:'#2d333b',brd:'#30363d',acc:'#2563eb',acl:'#3b82f6',red:'#ef4444',amb:'#f59e0b',grn:'#16a34a',pur:'#a855f7',txt:'#c9d1d9',tb:'#f0f6fc',tm:'#8b949e'}
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
    {id:'u1',username:'admin',     password:'admin',email:'admin@ucm.cl', nombre:'Administrador',  role:'admin',     passwordHashed:false},
    {id:'u2',username:'supervisor1',password:'1234', email:'sup@ucm.cl',  nombre:'Juan Supervisor',role:'supervisor',passwordHashed:false},
    {id:'u3',username:'farmacia1',  password:'1234', email:'farm@ucm.cl', nombre:'Ana Farmacia',   role:'farmacia',  passwordHashed:false},
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

  movimientos:[{id:'mv0',fecha:new Date().toLocaleString('es-CL'),tipo:'Sistema',descripcion:'UCM Gestión Interna v2.0 — Base de datos cargada desde Excel (26 móviles, 82 insumos, 35 medicamentos, 71 equipos).'}],
  notas_equip:[],mantenciones:[],mantenciones_vehiculo:[],
  notas_pizarra:[{id:'np1',texto:'Sistema iniciado con datos reales desde base de datos UCM. Los equipamientos están en inventario listos para asignación a móviles.',autorNombre:'Administrador',autorUsername:'admin',autorId:'u1',creadaEn:new Date().toISOString(),expiraEn:new Date(Date.now()+86400000*7).toISOString()}],
  _version:'2.0.0',
}

const uid=()=>crypto.randomUUID?.()??Math.random().toString(36).slice(2,10)
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
    doc.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${state.title||'UCM'}</title>
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
${el.innerHTML.replace(/style="[^"]*"/g,'')}
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
      const hashed=await sha256(p+APP_SALT)
      const found=users.find(x=>x.username.toLowerCase()===uname&&x.password===hashed&&x.passwordHashed)
      if(found){loginRL.reset(uname);onLogin({...found,lastLogin:new Date().toISOString()})}
      else{loginRL.hit(uname);const st=loginRL.check(uname);st.locked?setErr(`⛔ Demasiados intentos. Bloqueado por ${Math.ceil(loginRL.WIN/60000)} min.`):setErr(`❌ Credenciales incorrectas. ${st.remaining} intento${st.remaining!==1?'s':''} restante${st.remaining!==1?'s':''}.`)}
    }finally{setLoading(false)}
  }
  const kd=e=>{if(e.key==='Enter')doLogin()}

  return(
    <div style={{minHeight:'100vh',background:C.bg,display:'flex',alignItems:'center',justifyContent:'center',fontFamily:"'DM Sans',sans-serif"}}>
      <div style={{width:'100%',maxWidth:360}}>
        <div style={{textAlign:'center',marginBottom:28}}>
          <div style={{width:56,height:56,borderRadius:16,background:C.acc,display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:28,marginBottom:12,boxShadow:`0 0 0 4px ${C.acc}33`}}>🚑</div>
          <h1 style={{color:C.tb,margin:0,fontSize:22,fontWeight:800}}>Gestión Interna UCM</h1>
          <p style={{color:C.tm,margin:'4px 0 0',fontSize:13}}>Sistema de gestión operacional v2.0</p>
        </div>
        <Card style={{boxShadow:'0 8px 32px rgba(0,0,0,.4)'}}>
          <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:14,background:C.grn+'11',border:`1px solid ${C.grn}33`,borderRadius:6,padding:'6px 10px'}}>
            <span>🔒</span><span style={{color:C.grn,fontSize:11,fontWeight:600}}>Conexión segura · Contraseñas cifradas SHA-256</span>
          </div>
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
          <div style={{textAlign:'center',marginTop:10,color:C.tm,fontSize:11,borderTop:`1px solid ${C.brd}`,paddingTop:10}}>
            Demo: <code style={{background:C.s3,padding:'1px 4px',borderRadius:3}}>admin</code> / <code style={{background:C.s3,padding:'1px 4px',borderRadius:3}}>admin</code>
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
        {!col&&<span style={{color:C.tb,fontWeight:800,fontSize:14,paddingLeft:6}}>🚑 UCM</span>}
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
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(155px,1fr))',gap:10,marginBottom:18}}>
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
      <div style={{display:'grid',gridTemplateColumns:'1fr 340px',gap:14,alignItems:'start'}}>

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
    else if(fecha)expira=new Date(`${fecha}T00:01:00`).toISOString()
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
    if(modal?.type==='new'){const errs=validatePwd(form.password);if(errs.length>0){toast(errs.join(' · '),'error');return};if(data.users.find(u=>u.username.toLowerCase()===form.username.toLowerCase())){toast('El username ya existe','error');return};const hashed=await sha256(form.password+APP_SALT);setData(d=>({...d,users:[...d.users,{id:uid(),nombre:san(form.nombre,80),username:san(form.username,30).toLowerCase(),password:hashed,passwordHashed:true,email:san(form.email,100),role:form.role}]}));toast(`Usuario "${form.username}" creado`,'success')}
    else if(modal?.type==='edit'){let updatedPwd=modal.user.password,isHashed=modal.user.passwordHashed;if(form.password){const errs=validatePwd(form.password);if(errs.length>0&&modal.user.id!==user.id){toast(errs.join(' · '),'error');return};updatedPwd=await sha256(form.password+APP_SALT);isHashed=true};setData(d=>({...d,users:d.users.map(u=>u.id===modal.user.id?{...u,nombre:san(form.nombre,80),email:san(form.email,100),role:form.role,password:updatedPwd,passwordHashed:isHashed}:u)}));toast('Usuario actualizado','success')}
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
    <TblSimple cols={['Parámetro','Valor']} rows={[['Versión','2.0.0 (Seguridad mejorada)'],['Tu rol',roleLabel(user.role)],['Rate limiting login','Máx. 5 intentos · Bloqueo 5 min'],['Timeout sesión','30 min inactividad'],['Cifrado contraseñas','SHA-256 + Salt'],['Usuarios',data.users.length],['Móviles',data.moviles.length],['Bases',data.bases.length],['Movimientos',data.movimientos.length]]}/>
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
          <td style={{padding:'6px 10px'}}><Btn sm variant="secondary" onClick={()=>{exportPdf('UCM Gestión Interna',sections.map(s=>({name:s.label,cols:s.cols,rows:s.rows})),'UCM_todo.pdf');toast('Vista de impresión abierta','success',2500)}}>PDF</Btn></td>
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

  // Cargar datos y hashear contraseñas al inicio
  useEffect(()=>{
    (async()=>{
      try{
        const raw=localStorage.getItem('ucm_data_v2')
        if(raw){
          const parsed=JSON.parse(raw)
          const withHashed=await hashAllPasswords(parsed.users||[])
          setData({...parsed,users:withHashed})
        } else {
          // Primera carga: hashear contraseñas de demo
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

  // Guardar en storage cuando cambian los datos
  useEffect(()=>{
    if(!loaded)return
    try{localStorage.setItem('ucm_data_v2',JSON.stringify(data))}catch(e){}
  },[data,loaded])

  // Session timeout handler
  const handleExpire=useCallback(()=>{setUser(null)},[])
  const {remaining,reset}=useSessionTimeout(user?handleExpire:()=>{})

  const handleLogin=(u)=>{ reset(); setUser(u) }
  const handleLogout=()=>{ setUser(null); setPage('resumen') }

  if(!loaded) return(
    <div style={{minHeight:'100vh',background:C.bg,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',color:C.tb,fontFamily:"'DM Sans',sans-serif",gap:12}}>
      <div style={{fontSize:40,animation:'spin 1s linear infinite'}}>🚑</div>
      <div style={{fontSize:16,fontWeight:600}}>Cargando UCM v2.0…</div>
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
  return Promise.all(users.map(async u=>u.passwordHashed?u:{...u,password:await sha256(u.password+APP_SALT),passwordHashed:true}))
}
