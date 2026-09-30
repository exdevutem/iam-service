const { Pool } = require('pg');
const { randomUUID } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { userInfo } = require('node:os');

function connection(url, prefix) {
  if (!url) throw new Error('MISSING_CONFIGURATION');
  const parsed = new URL(url);
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol) || parsed.search || parsed.hash) throw new Error('INVALID_DATABASE_URL');
  const caFile = process.env[`${prefix}_CA_FILE`];
  const mode = process.env[`${prefix}_SSL`] || 'disable';
  if (!['disable', 'verify-full'].includes(mode)) throw new Error('INVALID_TLS_MODE');
  return new Pool({connectionString:url,max:1,connectionTimeoutMillis:5000,statement_timeout:5000,ssl:mode==='verify-full'?{rejectUnauthorized:true,...(caFile?{ca:readFileSync(caFile,'utf8')}:{})}:false});
}
async function main() {
 const [command, memberId, userId] = process.argv.slice(2);
 const code = process.env.AUTH_APPLICATION_CODE || 'rafael';
 if(!/^[a-z][a-z0-9_-]{0,63}$/.test(code)) throw new Error('INVALID_APPLICATION_CODE');
 const iam = connection(process.env.IAM_ADMIN_DATABASE_URL || process.env.DATABASE_IAM_URL, 'DATABASE_IAM');
 let members;
 try {
  if(command==='register-application') {
   if(memberId!=='--apply') throw new Error('EXPLICIT_APPLY_REQUIRED');
   const result=await iam.query("INSERT INTO public.applications(id,codigo,nombre,estado) VALUES($1,$2,$2,'habilitada') ON CONFLICT(codigo) DO NOTHING RETURNING id",[randomUUID(),code]);
   console.log(JSON.stringify({created:result.rowCount===1,code})); return;
  }
  if(command==='pending') {
   const result=await iam.query("SELECT u.id AS user_id,e.correo_observado,e.updated_at FROM public.application_access a JOIN public.applications p ON p.id=a.application_id JOIN public.users u ON u.id=a.user_id JOIN public.external_identities e ON e.user_id=u.id WHERE p.codigo=$1 AND a.estado='pendiente' ORDER BY e.updated_at DESC LIMIT 50",[code]);
   console.log(JSON.stringify(result.rows,null,2)); return;
  }
  if(command!=='link-member' || !/^[1-9][0-9]*$/.test(memberId||'') || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(userId||'')) throw new Error('USAGE: link-member MEMBER_ID IAM_UUID [--apply]');
  const identity=await iam.query("SELECT u.id,e.correo_observado,p.id AS application_id,a.estado AS access_state FROM public.users u JOIN public.external_identities e ON e.user_id=u.id JOIN public.application_access a ON a.user_id=u.id JOIN public.applications p ON p.id=a.application_id WHERE u.id=$1 AND u.estado='habilitado' AND e.issuer='https://accounts.google.com' AND e.correo_verificado=true AND e.correo_observado ILIKE '%@utem.cl' AND p.codigo=$2 AND p.estado='habilitada'",[userId,code]);
  if(identity.rows.length!==1 || identity.rows[0].access_state==='suspendido') throw new Error('IDENTITY_OR_ACCESS_NOT_ELIGIBLE');
  const found=identity.rows[0];
  members=connection(process.env.MEMBERS_ADMIN_DATABASE_URL,'DATABASE');
  const check=await members.query('SELECT id::text,iam_subject,estado,lower(btrim(correo_institucional)) AS email FROM public.miembros WHERE id=$1',[memberId]);
  const member=check.rows[0];
  if(!member || member.estado!=='activo' || (member.iam_subject && member.iam_subject!==userId) || member.email!==found.correo_observado) throw new Error('MEMBER_CONFLICT_REVIEW_REQUIRED');
  if(!process.argv.includes('--apply')) { console.log(JSON.stringify({reviewOnly:true,memberId,userId,code,message:'Verify the person independently before running --apply. No changes made.'})); return; }
  const business=await members.connect();
  try {
   await business.query('BEGIN');
   const updated=await business.query("UPDATE public.miembros SET iam_subject=$1 WHERE id=$2 AND estado='activo' AND (iam_subject IS NULL OR iam_subject=$1) AND lower(btrim(correo_institucional))=$3 RETURNING id",[userId,memberId,found.correo_observado]);
   if(updated.rowCount!==1) throw new Error('MEMBER_CHANGED');
   await business.query("INSERT INTO public.iam_link_audit_events(member_id,iam_subject,operator_name,action) VALUES($1,$2,$3,'link_confirmed')",[memberId,userId,userInfo().username]);
   await business.query('COMMIT');
  } catch(error) {await business.query('ROLLBACK');throw error;} finally {business.release();}
  const client=await iam.connect();
  try {
   await client.query('BEGIN');
   const access=await client.query("UPDATE public.application_access a SET estado='habilitado',granted_by=$1,granted_service=NULL,grant_reason=NULL,granted_at=clock_timestamp() FROM public.users u,public.applications p WHERE a.user_id=$1 AND a.application_id=$2 AND a.estado IN ('pendiente','habilitado') AND u.id=a.user_id AND u.estado='habilitado' AND p.id=a.application_id AND p.estado='habilitada' RETURNING a.user_id",[userId,found.application_id]);
   if(access.rowCount!==1) throw new Error('ACCESS_CHANGED');
   await client.query("INSERT INTO public.audit_events(application_id,actor_service,action,target_type,target_id,resultado) VALUES($1,$2,'access.enabled_by_operator','user',$3,'exito')",[found.application_id,`local:${userInfo().username}`,userId]);
   await client.query('COMMIT');
  } catch(error) {await client.query('ROLLBACK');throw error;} finally {client.release();}
  console.log(JSON.stringify({linked:true,accessEnabled:true,technicalRolesGranted:false,memberId,userId}));
 } finally {await members?.end();await iam.end();}
}
main().catch(()=>{console.error('OPERATION_NOT_COMPLETED: verify arguments, schema, privileges and identity. If member was linked, rerun after review; no automatic unlink or reactivation.');process.exitCode=1;});
