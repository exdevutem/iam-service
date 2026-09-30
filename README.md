# ExDev ID ‚Äî IAM Service

Base NestJS 12 / TypeScript estricto / PostgreSQL con pg. Sigue el patron modular de exdev-apply-api; no copia su configuracion ni credenciales. Incluye login Google UTEM, sesiones opacas y lectura de permisos por aplicacion; administracion web y guardas de la API de negocio siguen pendientes.

## Ingreso autom·tico a Rafael ó 2026-09-30

Un miembro activo con correo institucional verificado por Google puede vincularse y habilitar su acceso b·sico autom·ticamente, sin aprobaciÛn manual ni concesiÛn de roles. La polÌtica solo aplica a Rafael; no reactiva suspensiones. El vÌnculo y su auditorÌa se escriben mediante una funciÛn restringida en negocio, y la habilitaciÛn se audita en IAM como actor de servicio. Los reintentos entre ambas bases son idempotentes.

Antes de activar este cÛdigo, aplicar por separado `008_rafael_vinculacion_automatica_negocio.sql` en negocio y `009_rafael_acceso_automatico_iam.sql` en IAM. Est·n preparados, sin ejecutar, en `Knowledge/Software/ExDev/rafael`, junto con `Ingreso automatico Rafael.md`, que detalla permisos mÌnimos, pruebas y despliegue manual. Configurar DATABASE_URL con un login dedicado que herede `exdev_iam_membership_runtime`; no concederle el rol propietario `exdev_iam_link_owner` ni UPDATE general sobre miembros. No se modificaron secretos del entorno.

Las notas de implementaciÛn anteriores que requieren link-member para el primer ingreso quedan reemplazadas para Rafael por esta polÌtica. El operador sigue disponible para excepciones.

## Arranque local

Node.js 24 LTS. Ejecutar npm ci, configurar .env a partir de .env.example sin sobrescribir secretos existentes y npm run start:dev. Puerto predeterminado 3002, host 127.0.0.1. Si .env ya define PORT, ese valor prevalece. / conserva la respuesta inicial Hello World!.

- GET /health/live: proceso HTTP vivo, sin consultar PostgreSQL.
- GET /health/ready: 200 si SELECT 1 funciona; 503 si BD deshabilitada o caida. No valida tablas/migraciones IAM.

DATABASE_ENABLED=false permite trabajar con la base de codigo sin credenciales en development/test. Produccion exige true y DATABASE_IAM_URL valida. No hay conexion al arrancar: readiness debe gobernar el trafico del proxy; cada operacion de BD falla cerrada si no hay pool. No desplegar funcionalidades privadas hasta incorporar guardas IAM.

## PostgreSQL

DATABASE_IAM_URL identifica exclusivamente la base IAM del ambiente, nunca la de negocio. Formato de ejemplo: postgresql://usuario:password-codificado@host:5432/base_iam. Configurar DATABASE_ENABLED=true solo al tener acceso autorizado. Los secretos con caracteres especiales deben codificarse para URL. No se crean bases, tablas, usuarios ni migraciones al arrancar.

DATABASE_IAM_SSL=verify-full valida certificado y hostname; DATABASE_IAM_CA_FILE opcional para CA privada. disable solo cuando la topologia permite conexion sin TLS (por ejemplo loopback o tunel protegido); decidirlo explicitamente en la VM. No se admite rejectUnauthorized=false ni parametros SSL en DATABASE_IAM_URL que anulen la politica. No registrar URL ni secretos.

Pool maximo predeterminado 10 por proceso: dimensionar replicas por limite PostgreSQL. Timeout de conexion 3 s, consulta/statement 5 s, conexion idle 30 s y transaccion idle 10 s. Sin reintentos automaticos de escrituras ni transacciones. Si falla COMMIT puede haber resultado incierto: resolver con idempotencia de negocio, no repetir ciegamente. El pool se cierra al apagar; su listener de errores registra solo codigo seguro. No cambiar parser bigint: IDs siguen siendo strings.

## Estructura y extension

- config: validacion de variables y configuracion HTTP reusable en pruebas.
- common: filtro HTTP seguro y correlacion por request ID generado por servidor.
- shared/shared.module.ts: exporta DatabaseModule explicitamente, sin convertir toda la infraestructura en global.
- shared/connections: PG_POOL compatible con la otra API y DatabaseService con query parametrizada, transacciones en un mismo cliente, rollback y release.
- health: liveness/readiness.

Cada funcionalidad futura (auth, users, applications, access, sessions, audit) tendra module, service, controller y dto cuando se implemente. Importar SharedModule en el modulo que use BD; inyectar DatabaseService o PG_POOL en repositorios. No abrir pools por peticion ni ejecutar SQL en controllers. No crear CRUD publico generado para entidades IAM.

ValidationPipe exige DTO como clases decoradas para aplicar whitelist. Helmet, no-store y supresion de x-powered-by estan activos. Errores inesperados/5xx no exponen detalles internos; no se registran URLs, cuerpos ni tokens. No se confia en X-Request-Id enviado por cliente. Autenticacion/CSRF/rate limiting/proxy trust se implementaran junto al login, no estan resueltos por estas cabeceras.

No se habilita CORS: el dise√±o es mismo origen con proxy /auth hacia IAM y /api hacia negocio. No se fija prefijo /api en este servicio. CORS no es autorizacion. En VM definir HOST segun red (0.0.0.0 solo detras de firewall/proxy), TLS y reverse proxy; revisar explicitamente trust proxy al implementar cookies. Conservada intacta WEB_ORIGINS de la API de negocio.

## Verificacion

npm run build
npm run lint
npm test -- --runInBand
npm run test:e2e -- --runInBand

npm run start:prod ejecuta el build; no es despliegue. Commit de package-lock.json y uso de npm ci en CI. Tests usan doubles de pool, no BD real; probar conectividad y migraciones por separado cuando exista configuracion autorizada. Las migraciones/planes viven en Knowledge/Software/ExDev/rafael.

## Login Google implementado ‚Äî 2026-09-28

Modulos auth, applications y membership agregados. Endpoints: GET /auth/login, /auth/callback, /auth/me, /auth/csrf; POST /auth/logout, /auth/logout-all; POST privado /internal/sessions/validate. Restricci√≥n actual: Google UTEM verificado, miembro activo vinculado y acceso IAM habilitado. Pendiente de v√≠nculo no recibe sesi√≥n. No hay concesi√≥n autom√°tica de roles.

Ver la gu√≠a Google local - Primer login.md en Knowledge/Software/ExDev/rafael. AUTH_ENABLED=false hasta configurar cliente Google, clave, origen y base de miembros. DATABASE_IAM_URL habilita BD por defecto cuando est√° presente, salvo DATABASE_ENABLED=false expl√≠cito; debe apuntar a IAM, no a la base de negocio. La conexi√≥n previa del usuario apunta a miembros y debe separarse antes de habilitar login.

DATABASE_URL es lectura del perfil, conexi√≥n separada, sin escrituras en runtime. scripts/iam-operator.cjs es operaci√≥n local expl√≠cita con credenciales administrativas separadas; no se ejecuta al arrancar. No se ejecutaron migraciones ni comandos de habilitaci√≥n. Las tablas IAM deben existir y la aplicaci√≥n debe registrarse manualmente.

El login confirma identidad, no MFA ni autenticaci√≥n reciente garantizada del proveedor. No se exponen operaciones administrativas sensibles web hasta completar esos controles. Configurar cleanup peri√≥dico de login_transactions expiradas y sesiones antiguas, y rate limiting distribuido antes de m√∫ltiples r√©plicas. La clave criptogr√°fica tiene versi√≥n 1 en esta entrega; rotaci√≥n de clave requiere invalidar transacciones de login pendientes y coordinar revocaci√≥n de sesiones. No confundir authenticated_at local con auth_time/MFA de Google.

Rafael y exdev-apply-api no se modificaron en esta etapa. Cookies y autorizaci√≥n de la API de negocio todav√≠a necesitan integraci√≥n mediante proxy/guardas; el login IAM por s√≠ solo no protege los endpoints existentes.

