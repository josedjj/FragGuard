# FragGuard 🛡️🎮

Antivirus **ligero para gamers** en Windows 10/11 (MVP v0.1). Su ventaja diferencial: consumo mínimo de recursos y un **modo juego** que no interrumpe ni baja los FPS.

- Escaneo manual **rápido / completo / personalizado**.
- **Protección en tiempo real** a nivel de usuario (Descargas + carpetas de mods).
- **Cuarentena cifrada** (AES-256-GCM) con restaurar / eliminar.
- **Modo juego automático**: pausa escaneos programados, silencia avisos no críticos y baja la prioridad de CPU y E/S.
- Reglas **YARA** contra *infostealers* de Discord, Steam y navegadores, y avisos por nombres de **cheats / trainers / "free skins"**.
- Consulta de hashes en **VirusTotal** y **MalwareBazaar**, y de URLs de descarga (Mark-of-the-Web) en **URLhaus**. Nunca sube archivos y las claves las pone el usuario.
- **Firmas Authenticode** y editores de confianza (Valve, Riot, Epic, NVIDIA...) para reducir falsos positivos; detección de **PUP** y mineros.
- **Reglas YARA actualizables** por un canal firmado con ECDSA P-256 (nunca se aceptan reglas sin firma válida).
- **Protección en ejecución** (sección 7): reglas de comportamiento sobre procesos nuevos, escudo **anti-ransomware** con señuelos, **protección de cuentas** de Discord/Steam/navegadores, aviso de uso de **cámara y micrófono**, vigilancia de **autoruns** y de exclusiones de Defender, **USB**, escaneo de **memoria** bajo demanda y **DNS protegido** opcional.
- **Extensión de navegador** (Chrome/Edge, MV3) que bloquea ~21 800 dominios de estafas de Steam/Discord/skins.
- Página **Juegos**: juegos instalados (Steam, Epic, Riot, EA, Ubisoft, GOG, Battle.net, Rockstar), última vez jugado, tamaño, **Jugar** y **Desinstalar sin dejar restos**.
- Sin drivers ni hooks de kernel, sin inyección en procesos: **compatible con Vanguard, Easy Anti-Cheat y BattlEye**. Todo funciona en modo usuario.

> ⚠️ FragGuard es una capa **complementaria**. Windows Defender sigue activo: para sustituirlo en el Centro de seguridad de Windows hace falta un driver ELAM firmado y pertenecer al programa MVI de Microsoft.

---

## 1. Arquitectura

```
┌──────────── Sesión del usuario ────────────┐         ┌──────────── Sesión 0 (LocalSystem) ─────────────┐
│ FragGuard.exe (WPF, vive en la bandeja)     │  named  │ FragGuard.Service.exe (Worker Service)           │
│  • Panel, escaneos, cuarentena, ajustes     │  pipe   │  • PipeServer  (\\.\pipe\FragGuard.v1)           │
│  • Protección, Inicio de Windows, Juegos    │         │  • RealtimeProtection (FileSystemWatcher)        │
│  • Detector de pantalla completa  ──────────┼────────►│  • GameMode (Toolhelp + pantalla completa)       │
│  • Notificaciones (bandeja)       ◄─────────┼─eventos─│  • ProcessMonitor (reglas de comportamiento)     │
│  • Carpetas del usuario (Descargas...) ─────┼────────►│  • RansomwareShield · AccountProtection (4663)   │
└─────────────────────────────────────────────┘         │  • Privacy · Persistence · RemovableDrives       │
                                                        │  • ScanCoordinator + ScheduledScan + RulesUpdate │
                                                        │  • ResourceMonitor / SelfIntegrity / DNS         │
                                                        │            │ FragGuard.Core (motor)              │
                                                        │  hash → caché → YARA → comprimidos → nube (VT,   │
                                                        │  MalwareBazaar, URLhaus) → Authenticode/política │
                                                        │  → heurística → cuarentena → SQLite              │
                                                        └──────────────────────────────────────────────────┘
Datos: %ProgramData%\FragGuard\ { fragguard.db, settings.json, quarantine\, logs\, *.key }  (ACL: SYSTEM + Administradores)
```

### Estructura de la solución

```
FragGuard.sln
├── Directory.Build.props            Ajustes comunes (x64, nullable, versión)
├── rules/                           Reglas YARA de ejemplo (se copian junto al servicio)
├── scripts/                         install, uninstall, sign, new-dev-certificate, build-extension
├── browser-extension/               Extensión MV3 (declarativeNetRequest) contra estafas gamer
├── src/
│   ├── FragGuard.Shared/   net8.0          DTOs, protocolo del pipe, JSON source-generated
│   ├── FragGuard.Core/     net8.0-windows  Motor: YARA, hashing, comprimidos, nube, Authenticode, reglas de
│   │                                       comportamiento, autoruns, canal de reglas firmado, cuarentena, SQLite
│   ├── FragGuard.Service/  net8.0-windows  Servicio de Windows (protección en ejecución)
│   └── FragGuard.UI/       net8.0-windows  Interfaz WPF (solo referencia Shared, nunca analiza nada)
├── tools/FragGuard.RulesSigner/            Firma del canal de reglas (clave privada FUERA del repo)
└── tests/FragGuard.Core.Tests/             138 tests (xUnit) + corpus de falsos positivos opcional
```

### Dependencias NuGet

| Proyecto | Paquetes |
|---|---|
| Shared | ninguno |
| Core | `dnYara` 2.1.0 + `dnYara.NativePack` (libyara 4.x x64), `Microsoft.Data.Sqlite` 8, `Dapper` 2.1, `SharpCompress` 0.50, `System.Security.Cryptography.ProtectedData` 8, `System.Threading.RateLimiting` 8, `Microsoft.Extensions.Logging.Abstractions` / `DependencyInjection.Abstractions` 8 |
| Service | `Microsoft.Extensions.Hosting(.WindowsServices)` 8, `Serilog.Extensions.Hosting`, `Serilog.Sinks.File`, `Serilog.Sinks.Console`, `Serilog.Settings.Configuration` |
| UI | `CommunityToolkit.Mvvm` 8.4, `H.NotifyIcon.Wpf` **2.3.2** (la 2.4 ya no trae binarios para .NET 8), `Serilog`, `Serilog.Sinks.File` |

---

## 2. Requisitos

- Windows 10/11 x64.
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) para compilar. Para ejecutar basta el **.NET 8 Desktop Runtime**, o instala con `-SelfContained`.
- PowerShell **como administrador** para instalar.

## 3. Compilar y probar

```powershell
cd E:\Antivirus
dotnet build FragGuard.sln
dotnet test                           # 138 tests: deben pasar todos

# Corpus de falsos positivos (lento): analiza ~6000 ejecutables reales del equipo y exige 0 maliciosos
$env:FG_FP_CORPUS = 1; dotnet test --filter "FullyQualifiedName~FalsePositiveCorpus" --logger "console;verbosity=detailed"
```

Último resultado del corpus: **6000 archivos, 0 maliciosos, 1 sospechoso** (`ssh-keygen.exe` por la heurística de nombres; corregido después y cubierto por un test). Ejecútalo antes de publicar reglas nuevas.

## 4. Ejecutar en modo desarrollo (sin instalar)

```powershell
# Terminal 1: servicio como consola (datos en src\FragGuard.Service\devdata, sin exigir admin)
cd src\FragGuard.Service
$env:DOTNET_ENVIRONMENT = 'Development'
dotnet run

# Terminal 2: interfaz
dotnet run --project src\FragGuard.UI
```

`appsettings.Development.json` solo se usa así. Redirige los datos, no endurece la ACL y no exige administrador para cambiar ajustes. Nunca se copia a la instalación.

## 5. Instalar

```powershell
# PowerShell COMO ADMINISTRADOR
cd E:\Antivirus
.\scripts\install.ps1                 # servicio + interfaz
.\scripts\install.ps1 -SelfContained  # sin necesitar el runtime de .NET instalado
```

Qué hace el instalador:

1. Publica en Release y copia a `C:\Program Files\FragGuard\{Service,UI}`.
2. Registra el servicio `FragGuardService` (LocalSystem, inicio automático **retrasado** y reinicio si se cae).
3. Crea el acceso directo en el menú Inicio y el arranque de la UI en la bandeja al iniciar sesión.

Comprobar que funciona:

```powershell
Get-Service FragGuardService                                   # Status: Running
Get-Content "$env:ProgramData\FragGuard\logs\service-*.log" -Tail 20
```

Para desinstalar: `.\scripts\uninstall.ps1`. Añade `-PurgeData` para borrar también el historial y la cuarentena.

### Firma de código (Authenticode)

`install.ps1` firma automáticamente **solo los binarios propios** (`FragGuard*.exe` / `FragGuard*.dll`) si encuentra un certificado. Sin certificado, instala sin firmar y muestra un aviso.

**Uso personal (certificado de desarrollo, válido solo en este PC):**

```powershell
# PowerShell COMO ADMINISTRADOR
.\scripts\new-dev-certificate.ps1     # crea el certificado (clave NO exportable) y lo marca de confianza en este equipo
.\scripts\install.ps1                 # publica, FIRMA e instala
Get-AuthenticodeSignature "C:\Program Files\FragGuard\UI\FragGuard.exe"   # Status: Valid
```

Para quitarlo: `.\scripts\new-dev-certificate.ps1 -Remove`.

> ⚠️ El certificado de desarrollo se añade como **raíz de confianza** del equipo. Su clave privada no es exportable y solo sirve para firmar código, pero aun así elimínalo cuando no lo necesites.

**Distribución a otras personas (certificado comercial OV/EV):**

```powershell
.\scripts\install.ps1 -PfxPath C:\certs\fragguard.pfx          # o bien:
.\scripts\install.ps1 -CertificateThumbprint 0123ABCD...
.\scripts\sign.ps1 -Path .\artifacts\ui -Thumbprint 0123ABCD... # firmar una carpeta suelta
```

Las firmas llevan **sello de tiempo** (se envía solo el *hash* de cada archivo a `timestamp.digicert.com`) para que sigan siendo válidas aunque el certificado caduque. Usa `-NoTimestamp` en `sign.ps1` para firmar sin conexión.

## 6. Prueba de extremo a extremo con EICAR

[EICAR](https://www.eicar.org/download-anti-malware-testfile/) es un archivo de prueba **inofensivo** que todos los antivirus detectan a propósito. Defender lo eliminaría antes que FragGuard, así que se usa una carpeta excluida **solo durante la prueba**.

```powershell
# 1) PowerShell como ADMINISTRADOR: carpeta de prueba excluida de Defender
New-Item -ItemType Directory C:\FragGuardTest -Force
Add-MpPreference -ExclusionPath C:\FragGuardTest
```

2. Abre FragGuard. En **Ajustes**, pulsa **Reabrir como administrador** (aparece el aviso de UAC).
3. En **Protección en tiempo real**, pulsa **Añadir carpeta**, elige `C:\FragGuardTest` y pulsa **Guardar cambios**.

```powershell
# 4) Crear el archivo EICAR (se construye en dos mitades para que este README no sea "detectable")
$a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-'
$b = 'ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path C:\FragGuardTest\eicar_test.exe -Value ($a + $b) -NoNewline -Encoding ASCII
```

**Resultado esperado (en 2-3 s):**

- Notificación **"Amenaza bloqueada"** con `eicar_test.exe` y `FG_Test_EICAR`, movido a cuarentena.
- El archivo desaparece de `C:\FragGuardTest`.
- Aparece en **Cuarentena** y en **Historial**, y el contador **Amenazas bloqueadas** sube en el **Panel**.

Variante: vuelve a crear el archivo, desactiva el tiempo real y usa **Escanear → Personalizado → `C:\FragGuardTest`**.

```powershell
# 5) Limpieza: quita la exclusión de Defender
Remove-MpPreference -ExclusionPath C:\FragGuardTest
Remove-Item C:\FragGuardTest -Recurse -Force
```

> Si restauras EICAR desde la cuarentena a una carpeta no excluida, Defender lo borrará. Es lo esperado.

### Otras pruebas sin malware real

| Prueba | Cómo | Esperado |
|---|---|---|
| Nombre de cheat | Crea `CS2_Aimbot_Free.exe` (cualquier contenido) en una carpeta vigilada | Aviso **Sospechoso**. No se pone en cuarentena |
| Cheat en ejecución | Copia `C:\Windows\System32\PING.EXE` como `%TEMP%\Valorant_Aimbot.exe` y ejecútalo con `-n 30 127.0.0.1` | Aviso **"Posible cheat en ejecución"** con botón **Cerrar proceso** |
| Modo juego | Abre un juego de la lista, uno lanzado desde Steam/Epic, o cualquier app a pantalla completa | Chip **MODO JUEGO** en el panel y el servicio en prioridad baja |
| Bloqueo sin admin | Con la UI sin elevar, intenta **Guardar cambios** | Pide reabrir como administrador |

## 7. Protección en ejecución (modo usuario, sin drivers)

Cada módulo se activa o desactiva en **Ajustes → Protección en ejecución**, y su estado se ve en la página **Protección**.

| Módulo | Cómo funciona | Respuesta |
|---|---|---|
| **Reglas de comportamiento** | Instantánea de procesos cada 1,5 s (3 s en modo juego) y lectura de la línea de comandos de `vssadmin`, `wmic`, `bcdedit`, `powershell`, `certutil`, `schtasks`... Detecta borrado de copias de sombra, desactivar la recuperación, exclusiones o desactivar Defender, PowerShell oculto/codificado, descargas con LOLBins y tareas programadas sospechosas. | Avisar, detener el proceso o detener también a su **origen** (y aislarlo si está en una carpeta de usuario). Si el origen está firmado por un editor de confianza, solo avisa. |
| **Anti-ransomware** | Señuelos ocultos en Documentos, Escritorio e Imágenes, más detección de renombrados/cifrados masivos. El culpable se identifica por sus contadores de E/S (`GetProcessIoCounters`). | Detiene el proceso y lo aísla. |
| **Protección de cuentas** | Auditoría de Windows (SACL + evento **4663**) sobre los tokens de Discord, `ssfn`/`config` de Steam y los `Login Data`/`Cookies` de los navegadores. | Si un proceso que no es el propio cliente los lee: lo detiene y avisa. |
| **Cámara y micrófono** | Lee cada 5 s el `ConsentStore` de Windows (qué app los usa y desde cuándo). | Avisa si un programa sin firma de confianza empieza a usarlos. |
| **Inicio de Windows** | Inventario de Run/RunOnce, carpetas de Inicio, tareas programadas y servicios. Página **Inicio de Windows** para revisar, **desactivar** y **restaurar**. Vigila también las exclusiones de Defender. | Avisa de entradas nuevas sin firma de confianza. |
| **USB** | Al conectar una unidad extraíble revisa `autorun.inf` y analiza ejecutables, scripts y comprimidos de los 3 primeros niveles; después la vigila en tiempo real mientras esté conectada. | Cuarentena de lo malicioso. |
| **Memoria** | Escaneo YARA de la memoria de procesos **bajo demanda** (Escanear → Memoria), nunca en modo juego. | **Solo avisa**: no detiene nada, para no matar procesos legítimos por un falso positivo. |
| **DNS protegido** | Opcional (Ajustes → Red): pone **Quad9** (9.9.9.9, bloquea dominios maliciosos) con DNS-over-HTTPS y guarda la configuración anterior para restaurarla. | Bloqueo a nivel de red. |
| **Autoprotección** | Al arrancar comprueba la firma Authenticode de sus binarios (firma inválida = alguien los modificó). Los binarios y datos tienen ACL de administradores, y la UI avisa si el servicio deja de responder más de 15 s. | Avisos. |

**Límite honesto**: sin driver no se puede impedir que un proceso arranque. Las reglas actúan **después** (hasta 1,5 s), lo que basta para cortar la mayoría de cadenas de ransomware y stealers, pero no todas.

## 8. Servicios en la nube (opcionales)

### VirusTotal

1. Crea una cuenta gratuita en [virustotal.com](https://www.virustotal.com) y copia tu **API key** (perfil → API key).
2. En FragGuard (como administrador) ve a **Ajustes → VirusTotal**, pega la clave y pulsa **Guardar clave**.

La clave se guarda cifrada con DPAPI en `%ProgramData%\FragGuard\vt.key` y nunca vuelve a la UI ni aparece en los logs. Solo se consultan **hashes SHA-256** de ejecutables, scripts y comprimidos, respetando la cuota gratuita (4/min, 500/día). Si no queda cuota, el escaneo continúa sin esperar.

### abuse.ch (MalwareBazaar + URLhaus)

1. Crea una **Auth-Key gratuita** en [auth.abuse.ch](https://auth.abuse.ch/).
2. **Ajustes → abuse.ch**, pega la clave y pulsa **Guardar clave**.

Con ella, FragGuard consulta el **hash** en MalwareBazaar y la **URL de descarga** del archivo (Mark-of-the-Web) en URLhaus. Desde 2026 abuse.ch ya no ofrece descargas sin clave, por eso es por consulta.

### Canal de reglas firmado

El servicio descarga cada 12 h (nunca en modo juego) `manifest.json` + `manifest.sig` del repositorio público y **solo** acepta reglas cuya firma ECDSA P-256 coincida con la clave pública embebida en el binario. Si las reglas nuevas no compilan, sigue con las de serie. Para publicar reglas:

```powershell
dotnet run --project tools/FragGuard.RulesSigner -- sign rules E:\FragGuard-Releases\rules-channel
```

La clave privada vive en `%APPDATA%\FragGuard-Signing\` cifrada con DPAPI (`export-backup` para hacer copia). **Nunca** va al repositorio.

## 9. Extensión de navegador

```powershell
.\scripts\build-extension.ps1     # (opcional) descarga la lista actual y regenera browser-extension\rules
```

En Chrome/Edge: `chrome://extensions` → **Modo desarrollador** → **Cargar descomprimida** → carpeta `browser-extension` (o `C:\Program Files\FragGuard\browser-extension` tras instalar). Solo pide el permiso `declarativeNetRequest`: no lee las páginas ni el historial. Lista de dominios de [nikolaischunk/discord-phishing-links](https://github.com/nikolaischunk/discord-phishing-links) (MIT).

## 10. Banco de pruebas en máquina virtual

Las pruebas destructivas (señuelos de ransomware, reglas que detienen al proceso origen, DNS) **no** se hacen en el equipo principal:

1. VM Windows 11 (Hyper-V o VirtualBox) **sin carpetas compartidas** y con red NAT; instantánea limpia antes de cada prueba.
2. Instala FragGuard con `install.ps1 -SelfContained`.
3. Simulaciones sin malware real: `vssadmin delete shadows /all /quiet` (lanzado desde un `.bat` en Descargas), renombrar en bucle 30 archivos de un señuelo con extensión `.locked`, leer `%APPDATA%\discord\Local Storage\leveldb\*.ldb` con PowerShell, activar el DNS protegido y resolver un dominio de prueba.
4. Revisa **Historial** y `%ProgramData%\FragGuard\logs\` y vuelve a la instantánea.
5. Para muestras reales usa solo repositorios para investigadores (MalwareBazaar) **dentro de la VM aislada**.

---

## 11. Decisiones de diseño y seguridad

| Tema | Decisión |
|---|---|
| Binding YARA | **dnYara** para compilar. El **escaneo llama directamente a libyara** (`yr_rules_scan_mem/file`): `Scanner.ScanMemory` de dnYara 2.1 tiene una **fuga de memoria nativa** (copia cada buffer con `AllocHGlobal` y no lo libera). Lo cubre el test de regresión `MemoryTests`. |
| Concurrencia YARA | Un único `YaraContext` por proceso, compilación serializada y `ReaderWriterLockSlim` para recargar reglas en caliente sin crashes. Lo cubre `ConcurrentScans_AndReload_DoNotCrash`. |
| Operaciones sensibles | Cambiar ajustes, la clave de VirusTotal, restaurar o eliminar de cuarentena y cerrar procesos exigen **administrador elevado** (lo verifica el servicio suplantando al cliente). Así un malware del usuario no puede desactivar FragGuard ni "liberarse" de la cuarentena. |
| Pipe | Solo local (se deniega el acceso por red). `FirstPipeInstance` detecta suplantaciones del pipe, y la UI verifica que el servidor es `FragGuard.Service`. Mensajes limitados a 4 MB. |
| Cerrar procesos | El servicio (SYSTEM) solo cierra procesos que **él mismo marcó** como cheat. Evita usarlo para matar procesos protegidos. |
| Cuarentena | AES-256-GCM por bloques de 1 MB (RAM constante). El AAD incluye el contador y el indicador de bloque final, así que detecta manipulación y truncado. Clave aleatoria protegida con DPAPI y archivos `.fgq` no ejecutables. Si el original está en uso, se borra al reiniciar. Al restaurar se verifica el hash y el archivo pasa a la lista de permitidos. |
| Modo juego | Juegos de la lista, **hijos** de lanzadores (Steam abierto no basta) o pantalla completa informada por la UI. El servicio usa `PROCESS_MODE_BACKGROUND_BEGIN` (CPU, E/S y memoria bajas). |
| Anti-cheat | Solo APIs de lectura en modo usuario (Toolhelp, `QueryFullProcessImageName`, `SHQueryUserNotificationState`). Nada de drivers, hooks ni inyección. |
| Datos | SQLite (WAL) con Dapper; EF Core añadiría 15-25 MB de RAM. JSON con *source generators* para evitar reflexión. |
| Juegos: detección | El **servicio** (solo lectura) combina los manifiestos de Steam (`libraryfolders.vdf` + `appmanifest_*.acf`), los de Epic (`*.item`) y las claves *Uninstall* del registro (también las de cada usuario). "Última vez jugado": **Steam** usa su propio `LastPlayed` (exacto). Las demás plataformas usan **Prefetch** de Windows (requiere SYSTEM), solo con ejecutables de nombre distintivo, porque Prefetch guarda nombres y no rutas, y un `launcher.exe` de otra app daría fechas falsas. |
| Juegos: acciones | **Jugar, desinstalar y borrar restos los hace la UI con los permisos del usuario**, nunca el servicio SYSTEM. Un comando "borrar carpeta" en el servicio sería un vector de escalada de privilegios. La desinstalación usa siempre el **desinstalador oficial** (`steam://uninstall`, `UninstallString` de Riot/EA/Ubisoft...). |
| Juegos: restos | Solo carpetas con el nombre **exacto** del juego (o de su carpeta de instalación), en AppData, LocalLow, Documentos, My Games, Partidas guardadas y ProgramData, hasta 2 niveles. Nunca una carpeta que contenga otro juego instalado. Lo que puede contener partidas viene **desmarcado** y todo va a la **Papelera**. Lo cubren `LeftoverFinderTests`. |

## 12. Consumo medido (equipo de desarrollo)

Con todos los módulos de protección activos (servicio instalado, 6 minutos desde el arranque, muestras cada 5 s):

| Situación | RAM privada |
|---|---|
| Pico del arranque | **48,7 MB** |
| Reposo (desde los 2 min) | mín 37 · media ~42-43 · máx 47,7 MB |

El monitor de recursos recorta la memoria (GC compactando + working set) cuando la RAM privada supera 40 MB y ha crecido desde el último recorte: cada 30 s como mucho durante los 5 primeros minutos y cada 2 min después. `System.GC.ConserveMemory=5` y `TieredPGO=false` van en el `runtimeconfig.json`. La tabla de abajo es la medición del MVP, sin los módulos de protección.

| Proceso / situación | RAM privada | Working set | CPU |
|---|---|---|---|
| Servicio en reposo | **~26-28 MB** | ~10-16 MB | **~0,05 %** |
| Servicio escaneando (`System32\drivers`, 594 archivos) | pico 84 MB | — | — |
| Servicio en reposo tras ese escaneo | **~46 MB** | ~30 MB | ~0 % |
| UI solo en la bandeja (ventana nunca abierta) | ~21 MB | ~80 MB (incluye DLL compartidas de WPF) | 0 % |
| UI con la ventana abierta | ~150 MB | ~180-200 MB | baja |
| UI tras cerrar la ventana | memoria comprometida alta | **~20 MB** | 0 % |

La ventana se destruye al cerrarla y se recorta la memoria. El coste de WPF solo se paga mientras la ventana está abierta (ver mejoras v2).

## 13. Limitaciones conocidas

- **No bloquea la ejecución**: sin driver no se puede impedir que un archivo se ejecute. Se detecta al aparecer en disco (tiempo real) y al ejecutarse (sondeo de procesos cada 1,5 s, 3 s en modo juego).
- La protección de cuentas depende de la **auditoría de Windows** (evento 4663): llega una fracción de segundo después de la lectura.
- Las reglas YARA son **pocas y propias**: los stealers empaquetados u ofuscados (PyInstaller, ConfuserEx...) no exponen cadenas, y para ellos depende de VirusTotal/MalwareBazaar y de las reglas de comportamiento.
- No se ha hecho una **evaluación independiente** (AV-TEST, AV-Comparatives). Los señuelos de ransomware y las reglas que detienen al proceso origen solo se han probado con tests y simulaciones, no con muestras reales.
- Distribuir a otras personas requiere un **certificado de firma comercial** (si no, SmartScreen avisará).
- El escaneo completo vuelve a calcular el hash de cada archivo: no hay caché por ruta, tamaño y fecha.
- Algunos `.7z` no se pueden leer en *streaming*, y los comprimidos con contraseña no se inspeccionan (sí se analizan los nombres de sus entradas).
- Las notificaciones son *balloons* de la bandeja (Windows las muestra como toast, pero sin botones de acción).

---

## 14. Hoja de ruta (sin kernel)

Ya hecho: Authenticode y editores de confianza, canal de reglas firmado, MalwareBazaar/URLhaus, PUP y mineros, reglas de comportamiento, anti-ransomware, protección de cuentas, cámara/micrófono, autoruns, USB, escaneo de memoria, DNS protegido, extensión de navegador y corpus de falsos positivos.

Pendiente, todo en modo usuario:

1. **ETW** (`Microsoft-Windows-Kernel-Process`) en lugar de sondear procesos: detección instantánea y menos CPU.
2. **Desempaquetado de PyInstaller y análisis de ensamblados .NET** (formatos típicos de los stealers de Discord).
3. **Integridad del cliente de Discord**: hash de `discord_desktop_core\index.js` para detectar inyecciones.
4. **Caché por ruta/tamaño/fecha + USN Journal** para escaneos completos incrementales.
5. Cola persistente de consultas a la nube para los archivos que se quedaron sin cuota.
6. Instalador **MSI/MSIX** con certificado comercial y actualizaciones automáticas.
7. Notificaciones **toast nativas con acciones** y agente de bandeja ultraligero (Native AOT).
8. Interfaz en inglés, perfiles de modo juego por título e informe semanal.
9. **Evaluación independiente** y banco de pruebas automatizado en VM.

Descartado a propósito: minifiltro, ELAM, PPL y cualquier driver o inyección, por compatibilidad con los anti-cheat.

---

## 15. Solución de problemas

| Síntoma | Qué revisar |
|---|---|
| La UI dice "Servicio no disponible" | `Get-Service FragGuardService`; log en `%ProgramData%\FragGuard\logs\` |
| "Guardar cambios" pide admin | Es intencionado: usa **Reabrir como administrador** |
| No detecta EICAR | ¿Defender lo borró antes? Revisa la exclusión. ¿La carpeta está en **Carpetas vigiladas** y la extensión en la lista? |
| Regla YARA propia no carga | Revisa el log del servicio: las reglas con errores se omiten con un mensaje `Regla YARA inválida` |
| Logs de la UI | `%LOCALAPPDATA%\FragGuard\logs\ui-*.log` |
| Protección de cuentas "inactiva" | Requiere que el servicio pueda activar la auditoría de *Sistema de archivos*; revisa el log (`AuditSetSystemPolicy`) y que ninguna directiva de grupo la bloquee |
| Un programa legítimo fue detenido por una regla | **Historial** muestra la regla y quién lo lanzó; desactiva temporalmente **Reglas de comportamiento** en Ajustes y avísanos con el nombre de la regla |
| Sin Internet tras activar DNS protegido | Desactívalo en **Ajustes → Red**: restaura la configuración guardada en `%ProgramData%\FragGuard\dns-backup.json` |
