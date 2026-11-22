# FragGuard 🛡️🎮

Antivirus **ligero para gamers** en Windows 10/11 (MVP v0.1). Su ventaja diferencial: consumo mínimo de recursos y un **modo juego** que no interrumpe ni baja los FPS.

- Escaneo manual **rápido / completo / personalizado**.
- **Protección en tiempo real** a nivel de usuario (Descargas + carpetas de mods).
- **Cuarentena cifrada** (AES-256-GCM) con restaurar / eliminar.
- **Modo juego automático**: pausa escaneos programados, silencia avisos no críticos y baja la prioridad de CPU y E/S.
- Reglas **YARA** contra *infostealers* de Discord, Steam y navegadores, y avisos por nombres de **cheats / trainers / "free skins"**.
- Consulta de hashes en **VirusTotal**. Nunca sube archivos y la clave la pone el usuario.
- Página **Juegos**: juegos instalados (Steam, Epic, Riot, EA, Ubisoft, GOG, Battle.net, Rockstar), última vez jugado, tamaño, **Jugar** y **Desinstalar sin dejar restos**.
- Sin drivers ni hooks de kernel, sin inyección en procesos: **compatible con Vanguard, Easy Anti-Cheat y BattlEye**.

> ⚠️ FragGuard es una capa **complementaria**. Windows Defender sigue activo: para sustituirlo en el Centro de seguridad de Windows hace falta un driver ELAM firmado y pertenecer al programa MVI de Microsoft.

---

## 1. Arquitectura

```
┌──────────── Sesión del usuario ────────────┐         ┌──────────── Sesión 0 (LocalSystem) ─────────────┐
│ FragGuard.exe (WPF, vive en la bandeja)     │  named  │ FragGuard.Service.exe (Worker Service)           │
│  • Panel, escaneos, cuarentena, ajustes     │  pipe   │  • PipeServer  (\\.\pipe\FragGuard.v1)           │
│  • Detector de pantalla completa  ──────────┼────────►│  • RealtimeProtection (FileSystemWatcher)        │
│  • Notificaciones (bandeja)       ◄─────────┼─eventos─│  • GameMode (Toolhelp + pantalla completa)       │
│  • Carpetas del usuario (Descargas...) ─────┼────────►│  • ScanCoordinator + ScheduledScan               │
└─────────────────────────────────────────────┘         │  • ResourceMonitor / ProcessPriority             │
                                                        │            │ FragGuard.Core (motor)              │
                                                        │  hash → caché → YARA → comprimidos → VirusTotal  │
                                                        │  → heurística → cuarentena → SQLite              │
                                                        └──────────────────────────────────────────────────┘
Datos: %ProgramData%\FragGuard\ { fragguard.db, settings.json, quarantine\, logs\, *.key }  (ACL: SYSTEM + Administradores)
```

### Estructura de la solución

```
FragGuard.sln
├── Directory.Build.props            Ajustes comunes (x64, nullable, versión)
├── rules/                           Reglas YARA de ejemplo (se copian junto al servicio)
├── scripts/install.ps1, uninstall.ps1
├── src/
│   ├── FragGuard.Shared/   net8.0          DTOs, protocolo del pipe, JSON source-generated
│   ├── FragGuard.Core/     net8.0-windows  Motor: YARA, hashing, comprimidos, VirusTotal, cuarentena, SQLite
│   ├── FragGuard.Service/  net8.0-windows  Servicio de Windows
│   └── FragGuard.UI/       net8.0-windows  Interfaz WPF (solo referencia Shared, nunca analiza nada)
└── tests/FragGuard.Core.Tests/             54 tests (xUnit): detección, cuarentena, concurrencia, memoria...
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
dotnet test                           # 54 tests: deben pasar todos
```

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

## 7. Configurar VirusTotal (opcional)

1. Crea una cuenta gratuita en [virustotal.com](https://www.virustotal.com) y copia tu **API key** (perfil → API key).
2. En FragGuard (como administrador) ve a **Ajustes → VirusTotal**, pega la clave y pulsa **Guardar clave**.

La clave se guarda cifrada con DPAPI en `%ProgramData%\FragGuard\vt.key` y nunca vuelve a la UI ni aparece en los logs. Solo se consultan **hashes SHA-256** de ejecutables, scripts y comprimidos, respetando la cuota gratuita (4/min, 500/día). Si no queda cuota, el escaneo continúa sin esperar.

---

## 8. Decisiones de diseño y seguridad

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

## 9. Consumo medido (MVP, equipo de desarrollo)

| Proceso / situación | RAM privada | Working set | CPU |
|---|---|---|---|
| Servicio en reposo | **~26-28 MB** | ~10-16 MB | **~0,05 %** |
| Servicio escaneando (`System32\drivers`, 594 archivos) | pico 84 MB | — | — |
| Servicio en reposo tras ese escaneo | **~46 MB** | ~30 MB | ~0 % |
| UI solo en la bandeja (ventana nunca abierta) | ~21 MB | ~80 MB (incluye DLL compartidas de WPF) | 0 % |
| UI con la ventana abierta | ~150 MB | ~180-200 MB | baja |
| UI tras cerrar la ventana | memoria comprometida alta | **~20 MB** | 0 % |

La ventana se destruye al cerrarla y se recorta la memoria. El coste de WPF solo se paga mientras la ventana está abierta (ver mejoras v2).

## 10. Limitaciones conocidas del MVP

- **No bloquea la ejecución**: sin driver no se puede impedir que un archivo se ejecute. Se detecta al aparecer en disco (tiempo real) y al ejecutarse (sondeo de procesos cada 3 s).
- Las reglas YARA son **ejemplos educativos**: los stealers empaquetados u ofuscados (PyInstaller, ConfuserEx...) no exponen cadenas, y para ellos depende de VirusTotal.
- El escaneo completo vuelve a calcular el hash de cada archivo: no hay caché por ruta, tamaño y fecha.
- Algunos `.7z` no se pueden leer en *streaming*, y los comprimidos con contraseña no se inspeccionan (sí se analizan los nombres de sus entradas).
- Las notificaciones son *balloons* de la bandeja (Windows las muestra como toast, pero sin botones de acción).

---

## 11. Mejoras sugeridas para la versión 2

**Detección**
1. **Actualización automática y firmada de reglas YARA** (descarga periódica con verificación de firma) e integración de colecciones públicas como YARA-Forge.
2. **Verificación Authenticode y reputación de editor** (`WinVerifyTrust`): no alertar sobre binarios firmados por Valve, Riot, Epic, NVIDIA... Reduce mucho los falsos positivos.
3. **Desempaquetado de PyInstaller y análisis de ensamblados .NET**, que son los formatos más usados por los stealers de Discord.
4. **Monitor de integridad del cliente de Discord**: hash del `index.js` de `discord_desktop_core` para detectar inyecciones al momento.
5. Escaneo de memoria de procesos bajo demanda (`yr_rules_scan_proc`), **solo con el modo juego inactivo** para no chocar con los anti-cheat.
6. Cola persistente de consultas a VirusTotal para los archivos que se quedaron sin cuota, y subida opcional con consentimiento explícito.

**Rendimiento**
7. **Caché por ruta, tamaño y fecha + USN Journal** para que el escaneo completo solo analice lo que ha cambiado.
8. **Agente de bandeja ultraligero** (Native AOT, < 10 MB) y ventana WPF solo bajo demanda, en otro proceso.
9. **Native AOT** para el servicio: menos RAM y arranque instantáneo.
10. **ETW** (`Microsoft-Windows-Kernel-Process`) en lugar de sondear procesos: detección instantánea de ejecuciones y CPU aún menor.

**Producto**
11. Instalador **MSI/MSIX** (WiX) con **firma de código**, actualizaciones automáticas y desinstalación limpia.
12. Notificaciones **toast nativas con acciones** ("Ver", "Restaurar", "Cerrar proceso") mediante Windows App SDK.
13. Perfiles de modo juego por título (p. ej. sin escaneos con Valorant, bajo impacto con juegos *single player*).
14. Informe semanal ("X descargas analizadas, Y amenazas bloqueadas") e historial exportable.
15. Interfaz en inglés y español.

**Protección del propio antivirus**
16. *Self-protection*: ACL del servicio que impida a los usuarios detenerlo y vigilancia de sus binarios. A largo plazo, ELAM + *Protected Process Light* (requiere MVI).
17. Opcional y con mucho cuidado por los anti-cheat: un **minifiltro de sistema de archivos firmado** para bloquear antes de ejecutar.

---

## 12. Solución de problemas

| Síntoma | Qué revisar |
|---|---|
| La UI dice "Servicio no disponible" | `Get-Service FragGuardService`; log en `%ProgramData%\FragGuard\logs\` |
| "Guardar cambios" pide admin | Es intencionado: usa **Reabrir como administrador** |
| No detecta EICAR | ¿Defender lo borró antes? Revisa la exclusión. ¿La carpeta está en **Carpetas vigiladas** y la extensión en la lista? |
| Regla YARA propia no carga | Revisa el log del servicio: las reglas con errores se omiten con un mensaje `Regla YARA inválida` |
| Logs de la UI | `%LOCALAPPDATA%\FragGuard\logs\ui-*.log` |
