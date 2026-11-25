# Política de seguridad

FragGuard es un antivirus: se ejecuta como **SYSTEM** y decide qué archivos se aíslan o qué procesos se detienen. Un fallo de seguridad en él puede ser grave, así que te pedimos que lo comuniques **en privado**.

## Cómo informar de una vulnerabilidad

1. Ve a la pestaña [**Security**](../../security) de este repositorio y pulsa **Report a vulnerability** (aviso privado de GitHub).
2. Describe el problema, la versión de FragGuard y los pasos para reproducirlo.
3. **No** abras una Issue pública ni publiques la vulnerabilidad hasta que haya una versión corregida.

Responderemos lo antes posible e indicaremos cuándo se publicará la corrección. Si lo deseas, te reconoceremos en las notas de la versión.

## Qué nos interesa especialmente

- Escalada de privilegios a través del servicio o del *named pipe* `FragGuard.v1`.
- Formas de desactivar la protección, sacar archivos de la cuarentena o cambiar ajustes **sin ser administrador**.
- Saltarse la verificación de firma del canal de reglas (`rules-channel/`).
- Que FragGuard borre, aísle o detenga algo legítimo de forma que un atacante pueda provocarlo a propósito.

## Qué NO es una vulnerabilidad

- Un malware concreto que FragGuard no detecta: abre una Issue normal (sin adjuntar la muestra) indicando su hash SHA-256.
- Un falso positivo: abre una Issue normal.

## Versiones con soporte

Solo la última versión publicada recibe correcciones de seguridad.
