/*
    FragGuard - Regla de prueba EICAR
    ---------------------------------
    EICAR es un archivo de prueba estándar e INOFENSIVO que todos los antivirus detectan a propósito.
    Sirve para comprobar de extremo a extremo que la detección y la cuarentena funcionan.

    Nota: la cadena EICAR completa NO aparece literal en este archivo (se usa su prefijo en hexadecimal
    + un fragmento de texto). Así evitamos que otros antivirus, como Windows Defender, marquen este .yar como amenaza.

    Metadatos que lee FragGuard (en todas las reglas):
      description : texto que se muestra al usuario
      severity    : low | medium | high | critical   (high/critical = cuarentena automática)
      category    : agrupación libre (Test, Infostealer, Dropper...)
*/

rule FG_Test_EICAR
{
    meta:
        description = "Archivo de prueba EICAR (inofensivo). Si lo ves, la protección funciona."
        severity    = "high"
        category    = "Test"
        author      = "FragGuard"

    strings:
        // "X5O!P%@AP[4\PZX54(P^)7CC)7}$" en hexadecimal: el inicio obligatorio del archivo EICAR
        $prefix = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 }
        $name   = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        // El estándar exige que el archivo EMPIECE por el prefijo y sea pequeño (puede llevar espacios al final)
        $prefix at 0 and $name and filesize < 256
}
