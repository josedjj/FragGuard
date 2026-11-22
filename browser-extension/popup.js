// Muestra cuántos dominios hay en la regla estática (se calcula al generar las reglas y se guarda en stats.json).
fetch(chrome.runtime.getURL("rules/stats.json"))
  .then(r => r.json())
  .then(s => { document.getElementById("count").textContent = s.domains.toLocaleString("es-ES"); })
  .catch(() => { document.getElementById("count").textContent = "?"; });
