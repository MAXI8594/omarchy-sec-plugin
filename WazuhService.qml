import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "Model.js" as Model

Item {
  id: root

  property var settings: ({})

  property bool isProtected: false
  property bool detectorAvailable: true
  property string primarySensor: "Omarchy Sec"
  property string primaryType: "none"
  property int activeSensorCount: 0
  property var sensorsData: ({})
  property string lastCheck: ""

  readonly property string dashboardUrl: String(setting("dashboardUrl", "https://localhost:9001"))
  readonly property int refreshIntervalSec: intSetting("refreshIntervalSec", 30, 5, 300)
  readonly property bool enableNotifications: setting("enableNotifications", true) === true

  // ── Limites duros sobre lo que aceptamos del helper ──────────────────────
  // El helper es de confianza, pero un proceso de confianza que se cuelga o
  // escupe basura no puede colgar ni inflar la barra. Todo lo de abajo es un
  // tope, no una heuristica.
  readonly property int maxStdoutBytes: 65536   // 64 KiB; la salida real ronda 1 KiB
  readonly property int maxStringChars: 96
  readonly property int maxSensorKeys: 24
  readonly property int deadlineMs: 10000

  readonly property var knownTypes: ["none", "wazuh", "falcon", "cortex",
                                     "sentinelone", "defender", "falco"]

  readonly property string statusText: {
    if (!root.detectorAvailable) return "Estado desconocido · falta el paquete omarchy-sec"
    if (root.activeSensorCount > 1) return "Multi-EDR (" + root.activeSensorCount + " activos) · Protegido"
    if (root.activeSensorCount === 1) return root.primarySensor + " · Protegido"
    return "Desprotegido (Sin EDR Activo)"
  }

  // Verde/rojo acá son semantica, no decoracion: en un indicador de seguridad el
  // color ES el mensaje. La paleta de Omarchy no tiene token de "success", asi que
  // el verde va fijo — igual que successColor en Panel.qml. El estado desconocido y
  // el desprotegido si usan tokens del tema (muted / urgent).
  readonly property color protectedColor: "#22c55e"

  readonly property color statusColor: {
    if (!root.detectorAvailable) return Color.muted
    if (root.isProtected) return root.protectedColor
    return Color.urgent
  }

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  function intSetting(name, fallback, min, max) {
    var n = parseInt(String(setting(name, fallback)), 10)
    if (!isFinite(n)) n = fallback
    if (n < min) n = min
    if (n > max) n = max
    return n
  }

  // ── Texto externo ────────────────────────────────────────────────────────
  // Todo string que venga del helper pasa por aca antes de tocar la UI: se
  // acota el largo y se sacan los controles y los caracteres de marcado. Los
  // Text del panel ademas declaran textFormat: Text.PlainText, asi que esto es
  // la segunda linea, no la unica.
  function cleanString(value, fallback) {
    if (typeof value !== "string") return fallback
    var s = value.replace(/[\x00-\x1f\x7f]/g, " ").replace(/[<>&]/g, "")
    s = s.trim()
    if (s.length === 0) return fallback
    if (s.length > root.maxStringChars) s = s.substring(0, root.maxStringChars)
    return s
  }

  // ── Politica de URLs ─────────────────────────────────────────────────────
  // xdg-open despacha por esquema: file://, y cualquier esquema que tenga un
  // handler registrado, no son navegar a una pagina. El dashboard es una
  // consola web, asi que http(s) es el universo entero de lo valido.
  function safeUrl(candidate) {
    var s = String(candidate || "").trim()
    if (s.length === 0 || s.length > 2000) return ""
    if (!/^https?:\/\/[^\s/?#]+/i.test(s)) return ""
    if (/[\x00-\x1f\x7f]/.test(s)) return ""
    return s
  }

  function openUrl(url) {
    var safe = root.safeUrl(url)
    if (safe === "") {
      console.warn("omarchy-sec: se ignoro una URL que no es http(s):", url)
      return
    }
    Quickshell.execDetached(["xdg-open", safe])
  }

  function openDashboard() {
    root.openUrl(root.dashboardUrl)
  }

  function callAgent() {
    if (!root.agentValidated) {
      console.warn("omarchy-sec:", root.agentHelper,
                   "no esta validado; no se lanza el agente")
      return
    }
    Quickshell.execDetached([root.agentHelper, "agent"])
  }

  // ── Resolucion del helper ────────────────────────────────────────────────
  // Sin PATH ambiental: se prueban rutas absolutas conocidas, en orden, y se
  // recuerda la que funciono. Un directorio escribible antes que /usr/bin en
  // el PATH del usuario no puede secuestrar al detector.
  readonly property string homeDir: Quickshell.env("HOME") || ""

  property string resolvedHelper: ""

  // Quickshell no emite onExited cuando el binario no existe, asi que no se
  // puede resolver la ruta a partir del fallo del proceso. Se sondea la
  // existencia del archivo, que es determinista.
  //
  // ponytail: los dos candidatos son scripts de bash de unos pocos KB, asi que
  // leerlos para probar existencia es barato. Si algun dia el helper fuera un
  // binario grande, esto tendria que ser un stat y no una lectura.
  // ── Validacion del helper ────────────────────────────────────────────────
  // Solo /usr/bin. La ruta en ~/.local/bin se cayo a proposito: validar y
  // despues ejecutar por nombre de archivo es check-then-execute, y un archivo
  // que el propio usuario puede reescribir entre las dos cosas no es una
  // identidad en la que se pueda confiar. /usr/bin/... solo lo cambia root, y
  // root tambien puede reemplazar este widget: queda fuera del modelo.
  //
  // Consecuencia asumida: una instalacion desde el checkout (~/.local/bin) ya
  // no alimenta al widget. Queda en gris hasta que se instale el paquete. Es la
  // respuesta correcta para un indicador de seguridad — antes que mostrar un
  // estado que salio de un binario que cualquiera pudo cambiar.
  readonly property string detectHelper: "/usr/bin/omarchy-sec-detect"
  readonly property string agentHelper: "/usr/bin/omarchy-sec"

  // regular · no symlink · de root · no escribible por grupo ni otros ·
  // ejecutable · acotado. Sin leer una sola linea del contenido.
  function validationArgs(path) {
    return ["/usr/bin/find", path,
            "-maxdepth", "0",
            "-type", "f", "!", "-type", "l",
            "-user", "root", "!", "-perm", "/022",
            "-perm", "-u+x",
            "-size", "-1048577c",
            "-print"]
  }

  property bool agentValidated: false

  Process {
    id: validateProcess
    running: false
    command: []
    stdout: StdioCollector { id: validateOut; waitForEnd: true }
    onExited: {
      if (String(validateOut.text || "").trim() === root.detectHelper) {
        root.resolvedHelper = root.detectHelper
        console.warn("omarchy-sec: detector validado en", root.detectHelper)
        root.refresh()
      } else {
        console.warn("omarchy-sec:", root.detectHelper,
                     "no pasa la validacion (regular, de root, no escribible por otros);",
                     "estado desconocido")
        root.markUnknown()
      }
      // El binario del agente se valida aparte: es otro ejecutable y heredar la
      // confianza de su hermano de directorio no lo convierte en confiable.
      validateAgent.command = root.validationArgs(root.agentHelper)
      validateAgent.running = true
    }
  }

  Process {
    id: validateAgent
    running: false
    command: []
    stdout: StdioCollector { id: agentOut; waitForEnd: true }
    onExited: {
      root.agentValidated = (String(agentOut.text || "").trim() === root.agentHelper)
      if (!root.agentValidated)
        console.warn("omarchy-sec:", root.agentHelper,
                     "no pasa la validacion; 'Call Agent' queda deshabilitado")
    }
  }

  function validateCandidate() {
    validateProcess.command = root.validationArgs(root.detectHelper)
    validateProcess.running = true
  }

  Component.onCompleted: root.validateCandidate()

  property string collected: ""
  property bool overflowed: false

  function refresh() {
    // Sin ruta validada no se lanza nada: validateCandidate llama de vuelta.
    if (root.resolvedHelper === "") return
    if (detectProcess.running) return
    root.collected = ""
    root.overflowed = false
    // El scope de systemd reemplaza a setsid + kill -- -PID. Ese esquema estaba
    // mal: setsid FORKEA, asi que el PID que observabamos era el de setsid y no
    // el del lider de sesion, y matar ese "grupo" apuntaba a otra cosa — o, con
    // reutilizacion de PID, a un tercero. Un scope se direcciona por un nombre
    // que elegimos nosotros, posee el arbol entero de descendientes y se corta
    // de forma sincronica. No hay PID que observar ni carrera que perder.
    //
    //   timeout  — plazo del sistema operativo, no una promesa de un Timer
    //   head -c  — corta a los 64 KiB y el productor muere de SIGPIPE, asi que
    //              el tope se aplica mientras escribe y no despues
    //   pipefail — sin esto el exit code seria el de head y un fallo del helper
    //              se leeria como exito
    root.scopeUnit = "omarchy-sec-detect-" + Date.now() + "-" +
                     Math.floor(Math.random() * 100000)
    var quoted = "'" + String(root.resolvedHelper).replace(/'/g, "'\''") + "'"
    detectProcess.command = [
      "/usr/bin/systemd-run", "--user", "--scope", "--collect", "--quiet",
      "--unit", root.scopeUnit,
      "/bin/bash", "-c",
      "set -o pipefail; /usr/bin/timeout -k 2 " +
      Math.ceil(root.deadlineMs / 1000) + " " + quoted +
      " | /usr/bin/head -c " + root.maxStdoutBytes
    ]
    detectProcess.running = true
    deadline.restart()
  }

  property string scopeUnit: ""

  // Se corta la unidad por su nombre, no un grupo deducido de un PID: el scope
  // posee el cgroup, asi que systemd mata todo el arbol de descendientes de una
  // y sin depender de que ningun PID siga siendo el que creiamos.
  function killDetectScope() {
    if (root.scopeUnit === "") return
    Quickshell.execDetached(["/usr/bin/systemctl", "--user", "stop",
                             root.scopeUnit + ".scope"])
  }

  function abortDetect(reason) {
    console.warn("omarchy-sec:", reason)
    deadline.stop()
    root.killDetectScope()
    detectProcess.running = false
    root.markUnknown()
  }

  function markUnknown() {
    root.detectorAvailable = false
    root.isProtected = false
    root.activeSensorCount = 0
    root.primarySensor = "Omarchy Sec"
    root.primaryType = "none"
    root.sensorsData = ({})
  }

  // ── Validacion de esquema ────────────────────────────────────────────────
  // Se aceptan solo las claves conocidas, con el tipo esperado y acotadas.
  // Nada de la salida del helper llega a una propiedad sin pasar por aca.
  function applyDetect(raw) {
    var data
    try {
      data = JSON.parse(raw)
    } catch (err) {
      console.warn("omarchy-sec: el detector no devolvio JSON valido")
      return false
    }
    if (data === null || typeof data !== "object" || Array.isArray(data)) return false
    if (data.status !== "protected" && data.status !== "unprotected") return false

    var count = Number(data.activeCount)
    if (!isFinite(count) || count < 0 || count > 99) count = 0

    var type = root.knownTypes.indexOf(String(data.primaryType)) >= 0
             ? String(data.primaryType) : "none"

    var sensors = ({})
    if (data.sensors !== null && typeof data.sensors === "object" && !Array.isArray(data.sensors)) {
      var keys = Object.keys(data.sensors).slice(0, root.maxSensorKeys)
      for (var i = 0; i < keys.length; i++) {
        var entry = data.sensors[keys[i]]
        if (entry === null || typeof entry !== "object") continue
        var clean = ({})
        var fields = Object.keys(entry).slice(0, 8)
        for (var j = 0; j < fields.length; j++) {
          var v = entry[fields[j]]
          if (typeof v === "string") clean[fields[j]] = root.cleanString(v, "")
          else if (typeof v === "number" || typeof v === "boolean") clean[fields[j]] = v
        }
        sensors[keys[i]] = clean
      }
    }

    // Solo las transiciones, no cada sondeo: que quede rastro de cuando este
    // endpoint dejo de estar protegido es justamente el punto del widget.
    var nowProtected = (data.status === "protected")
    if (nowProtected !== root.isProtected || !root.detectorAvailable) {
      console.warn("omarchy-sec: estado ->",
                   nowProtected ? "protegido" : "desprotegido",
                   "· sensores activos:", Math.floor(Number(data.activeCount) || 0))
    }

    root.isProtected = nowProtected
    root.primarySensor = root.cleanString(data.primary, "Omarchy Sec")
    root.primaryType = type
    root.activeSensorCount = Math.floor(count)
    root.sensorsData = sensors
    root.lastCheck = Qt.formatTime(new Date(), "hh:mm:ss")
    return true
  }

  Process {
    id: detectProcess
    running: false
    command: []
    // SplitParser entrega por lineas en vez de retener toda la salida hasta el
    // final, asi que el presupuesto se aplica mientras el helper escribe y no
    // despues. StdioCollector no expone ningun tope: el chequeo de tamano
    // llegaba cuando la salida entera ya estaba en memoria.
    stdout: SplitParser {
      splitMarker: "\n"
      onRead: function(data) {
        if (root.overflowed) return
        if (root.collected.length + data.length > root.maxStdoutBytes) {
          root.overflowed = true
          root.abortDetect("el detector supero el presupuesto de " +
                           root.maxStdoutBytes + " bytes; se corta")
          return
        }
        root.collected += data + "\n"
      }
    }

    onExited: function(exitCode) {
      deadline.stop()
      if (root.overflowed) return
      var raw = root.collected

      // Sin detector no sabemos nada. Reportar "desprotegido" seria una falsa
      // alarma en un widget de seguridad: se marca como desconocido.
      if (exitCode !== 0 || raw.trim().length === 0) {
        root.markUnknown()
        return
      }


      if (!root.applyDetect(raw.trim())) {
        root.markUnknown()
        return
      }

      root.detectorAvailable = true
    }
  }

  // Un detector colgado no puede dejar al widget mostrando datos viejos como si
  // fueran actuales, ni bloquear todos los refrescos siguientes por el guard de
  // `running`.
  Timer {
    id: deadline
    interval: root.deadlineMs
    repeat: false
    onTriggered: {
      if (!detectProcess.running) return
      root.abortDetect("el detector no respondio en " + root.deadlineMs +
                       " ms; se corta el grupo de procesos")
    }
  }

  Timer {
    id: pollTimer
    interval: root.refreshIntervalSec * 1000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }
}
