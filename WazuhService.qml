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

  // El CLI y el detector se instalan juntos, asi que el agente vive en el mismo
  // directorio que el detector que ya resolvimos. Sin detector resuelto no hay
  // a quien llamar, y lanzar por PATH seria volver al problema original.
  function callAgent() {
    if (root.resolvedHelper === "") {
      console.warn("omarchy-sec: no hay detector resuelto; no se llama al agente")
      return
    }
    var dir = root.resolvedHelper.substring(0, root.resolvedHelper.lastIndexOf("/"))
    Quickshell.execDetached([dir + "/omarchy-sec", "agent"])
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
  // Una sonda por candidato, cada una se dispara una sola vez. Nada de mutar un
  // path y esperar que FileView recargue: eso no reintentaba, y una sonda que
  // falla en silencio deja al widget en gris para siempre.
  //
  // ponytail: dos candidatos fijos alcanzan. Si algun dia hay mas rutas de
  // instalacion, esto pide un Repeater sobre la lista, no una tercera copia.
  property bool systemProbeDone: false
  property bool userProbeDone: false
  property bool systemHelperExists: false
  property bool userHelperExists: false

  readonly property string systemHelper: "/usr/bin/omarchy-sec-detect"
  readonly property string userHelper: root.homeDir === "" ? ""
                                     : root.homeDir + "/.local/bin/omarchy-sec-detect"

  // /usr/bin gana sobre ~/.local/bin: el paquete del sistema es el de confianza,
  // y un directorio escribible por el usuario no puede adelantarsele.
  function settleDetector() {
    if (!root.systemProbeDone) return
    if (root.userHelper !== "" && !root.userProbeDone) return

    if (root.systemHelperExists)      root.resolvedHelper = root.systemHelper
    else if (root.userHelperExists)   root.resolvedHelper = root.userHelper
    else {
      root.markUnknown()
      return
    }
    console.warn("omarchy-sec: detector resuelto en", root.resolvedHelper)
    root.refresh()
  }

  FileView {
    path: root.systemHelper
    preload: true
    printErrors: false
    onLoaded:     { root.systemHelperExists = true;  root.systemProbeDone = true; root.settleDetector() }
    onLoadFailed: { root.systemHelperExists = false; root.systemProbeDone = true; root.settleDetector() }
  }

  FileView {
    path: root.userHelper
    preload: true
    printErrors: false
    onLoaded:     { root.userHelperExists = true;  root.userProbeDone = true; root.settleDetector() }
    onLoadFailed: { root.userHelperExists = false; root.userProbeDone = true; root.settleDetector() }
  }

  function refresh() {
    // Sin ruta resuelta no se lanza nada: las sondas llaman de vuelta.
    if (root.resolvedHelper === "") return
    if (detectProcess.running) return
    detectProcess.command = [root.resolvedHelper]
    detectProcess.running = true
    deadline.restart()
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

    root.isProtected = (data.status === "protected")
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
    stdout: StdioCollector { id: detectStdout; waitForEnd: true }

    onExited: function(exitCode) {
      deadline.stop()
      var raw = String(detectStdout.text || "")

      // Sin detector no sabemos nada. Reportar "desprotegido" seria una falsa
      // alarma en un widget de seguridad: se marca como desconocido.
      if (exitCode !== 0 || raw.trim().length === 0) {
        root.markUnknown()
        return
      }

      // Un helper de confianza que escupe 10 MB sigue colgando la barra si lo
      // parseamos. El tope se aplica antes del JSON.parse, no despues.
      if (raw.length > root.maxStdoutBytes) {
        console.warn("omarchy-sec: el detector devolvio", raw.length,
                     "bytes, por encima del tope de", root.maxStdoutBytes)
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
      console.warn("omarchy-sec: el detector no respondio en",
                   root.deadlineMs, "ms; se corta")
      detectProcess.running = false
      root.markUnknown()
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
