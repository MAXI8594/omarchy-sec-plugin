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

  readonly property string statusText: {
    if (!root.detectorAvailable) return "Estado desconocido · falta el paquete omarchy-sec"
    if (root.activeSensorCount > 1) return "Multi-EDR (" + root.activeSensorCount + " activos) · Protegido"
    if (root.activeSensorCount === 1) return root.primarySensor + " · Protegido"
    return "Desprotegido (Sin EDR Activo)"
  }

  readonly property color statusColor: {
    if (!root.detectorAvailable) return Color.muted
    if (root.isProtected) return Color.accent
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

  function openDashboard() {
    Quickshell.execDetached(["xdg-open", root.dashboardUrl])
  }

  function openUrl(url) {
    Quickshell.execDetached(["xdg-open", url])
  }

  function callAgent() {
    Quickshell.execDetached(["omarchy-sec", "agent"])
  }

  function refresh() {
    if (detectProcess.running) return
    detectProcess.command = ["omarchy-sec-detect"]
    detectProcess.running = true
  }

  Process {
    id: detectProcess
    running: false
    command: []
    stdout: StdioCollector { id: detectStdout; waitForEnd: true }
    onExited: function(exitCode) {
      // Sin omarchy-sec-detect en el PATH no sabemos nada. Reportar "desprotegido"
      // sería una falsa alarma en un widget de seguridad: se marca como desconocido.
      var raw = String(detectStdout.text || "").trim()
      if (exitCode !== 0 || !raw) {
        root.detectorAvailable = false
        root.isProtected = false
        root.activeSensorCount = 0
        return
      }
      root.detectorAvailable = true
      try {
        var data = JSON.parse(raw)
        root.isProtected = (data.status === "protected")
        root.primarySensor = data.primary || "Omarchy Sec"
        root.primaryType = data.primaryType || "none"
        root.activeSensorCount = data.activeCount || 0
        root.sensorsData = data.sensors || {}
        root.lastCheck = Qt.formatTime(new Date(), "hh:mm:ss")
      } catch (err) {
        console.error("Error parsing security detect JSON:", err)
      }
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
