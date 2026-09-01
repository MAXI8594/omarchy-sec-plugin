import QtQuick
import qs.Commons
import qs.Ui
import "Model.js" as Model

BarWidget {
  id: root
  moduleName: "io.github.maxi8594.omarchy-sec"

  // Contrato de ciclo de vida exigido por Quattro / Omarchy Shell
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function open()  { if (panelLoader.item) panelLoader.item.open() }
  function close() { if (panelLoader.item) panelLoader.item.close() }
  function togglePanel() { if (panelLoader.item) panelLoader.item.toggle() }
  function closeForPopoutSwitch() { if (panelLoader.item) panelLoader.item.closeForPopoutSwitch() }

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
    if ("service" in target) target.service = service
  }

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  WazuhService {
    id: service
    settings: root.settings
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    slotSize: Style.bar.statusSlot
    active: service.isProtected
    useActiveColor: true
    activeColor: service.statusColor
    tooltipText: "Omarchy Sec: " + service.statusText

    onPressed: function(b) {
      if (b === Qt.MiddleButton) service.openDashboard()
      else root.togglePanel()
    }
  }

  // Indicador de estado (punto verde / amarillo / rojo)
  Rectangle {
    width: Style.space(6)
    height: Style.space(6)
    radius: 3
    color: service.statusColor
    anchors.bottom: parent.bottom
    anchors.right: parent.right
    anchors.bottomMargin: Style.space(3)
    anchors.rightMargin: Style.space(3)
    border.color: Color.background || "#000000"
    border.width: 1
  }
}
