import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "io.github.maxi8594.omarchy-sec"
  ipcTarget: "io.github.maxi8594.omarchy-sec"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  property var service: null

  // "" = General Omarchy Sec; "wazuh", "crowdstrike", "cortex", "defender", "sentinelone", "ebpf", "auditd"
  property string selectedSensor: ""

  readonly property var barIdentity: hostWidget || root
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color dim: Qt.darker(foreground, 1.4)
  readonly property color successColor: "#22c55e"
  readonly property color warningColor: "#eab308"

  readonly property bool isProtected: service ? service.isProtected : false
  readonly property color statusColor: service ? service.statusColor : foreground
  readonly property var sensors: service && service.sensorsData ? service.sensorsData : ({})

  // Titulo dinamico: "Omarchy Sec" por defecto, o el nombre del sensor seleccionado
  readonly property string heroTitle: Model.sensorName(root.selectedSensor)

  function toggleSelectSensor(key) {
    if (root.selectedSensor === key) {
      root.selectedSensor = ""
    } else {
      root.selectedSensor = key
    }
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(560))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Column {
        id: column
        width: parent.width
        spacing: Style.space(10)

        // ---- Encabezado Hero Dinámico ----
        PanelHero {
          width: parent.width
          title: root.heroTitle
          foreground: root.statusColor
          fontFamily: root.fontFamily
          iconOpacity: root.isProtected ? 1.0 : 0.7
          iconComponent: Component {
            Item {
              width: Style.space(52)
              height: Style.space(52)
              OpticalGlyph {
                anchors.fill: parent
                text: ""
                fontFamily: root.fontFamily
                fontSize: Style.space(42)
                color: root.statusColor
              }
            }
          }
        }

        // Subtítulo de estado general
        Text {
          anchors.horizontalCenter: parent.horizontalCenter
          text: root.selectedSensor === "" 
                ? (service ? service.statusText : "Omarchy Sec")
                : "Sensor seleccionado · Click para deseleccionar"
          font.family: root.fontFamily
          font.pixelSize: Style.space(10)
          color: root.dim
        }

        PanelSeparator { width: parent.width; foreground: root.foreground }

        // ---- Tarjeta de Sensores EDR / XDR Seleccionables ----
        Rectangle {
          width: parent.width
          implicitHeight: sensorCol.implicitHeight + Style.space(16)
          radius: Style.cornerRadius
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.06)
          border.color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.12)
          border.width: 1

          Column {
            id: sensorCol
            anchors.fill: parent
            anchors.margins: Style.space(10)
            spacing: Style.space(6)

            Text {
              text: "Selecciona un Sensor para detalles:"
              font.family: root.fontFamily
              font.pixelSize: Style.space(11)
              font.bold: true
              color: root.foreground
            }

            // 1. Wazuh Open XDR/EDR
            Rectangle {
              width: parent.width
              height: Style.space(26)
              radius: Style.cornerRadius
              color: root.selectedSensor === "wazuh" ? Qt.rgba(root.successColor.r, root.successColor.g, root.successColor.b, 0.15) : (rowWazuhArea.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent")
              border.color: root.selectedSensor === "wazuh" ? root.successColor : "transparent"
              border.width: 1

              MouseArea {
                id: rowWazuhArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.toggleSelectSensor("wazuh")
              }

              Row {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: Style.space(6)
                spacing: Style.space(8)
                Rectangle {
                  width: Style.space(8); height: Style.space(8); radius: 4
                  color: (sensors.wazuh && sensors.wazuh.agent === "active") ? root.successColor : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.2)
                  anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                  text: "Wazuh Open XDR/EDR"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(10)
                  font.bold: root.selectedSensor === "wazuh"
                  color: (sensors.wazuh && sensors.wazuh.agent === "active") ? root.foreground : root.dim
                }
                Text {
                  text: (sensors.wazuh && sensors.wazuh.agent === "active") ? "• Activo (:1514)" : "• Inactivo"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(9)
                  color: (sensors.wazuh && sensors.wazuh.agent === "active") ? root.successColor : root.dim
                }
              }
            }

            // 2. CrowdStrike Falcon
            Rectangle {
              width: parent.width
              height: Style.space(26)
              radius: Style.cornerRadius
              color: root.selectedSensor === "crowdstrike" ? Qt.rgba(root.successColor.r, root.successColor.g, root.successColor.b, 0.15) : (rowFalconArea.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent")
              border.color: root.selectedSensor === "crowdstrike" ? root.successColor : "transparent"
              border.width: 1

              MouseArea {
                id: rowFalconArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.toggleSelectSensor("crowdstrike")
              }

              Row {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: Style.space(6)
                spacing: Style.space(8)
                Rectangle {
                  width: Style.space(8); height: Style.space(8); radius: 4
                  color: (sensors.crowdstrike && sensors.crowdstrike.status === "active") ? root.successColor : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.2)
                  anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                  text: "CrowdStrike Falcon Sensor"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(10)
                  font.bold: root.selectedSensor === "crowdstrike"
                  color: (sensors.crowdstrike && sensors.crowdstrike.status === "active") ? root.foreground : root.dim
                }
                Text {
                  text: (sensors.crowdstrike && sensors.crowdstrike.status === "active") ? "• Activo" : "• No detectado"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(9)
                  color: (sensors.crowdstrike && sensors.crowdstrike.status === "active") ? root.successColor : root.dim
                }
              }
            }

            // 3. Palo Alto Cortex XDR
            Rectangle {
              width: parent.width
              height: Style.space(26)
              radius: Style.cornerRadius
              color: root.selectedSensor === "cortex" ? Qt.rgba(root.successColor.r, root.successColor.g, root.successColor.b, 0.15) : (rowCortexArea.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent")
              border.color: root.selectedSensor === "cortex" ? root.successColor : "transparent"
              border.width: 1

              MouseArea {
                id: rowCortexArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.toggleSelectSensor("cortex")
              }

              Row {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: Style.space(6)
                spacing: Style.space(8)
                Rectangle {
                  width: Style.space(8); height: Style.space(8); radius: 4
                  color: (sensors.cortex && sensors.cortex.status === "active") ? root.successColor : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.2)
                  anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                  text: "Palo Alto Cortex XDR"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(10)
                  font.bold: root.selectedSensor === "cortex"
                  color: (sensors.cortex && sensors.cortex.status === "active") ? root.foreground : root.dim
                }
                Text {
                  text: (sensors.cortex && sensors.cortex.status === "active") ? "• Activo" : "• No detectado"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(9)
                  color: (sensors.cortex && sensors.cortex.status === "active") ? root.successColor : root.dim
                }
              }
            }

            // 4. Microsoft Defender / SentinelOne
            Rectangle {
              width: parent.width
              height: Style.space(26)
              radius: Style.cornerRadius
              color: root.selectedSensor === "defender" ? Qt.rgba(root.successColor.r, root.successColor.g, root.successColor.b, 0.15) : (rowDefArea.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent")
              border.color: root.selectedSensor === "defender" ? root.successColor : "transparent"
              border.width: 1

              MouseArea {
                id: rowDefArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.toggleSelectSensor("defender")
              }

              Row {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: Style.space(6)
                spacing: Style.space(8)
                Rectangle {
                  width: Style.space(8); height: Style.space(8); radius: 4
                  color: (sensors.defender && sensors.defender.status === "active") ? root.successColor : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.2)
                  anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                  text: "Microsoft Defender (MDE)"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(10)
                  font.bold: root.selectedSensor === "defender"
                  color: (sensors.defender && sensors.defender.status === "active") ? root.foreground : root.dim
                }
                Text {
                  text: (sensors.defender && sensors.defender.status === "active") ? "• Activo" : "• No detectado"
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(9)
                  color: (sensors.defender && sensors.defender.status === "active") ? root.successColor : root.dim
                }
              }
            }
          }
        }

        // ---- Botón de Acción Dinámico según Selección ----
        Rectangle {
          width: parent.width
          height: Style.space(36)
          radius: Style.cornerRadius
          color: btnDashArea.containsMouse ? Qt.rgba(root.statusColor.r, root.statusColor.g, root.statusColor.b, 0.2) : Qt.rgba(root.statusColor.r, root.statusColor.g, root.statusColor.b, 0.12)
          border.color: root.statusColor
          border.width: 1

          MouseArea {
            id: btnDashArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (root.selectedSensor === "crowdstrike") {
                if (service) service.openUrl("https://falcon.crowdstrike.com")
              } else if (root.selectedSensor === "cortex") {
                if (service) service.openUrl("https://cortex.paloaltonetworks.com")
              } else if (root.selectedSensor === "defender") {
                if (service) service.openUrl("https://security.microsoft.com")
              } else {
                if (service) service.openDashboard()
              }
              root.close()
            }
          }

          Row {
            anchors.centerIn: parent
            spacing: Style.space(8)
            Text { text: "󰖟"; font.family: root.fontFamily; font.pixelSize: Style.space(13); color: root.statusColor; anchors.verticalCenter: parent.verticalCenter }
            Text {
              text: {
                if (root.selectedSensor === "crowdstrike") return "Abrir Falcon Console (Cloud)"
                if (root.selectedSensor === "cortex") return "Abrir Cortex XDR Hub"
                if (root.selectedSensor === "defender") return "Abrir Microsoft Defender Portal"
                return "Abrir SOC Dashboard (:9001)"
              }
              font.family: root.fontFamily
              font.pixelSize: Style.space(11)
              font.bold: true
              color: root.statusColor
              anchors.verticalCenter: parent.verticalCenter
            }
          }
        }

        // ---- Botones Secundarios: Refrescar & Call Agent ----
        Row {
          width: parent.width
          spacing: Style.space(8)

          Rectangle {
            width: (parent.width - Style.space(8)) / 2
            height: Style.space(30)
            radius: Style.cornerRadius
            color: btnRefreshArea.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.1) : "transparent"
            border.color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.2)
            border.width: 1

            MouseArea {
              id: btnRefreshArea
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: if (service) service.refresh()
            }

            Row {
              anchors.centerIn: parent
              spacing: Style.space(4)
              Text { text: ""; font.family: root.fontFamily; font.pixelSize: Style.space(10); color: root.foreground }
              Text { text: "Refrescar"; font.family: root.fontFamily; font.pixelSize: Style.space(10); color: root.foreground }
            }
          }

          Rectangle {
            width: (parent.width - Style.space(8)) / 2
            height: Style.space(30)
            radius: Style.cornerRadius
            color: btnAgentArea.containsMouse ? Qt.rgba(root.warningColor.r, root.warningColor.g, root.warningColor.b, 0.2) : Qt.rgba(root.warningColor.r, root.warningColor.g, root.warningColor.b, 0.08)
            border.color: Qt.rgba(root.warningColor.r, root.warningColor.g, root.warningColor.b, 0.5)
            border.width: 1

            MouseArea {
              id: btnAgentArea
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: {
                if (service) service.callAgent()
                root.close()
              }
            }

            Row {
              anchors.centerIn: parent
              spacing: Style.space(4)
              Text { text: "🤖"; font.family: root.fontFamily; font.pixelSize: Style.space(10); color: root.foreground }
              Text { text: "Call Agent"; font.family: root.fontFamily; font.pixelSize: Style.space(10); font.bold: true; color: root.foreground }
            }
          }
        }
      }
    }
  }
}
