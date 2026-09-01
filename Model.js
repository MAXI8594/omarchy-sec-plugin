.pragma library

/**
 * Returns formatted status string based on active protection
 */
function deriveStatus(activeCount, primarySensor) {
  if (activeCount > 1) return "Multi-EDR Protegido (" + activeCount + " activos)";
  if (activeCount === 1) return primarySensor + " · Protegido";
  return "Desprotegido (Sin EDR Activo)";
}

/**
 * Returns friendly sensor name by key
 */
function sensorName(key) {
  var names = {
    "": "Omarchy Sec",
    "wazuh": "Wazuh Open XDR/EDR",
    "crowdstrike": "CrowdStrike Falcon",
    "cortex": "Palo Alto Cortex XDR",
    "sentinelone": "SentinelOne",
    "defender": "Microsoft Defender (MDE)",
    "ebpf": "Falco / Tetragon (eBPF)",
    "auditd": "Linux Auditd"
  };
  return names[key] || "Omarchy Sec";
}
