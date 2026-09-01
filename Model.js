.pragma library

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
