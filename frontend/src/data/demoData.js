export const networkRows = [
  {
    ssid: "Airtel_ashw_2959",
    bssid: "14:A7:2B:D0:EF:16",
    vendor: "Currentoptronics",
    signal: "-67 dBm",
    channel: "6",
    encryption: "WPA2",
    status: "Safe",
    attack: "Normal",
  },
  {
    ssid: "OPPO A16",
    bssid: "C2:FF:A7:C5:36:4E",
    vendor: "Unknown",
    signal: "-21 dBm",
    channel: "11",
    encryption: "WPA2",
    status: "Safe",
    attack: "Normal",
  },
  {
    ssid: "Unknown_AP",
    bssid: "F4:4D:5C:F6:F7:86",
    vendor: "Unknown",
    signal: "Unknown",
    channel: "Unknown",
    encryption: "Unknown",
    status: "Review",
    attack: "Rogue AP",
  },
  {
    ssid: "Guest_WiFi",
    bssid: "28:18:FD:90:E3:76",
    vendor: "Unknown",
    signal: "-70 dBm",
    channel: "9",
    encryption: "Open",
    status: "Warning",
    attack: "Weak Network",
  },
];

export const threatCards = [
  {
    title: "Rogue Access Point",
    severity: "High",
    text: "Possible unauthorized access point detected near the monitored wireless area.",
  },
  {
    title: "Evil Twin Indicator",
    severity: "Critical",
    text: "Duplicate SSID behavior may indicate impersonation of a trusted network.",
  },
  {
    title: "Unknown Device",
    severity: "Medium",
    text: "Unknown BSSID or vendor information requires administrator review.",
  },
  {
    title: "Weak or Open Network",
    severity: "Medium",
    text: "Open or weakly protected networks can expose users to unsafe connections.",
  },
];

export const reportCards = [
  {
    title: "Final Security Report",
    type: "CSV",
    text: "Security score, risk level, packet count, and attack classification.",
  },
  {
    title: "Security Advisor Report",
    type: "TXT / JSON",
    text: "Clear recommendations and explanations for detected wireless risks.",
  },
  {
    title: "Historical Trend Report",
    type: "JSON",
    text: "Comparison between previous and current scan results.",
  },
  {
    title: "Alert Notification Log",
    type: "LOG / JSON",
    text: "Severity-based alert records for suspicious wireless activity.",
  },
];

export const historyItems = [
  {
    title: "New Networks",
    value: "04",
    text: "Networks appeared after previous scan",
  },
  {
    title: "Disappeared Networks",
    value: "02",
    text: "Networks missing in latest scan",
  },
  {
    title: "Repeated Alerts",
    value: "03",
    text: "Suspicious entries seen again",
  },
  {
    title: "Trend Status",
    value: "Improving",
    text: "Threat count reduced in latest scan",
  },
];

export const featureCards = [
  {
    tag: "Discovery",
    title: "WiFi Network Scanning",
    text: "Discover nearby WiFi networks and collect SSID, BSSID, channel, signal strength, and encryption details.",
    points: ["SSID and BSSID visibility", "Signal and channel details", "Encryption status"],
    visual: "radar",
  },
  {
    tag: "Inspection",
    title: "Live Packet Analysis",
    text: "Analyze wireless packet activity, device behavior, and suspicious traffic patterns.",
    points: ["Packet type monitoring", "Source and destination review", "Suspicious activity support"],
    visual: "packet",
  },
  {
    tag: "Detection",
    title: "Threat Detection",
    text: "Identify Rogue AP indicators, Evil Twin behavior, unknown devices, and weak wireless networks.",
    points: ["Rogue AP indicators", "Evil Twin indicators", "Unknown device review"],
    visual: "threat",
  },
  {
    tag: "Advisor",
    title: "Security Advisor",
    text: "Convert technical scan results into clear recommendations, explanations, and reports.",
    points: ["Readable recommendations", "Security score", "Professional reports"],
    visual: "advisor",
  },
];
