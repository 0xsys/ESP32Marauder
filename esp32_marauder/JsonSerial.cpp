#include "JsonSerial.h"

#include "WiFiScan.h"
#include "EvilPortal.h"
#include "settings.h"
#include "utils.h"
#if defined(HAS_CSI_MOTION)
  #include "CsiMotionMonitor.h"
#endif

extern Settings settings_obj;

// Globals defined in WiFiScan.cpp / esp32_marauder.ino (mirrors CommandLine.h)
extern LinkedList<AccessPoint>* access_points;
extern LinkedList<Station>* stations;
extern LinkedList<ssid>* ssids;
extern LinkedList<IPAddress>* ipList;
extern LinkedList<ProbeReqSsid>* probe_req_ssids;
extern LinkedList<AirTag>* airtags;
extern WiFiScan wifi_scan_obj;
extern const String version_number;

// When false, the continuous analyzer / channel-activity streaming is
// suppressed so a plain serial monitor (no JSON host) is never flooded with
// "@J" lines. Enabled by the `jsoninfo` handshake or an explicit `jsonmode 1`.
static bool g_jsonMode = false;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Escape a string for safe inclusion inside a JSON string literal.
//
// 802.11 SSIDs are arbitrary byte strings, so this is UTF-8 aware: valid UTF-8
// sequences are passed through verbatim (JSON text is UTF-8); ", \, and control
// characters are escaped; and any byte that is not part of a valid UTF-8
// sequence is replaced with U+FFFD. The result is therefore always valid JSON,
// even for non-UTF-8 / random-byte SSIDs.
static String jsonEscape(const String& in) {
  String out;
  unsigned int n = in.length();
  out.reserve(n + 8);
  for (unsigned int i = 0; i < n; ) {
    uint8_t c = (uint8_t)in.charAt(i);

    if (c < 0x80) { // ASCII
      switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
          if (c < 0x20 || c == 0x7F) {
            char buf[7];
            snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
          } else {
            out += (char)c;
          }
      }
      i++;
      continue;
    }

    // Multi-byte UTF-8: validate length, continuation bytes, AND the decoded
    // code point (reject overlong encodings, UTF-16 surrogates U+D800..U+DFFF,
    // and values > U+10FFFF). This guarantees the emitted string is always
    // well-formed UTF-8, i.e. valid JSON, for arbitrary 802.11 SSID bytes.
    int seqLen = 0;
    if ((c & 0xE0) == 0xC0) seqLen = 2;
    else if ((c & 0xF0) == 0xE0) seqLen = 3;
    else if ((c & 0xF8) == 0xF0) seqLen = 4;

    bool valid = (seqLen >= 2) && (i + (unsigned int)seqLen <= n);
    uint32_t cp = 0;
    if (valid) {
      cp = (uint32_t)(c & (0xFF >> (seqLen + 1)));
      for (int k = 1; k < seqLen; k++) {
        uint8_t cc = (uint8_t)in.charAt(i + k);
        if ((cc & 0xC0) != 0x80) { valid = false; break; }
        cp = (cp << 6) | (uint32_t)(cc & 0x3F);
      }
    }
    if (valid) {
      static const uint32_t minCp[5] = {0, 0, 0x80, 0x800, 0x10000};
      if (cp < minCp[seqLen] || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)
        valid = false;
    }

    if (valid) {
      for (int k = 0; k < seqLen; k++) out += in.charAt(i + k);
      i += (unsigned int)seqLen;
    } else {
      out += "\\ufffd"; // invalid byte -> U+FFFD replacement character
      i++;
    }
  }
  return out;
}

// Emit  "key":true,  (or false). Pass comma=false to omit the trailing comma.
static inline void boolField(const __FlashStringHelper* key, bool v, bool comma = true) {
  Serial.print(key);
  Serial.print(v ? F("true") : F("false"));
  if (comma) Serial.print(F(","));
}

// ---------------------------------------------------------------------------
// jsoninfo - handshake / capability advertisement
// ---------------------------------------------------------------------------
static void printInfo() {
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"info\",\"fw\":\""));
  Serial.print(version_number);
  Serial.print(F("\",\"proto\":"));
  Serial.print(MARAUDER_JSON_PROTO);
  Serial.print(F(",\"board\":\""));
  Serial.print(F(HARDWARE_NAME));
  Serial.print(F("\",\"caps\":["));

  // WiFi is present on every supported board, so it is always emitted first;
  // every other capability is conditionally appended with a leading comma.
  Serial.print(F("\"wifi\""));
  // Length-prefixed binary capture streaming + jsonbaud are board-independent
  // (proto >= 2). A host uses this cap to switch on host-side pcap capture and
  // the higher line rate instead of relying on an on-device SD card.
  Serial.print(F(",\"capstream\""));
  #ifdef HAS_BT
    Serial.print(F(",\"bt\""));
  #endif
  #ifdef HAS_GPS
    Serial.print(F(",\"gps\""));
  #endif
  #ifdef HAS_SD
    Serial.print(F(",\"sd\""));
  #endif
  #ifdef HAS_SCREEN
    Serial.print(F(",\"screen\""));
  #endif
  // proto >= 3 features. A host feature-detects each capability instead of
  // assuming it from the firmware version.
  Serial.print(F(",\"remoteid\""));   // jsonlist d (drone Remote ID) + target tracking
  Serial.print(F(",\"foxhunt\""));    // {"t":"fox"} live signal-strength stream
  Serial.print(F(",\"recon\""));      // recon mission (results land in the a/c lists)
  #ifdef HAS_CSI_MOTION
    Serial.print(F(",\"csi\""));      // {"t":"csi"} motion stream
  #endif
  #ifdef HAS_GPS
    Serial.print(F(",\"geofence\"")); // jsonlist g (configured geofences)
  #endif

  Serial.println(F("]}"));
}

// ---------------------------------------------------------------------------
// jsonstatus - lightweight, poll friendly device state
// ---------------------------------------------------------------------------
static void printStatus() {
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"status\",\"mode\":"));
  Serial.print(wifi_scan_obj.currentScanMode);
  Serial.print(F(",")); boolField(F("\"running\":"), wifi_scan_obj.scanning());
  Serial.print(F("\"free\":"));
  Serial.print(ESP.getFreeHeap());
  Serial.print(F(",\"aps\":"));
  Serial.print(access_points ? access_points->size() : 0);
  Serial.print(F(",\"stas\":"));
  Serial.print(stations ? stations->size() : 0);
  Serial.print(F(",\"ssids\":"));
  Serial.print(ssids ? ssids->size() : 0);
  Serial.print(F(",\"ips\":"));
  Serial.print(ipList ? ipList->size() : 0);
  Serial.print(F(",\"probes\":"));
  Serial.print(probe_req_ssids ? probe_req_ssids->size() : 0);
  Serial.print(F(",\"airtags\":"));
  Serial.print(airtags ? airtags->size() : 0);
  Serial.print(F(",\"rid\":"));
  Serial.print(wifi_scan_obj.remoteIdCount());
  #ifdef HAS_CSI_MOTION
    Serial.print(F(",")); boolField(F("\"csi\":"), csi_motion_obj.active(), false);
  #endif
  Serial.println(F("}"));
}

// ---------------------------------------------------------------------------
// jsonlist emitters. Each returns the number of objects it actually emitted so
// the closing {"t":"end"} "n" always matches the streamed rows.
// ---------------------------------------------------------------------------
static int listAps() {
  int n = access_points ? access_points->size() : 0;
  for (int i = 0; i < n; i++) {
    AccessPoint ap = access_points->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"ap\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"ch\":"));   Serial.print(ap.channel);
    Serial.print(F(",\"rssi\":")); Serial.print(ap.rssi);
    Serial.print(F(",")); boolField(F("\"sel\":"), ap.selected);
    Serial.print(F("\"pkts\":"));  Serial.print(ap.packets);
    Serial.print(F(",\"sec\":"));  Serial.print(ap.sec);
    Serial.print(F(",")); boolField(F("\"wps\":"), ap.wps);
    Serial.print(F("\"nsta\":"));  Serial.print(ap.stations ? ap.stations->size() : 0);
    Serial.print(F(",\"bssid\":\"")); Serial.print(macToString(ap.bssid));
    Serial.print(F("\",\"essid\":\"")); Serial.print(jsonEscape(ap.essid));
    Serial.println(F("\"}"));
  }
  return n;
}

static int listStations() {
  if (!access_points || !stations) return 0;
  int emitted = 0;
  for (int x = 0; x < access_points->size(); x++) {
    AccessPoint ap = access_points->get(x);
    if (!ap.stations) continue;
    for (int j = 0; j < ap.stations->size(); j++) {
      uint16_t idx = ap.stations->get(j);
      Station st = stations->get(idx);
      Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"sta\",\"ap\":"));
      Serial.print(x);
      Serial.print(F(",\"i\":"));   Serial.print(idx);
      Serial.print(F(",")); boolField(F("\"sel\":"), st.selected);
      Serial.print(F("\"pkts\":")); Serial.print(st.packets);
      Serial.print(F(",\"mac\":\"")); Serial.print(macToString(st.mac));
      Serial.println(F("\"}"));
      emitted++;
    }
  }
  return emitted;
}

static int listSsids() {
  int n = ssids ? ssids->size() : 0;
  for (int i = 0; i < n; i++) {
    ssid s = ssids->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"ssid\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"ch\":")); Serial.print(s.channel);
    Serial.print(F(",")); boolField(F("\"sel\":"), s.selected);
    Serial.print(F("\"essid\":\"")); Serial.print(jsonEscape(s.essid));
    Serial.println(F("\"}"));
  }
  return n;
}

static int listIps() {
  int n = ipList ? ipList->size() : 0;
  for (int i = 0; i < n; i++) {
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"ip\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"ip\":\""));
    Serial.print(ipList->get(i).toString());
    Serial.println(F("\"}"));
  }
  return n;
}

static int listProbes() {
  int n = probe_req_ssids ? probe_req_ssids->size() : 0;
  for (int i = 0; i < n; i++) {
    ProbeReqSsid p = probe_req_ssids->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"probe\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"req\":")); Serial.print(p.requests);
    Serial.print(F(",")); boolField(F("\"sel\":"), p.selected);
    Serial.print(F("\"essid\":\"")); Serial.print(jsonEscape(p.essid));
    Serial.println(F("\"}"));
  }
  return n;
}

static int listAirtags() {
  int n = airtags ? airtags->size() : 0;
  for (int i = 0; i < n; i++) {
    AirTag a = airtags->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"airtag\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"rssi\":")); Serial.print(a.rssi);
    Serial.print(F(",")); boolField(F("\"sel\":"), a.selected);
    Serial.print(F("\"mac\":\"")); Serial.print(jsonEscape(a.mac));
    Serial.println(F("\"}"));
  }
  return n;
}

// jsonlist d - detected Remote ID (drone) records. Coordinates are emitted as
// the raw 1e-7 degree integers the ASTM/Open Drone ID payload carries, so the
// host divides by 1e7 (no lossy on-device float formatting). alt/speed are
// metres / m-per-second; "loc" says whether the location fields are valid.
static int listRemoteId() {
  size_t n = wifi_scan_obj.remoteIdCount();
  RemoteIdRecord r;
  int emitted = 0;
  for (size_t i = 0; i < n; i++) {
    if (!wifi_scan_obj.remoteIdAt(i, r)) continue;
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"rid\",\"i\":"));
    Serial.print((int)i);
    Serial.print(F(",\"mac\":\"")); Serial.print(macToString(r.mac));
    Serial.print(F("\",\"uas\":\"")); Serial.print(jsonEscape(String(r.uasId)));
    Serial.print(F("\",\"op\":\"")); Serial.print(jsonEscape(String(r.operatorId)));
    Serial.print(F("\",\"lat\":")); Serial.print(r.latitudeE7);
    Serial.print(F(",\"lon\":")); Serial.print(r.longitudeE7);
    Serial.print(F(",\"alt\":")); Serial.print(r.altitudeGeoM, 1);
    Serial.print(F(",\"spd\":")); Serial.print(r.horizontalSpeedMps, 1);
    Serial.print(F(",\"dir\":")); Serial.print(r.directionDeg);
    Serial.print(F(",\"rssi\":")); Serial.print(r.rssi);
    Serial.print(F(",\"ua\":")); Serial.print(r.uaType);
    Serial.print(F(",\"pkts\":")); Serial.print(r.packetCount);
    Serial.print(F(",")); boolField(F("\"loc\":"), r.hasLocation, false);
    Serial.println(F("}"));
    emitted++;
  }
  return emitted;
}

// jsonlist g - the configured geofences (persisted in settings, not a live scan).
static int listGeofences() {
  int emitted = 0;
  for (uint8_t i = 0; i < MAX_GEOFENCES; i++) {
    GeofenceConfig fence;
    if (!settings_obj.loadGeofence(i, fence)) continue;
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"fence\",\"i\":"));
    Serial.print(i + 1);
    Serial.print(F(",")); boolField(F("\"en\":"), fence.enabled);
    Serial.print(F("\"lat\":")); Serial.print(fence.latitude, 6);
    Serial.print(F(",\"lon\":")); Serial.print(fence.longitude, 6);
    Serial.print(F(",\"r\":")); Serial.print(fence.radiusMiles, 2);
    Serial.print(F(",\"name\":\"")); Serial.print(jsonEscape(fence.name));
    Serial.println(F("\"}"));
    emitted++;
  }
  return emitted;
}

static void printList(char which) {
  int count;
  switch (which) {
    case 'a': count = listAps();      break;
    case 's': count = listSsids();    break;
    case 'c': count = listStations(); break;
    case 'i': count = listIps();      break;
    case 'p': count = listProbes();   break;
    case 't': count = listAirtags();  break;
    case 'd': count = listRemoteId(); break;
    case 'g': count = listGeofences(); break;
    default:
      // Unknown list type: report an explicit error instead of silently
      // returning the AP list under the wrong label.
      Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"err\",\"cmd\":\"jsonlist\",\"arg\":\""));
      Serial.print(jsonEscape(String(which))); // escape so e.g. `jsonlist \` stays valid JSON
      Serial.println(F("\"}"));
      return;
  }
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"end\",\"list\":\""));
  Serial.print(which);
  Serial.print(F("\",\"n\":"));
  Serial.print(count);
  Serial.println(F("}"));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
bool JsonSerial::jsonModeEnabled() {
  return g_jsonMode;
}

bool JsonSerial::handle(LinkedList<String>* cmd_args) {
  if (!cmd_args || cmd_args->size() == 0) return false;
  String cmd = cmd_args->get(0);

  if (cmd == JSON_INFO_CMD) {
    g_jsonMode = true; // a host is talking to us -> enable streaming
    printInfo();
    return true;
  }
  if (cmd == JSON_STATUS_CMD) {
    printStatus();
    return true;
  }
  if (cmd == JSON_MODE_CMD) {
    if (cmd_args->size() > 1) {
      String a = cmd_args->get(1);
      g_jsonMode = (a == "1" || a == "on" || a == "true");
    }
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"jsonmode\","));
    boolField(F("\"on\":"), g_jsonMode, false);
    Serial.println(F("}"));
    return true;
  }
  if (cmd == JSON_BAUD_CMD) {
    // Raise (or lower) the serial line rate so a host can drain captured pcap
    // faster than the 115200 default. The confirmation is sent at the OLD rate
    // and flushed BEFORE switching, so the host can read it, then re-open its
    // port at the new rate — no bytes are lost across the change. On native
    // USB-CDC boards updateBaudRate() is a harmless no-op (USB runs at its own
    // speed regardless of the requested rate).
    long rate = (cmd_args->size() > 1) ? cmd_args->get(1).toInt() : 0;
    if (rate < 9600) rate = 115200; // guard against a bogus / missing argument
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"baud\",\"rate\":"));
    Serial.print(rate);
    Serial.println(F("}"));
    Serial.flush();       // drain TX at the old rate before switching
    delay(60);
#if !ARDUINO_USB_CDC_ON_BOOT
    Serial.updateBaudRate((uint32_t)rate);
#endif
    return true;
  }
  if (cmd == JSON_LIST_CMD) {
    char which = 'a';
    if (cmd_args->size() > 1) {
      String a = cmd_args->get(1);
      a.replace("-", "");
      a.trim();
      if (a.length() > 0) which = a.charAt(0);
    }
    printList(which);
    return true;
  }
  return false;
}

void JsonSerial::emitAnalyzerSample(uint8_t mode, int ch, int16_t value) {
  if (!g_jsonMode) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"asample\",\"mode\":"));
  Serial.print(mode);
  Serial.print(F(",\"ch\":"));
  Serial.print(ch);
  Serial.print(F(",\"v\":"));
  Serial.print(value);
  Serial.println(F("}"));
}

void JsonSerial::emitChannelActivity(const int* channels, const uint8_t* values, int count, int page) {
  if (!g_jsonMode || !channels || !values || count <= 0) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"chan\",\"page\":"));
  Serial.print(page);
  Serial.print(F(",\"ch\":["));
  for (int i = 0; i < count; i++) {
    if (i) Serial.print(',');
    Serial.print(channels[i]);
  }
  Serial.print(F("],\"v\":["));
  for (int i = 0; i < count; i++) {
    if (i) Serial.print(',');
    Serial.print(values[i]);
  }
  Serial.println(F("]}"));
}

void JsonSerial::emitCred(const String& user, const String& pass) {
  if (!g_jsonMode) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"cred\",\"u\":\""));
  Serial.print(jsonEscape(user));
  Serial.print(F("\",\"p\":\""));
  Serial.print(jsonEscape(pass));
  Serial.println(F("\"}"));
}

void JsonSerial::emitFoxHunt(const String& name, int rssi, int channel, bool bt) {
  if (!g_jsonMode) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"fox\",\"name\":\""));
  Serial.print(jsonEscape(name));
  Serial.print(F("\",\"rssi\":"));
  Serial.print(rssi);
  Serial.print(F(",\"ch\":"));
  Serial.print(channel);
  Serial.print(F(",")); boolField(F("\"bt\":"), bt, false);
  Serial.println(F("}"));
}

void JsonSerial::emitCsi(const char* state, int motion, int reliability, int rate,
                         int calibration, const String& target, int channel) {
  if (!g_jsonMode) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"csi\",\"state\":\""));
  Serial.print(state ? state : "");
  Serial.print(F("\",\"motion\":"));
  Serial.print(motion);
  Serial.print(F(",\"rel\":"));
  Serial.print(reliability);
  Serial.print(F(",\"rate\":"));
  Serial.print(rate);
  Serial.print(F(",\"cal\":"));
  Serial.print(calibration);
  Serial.print(F(",\"ch\":"));
  Serial.print(channel);
  Serial.print(F(",\"ap\":\""));
  Serial.print(jsonEscape(target));
  Serial.println(F("\"}"));
}
