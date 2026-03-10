// CYDWiFiScanner — Advanced WiFi/BLE Security Scanner for CYD (Cheap Yellow Display)
//
// MODE_SCAN:    Active network scanner — sorted SSID list, RSSI bars, CH, ENC
//               Results stay on screen during re-scan; header shows ↻ when updating
// MODE_PROBE:   Probe request sniffer — captures device MAC → queried SSID in real time
// MODE_CHANNEL: Channel traffic analyzer — bar chart of frame density across CH 1-13
//               Tap a bar to lock that channel
// MODE_DEAUTH:  Deauth/disassoc attack detector — rate-based alert, body tap = clear
// MODE_BLE:     BLE / card skimmer hunter — flags suspicious devices by name + MAC prefix
// MODE_SHADY:   Suspicious network analyzer — scores networks for evil twin, PineAP,
//               open/hidden/strong-signal/random-SSID threats
//
// MODE_AP:       CSI ping AP — turns this CYD into Board 1 (soft AP + UDP broadcaster)
//               Required by PRESENCE mode on a second CYD (Board 2)
// MODE_PRESENCE: Human presence detector via WiFi CSI — connects to an AP CYD,
//               measures signal variance across all OFDM subcarriers.
//               Still room = flat CSI.  Person present/moving = variance spikes.
//               Tap body to calibrate empty-room baseline.
//
// Footer:  9 equal tap zones = [ SCAN | PROBE | CHAN | DAUTH | BLE | SHADY | HASH | AP | PRES ]
// Theme:   Green-on-black hacker terminal, 320x240 landscape
// LED:     RGB status LED — green=touch, red=deauth, blue=BLE threat, yellow=shady net
// SD:      Logs threats to /cydscan.txt when SD card present (HSPI on GPIO 18/19/23/5)
// Serial:  [SCAN]/[PROBE]/[CHAN]/[DEAUTH]/[BLE]/[SHADY] prefixed logs at 115200 baud

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <Arduino_GFX_Library.h>
#include <XPT2046_Touchscreen.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <SD.h>
#include <FS.h>
#include <WiFiUdp.h>

// ─── Display — CYD ILI9341 320×240 landscape ────────────────────────────────
#define GFX_BL 21
Arduino_DataBus *bus = new Arduino_HWSPI(2/*DC*/, 15/*CS*/, 14/*SCK*/, 13/*MOSI*/, 12/*MISO*/);
Arduino_GFX    *gfx = new Arduino_ILI9341(bus, GFX_NOT_DEFINED, 1/*landscape*/);

// ─── Touch — XPT2046 on VSPI ────────────────────────────────────────────────
#define XPT2046_IRQ   36
#define XPT2046_MOSI  32
#define XPT2046_MISO  39
#define XPT2046_CLK   25
#define XPT2046_CS    33
#define TOUCH_DEBOUNCE 300
SPIClass touchSPI(VSPI);
XPT2046_Touchscreen ts(XPT2046_CS, XPT2046_IRQ);
static unsigned long lastTouchTime = 0;

// ─── RGB LED (active LOW) ────────────────────────────────────────────────────
#define LED_R 4
#define LED_G 16
#define LED_B 17
static void ledSet(bool r, bool g, bool b) {
  digitalWrite(LED_R, r ? LOW : HIGH);
  digitalWrite(LED_G, g ? LOW : HIGH);
  digitalWrite(LED_B, b ? LOW : HIGH);
}
static void ledOff() { ledSet(false, false, false); }
static void ledFlash(bool r, bool g, bool b, int ms) {
  ledSet(r, g, b); delay(ms); ledOff();
}

// ─── SD Card — HSPI ─────────────────────────────────────────────────────────
#define SD_CS   5
#define SD_MISO 19
#define SD_MOSI 23
#define SD_SCK  18
static SPIClass sdSPI(HSPI);
static bool     sdOK = false;
static void sdLog(const char* tag, const char* msg) {
  if (!sdOK) return;
  File f = SD.open("/cydscan.txt", FILE_APPEND);
  if (f) { f.printf("[%lu][%s] %s\n", millis(), tag, msg); f.close(); }
}

// ─── Layout ─────────────────────────────────────────────────────────────────
#define SCREEN_W   320
#define SCREEN_H   240
#define HEADER_H    20
#define FOOTER_H    28
#define BODY_Y      HEADER_H
#define BODY_H      192
#define FOOTER_Y    212
#define NUM_MODES     9

// ─── Colors ─────────────────────────────────────────────────────────────────
#define COL_BG        0x0000
#define COL_GREEN     0x07E0
#define COL_DIM       0x0320
#define COL_YELLOW    0xFFE0
#define COL_RED       0xF800
#define COL_WHITE     0xFFFF
#define COL_CYAN      0x07FF
#define COL_ORANGE    0xFB20
#define COL_MAGENTA   0xF81F
#define COL_HDR_BG    0x0100
#define COL_FTR_BG    0x00C0
#define COL_DIVIDER   0x0180

// ─── Modes ──────────────────────────────────────────────────────────────────
#define MODE_SCAN    0
#define MODE_PROBE   1
#define MODE_CHANNEL 2
#define MODE_DEAUTH  3
#define MODE_BLE     4
#define MODE_SHADY   5
#define MODE_HASH    6
#define MODE_AP      7
#define MODE_PRESENCE 8
static const char* MODE_NAMES[NUM_MODES] = {"SCAN","PROBE","CHAN","DAUTH","BLE","SHADY","HASH","AP","PRES"};

// ─── App state ───────────────────────────────────────────────────────────────
static int  sc_mode   = -1;
static bool sc_redraw = true;

// ─── SCAN state ──────────────────────────────────────────────────────────────
// Layout (AntiPMatrix-style compact rows):
//   SSID(14) * [BAR-110px] dBm(4) Ch(3)   → 10 rows × 18px = 180px body
#define SCAN_ROW_H     18
#define SCAN_VISIBLE   10
#define SCAN_INTERVAL  5000UL
#define SCAN_NET_MAX   40

struct ScanNet {
  char ssid[27];
  char bssid[18];
  int  rssi;
  int  channel;
  wifi_auth_mode_t enc;
  bool hidden;
};

static ScanNet       scanNets[SCAN_NET_MAX];
static ScanNet       scanTmp[SCAN_NET_MAX];  // scratch buffer for processing results
static int           sc_scanCount   = 0;
static int           sc_scanScroll  = 0;
static bool          sc_scanRunning = false;
static unsigned long sc_scanLast    = 0;

// Called when WiFi.scanComplete() returns results; processes into scanNets[]
static void processScanResults(int n) {
  int count = 0;
  // Pass 1: visible networks, dedup by BSSID
  for (int i = 0; i < n && count < SCAN_NET_MAX; i++) {
    if (WiFi.SSID(i).length() == 0) continue;
    char bssid[18]; strncpy(bssid, WiFi.BSSIDstr(i).c_str(), 17); bssid[17] = '\0';
    bool dup = false;
    for (int j = 0; j < count; j++) { if (strcmp(scanTmp[j].bssid, bssid)==0){dup=true;break;} }
    if (dup) continue;
    ScanNet& s = scanTmp[count++];
    strncpy(s.ssid, WiFi.SSID(i).c_str(), 26); s.ssid[26] = '\0';
    strncpy(s.bssid, bssid, 17); s.bssid[17] = '\0';
    s.rssi = WiFi.RSSI(i); s.channel = WiFi.channel(i);
    s.enc = WiFi.encryptionType(i);
    s.hidden = false;
  }
  // Sort visible by RSSI descending (insertion sort)
  for (int i = 1; i < count; i++) {
    ScanNet key = scanTmp[i]; int j = i-1;
    while (j >= 0 && scanTmp[j].rssi < key.rssi) { scanTmp[j+1] = scanTmp[j]; j--; }
    scanTmp[j+1] = key;
  }
  // Pass 2: hidden networks appended at bottom
  for (int i = 0; i < n && count < SCAN_NET_MAX; i++) {
    if (WiFi.SSID(i).length() > 0) continue;
    char bssid[18]; strncpy(bssid, WiFi.BSSIDstr(i).c_str(), 17); bssid[17] = '\0';
    bool dup = false;
    for (int j = 0; j < count; j++) { if (strcmp(scanTmp[j].bssid, bssid)==0){dup=true;break;} }
    if (dup) continue;
    ScanNet& s = scanTmp[count++];
    strcpy(s.ssid, ""); strncpy(s.bssid, bssid, 17); s.bssid[17] = '\0';
    s.rssi = WiFi.RSSI(i); s.channel = WiFi.channel(i);
    s.enc = WiFi.encryptionType(i);
    s.hidden = true;
  }
  WiFi.scanDelete();
  memcpy(scanNets, scanTmp, sizeof(ScanNet) * count);
  sc_scanCount  = count;
  sc_scanScroll = 0;
}

static const char* encLabel(wifi_auth_mode_t enc) {
  switch (enc) {
    case WIFI_AUTH_OPEN:          return "OPEN";
    case WIFI_AUTH_WEP:           return "WEP ";
    case WIFI_AUTH_WPA_PSK:       return "WPA ";
    case WIFI_AUTH_WPA2_PSK:      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "WPA+";
    case WIFI_AUTH_WPA3_PSK:      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WP3+";
    default:                      return "????";
  }
}

// ─── PROBE state ─────────────────────────────────────────────────────────────
#define PROBE_MAX     16
#define PROBE_ROW_H   24
#define PROBE_VISIBLE  8
struct ProbeEntry { char mac[18]; char ssid[33]; };
static ProbeEntry probeList[PROBE_MAX];
static int probeHead = 0, probeCount = 0;
static portMUX_TYPE probeMux   = portMUX_INITIALIZER_UNLOCKED;
static int sc_probeScroll      = 0;
static volatile bool probeUpdated = false;

// ─── CHANNEL state ───────────────────────────────────────────────────────────
#define CHAN_COUNT   13
#define CHAN_HOP_MS 200UL
static volatile uint32_t chanFrames[CHAN_COUNT];
static uint8_t  sc_chanCurrent = 1;
static bool     sc_chanLocked  = false;
static unsigned long sc_chanLastHop  = 0;
static unsigned long sc_chanLastDraw = 0;
static portMUX_TYPE chanMux = portMUX_INITIALIZER_UNLOCKED;

// ─── DEAUTH state ────────────────────────────────────────────────────────────
#define DEAUTH_MAX        8
#define DEAUTH_ROW_H     26
#define DEAUTH_ALERT_RATE 5.0f
struct DeauthEntry {
  uint8_t bssid[6]; char bssidStr[18];
  int totalCount;
  unsigned long lastSeen, windowStart;
  int  windowCount; float rate; bool alert;
};
static DeauthEntry deauthList[DEAUTH_MAX];
static int deauthCount = 0;
static portMUX_TYPE deauthMux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool deauthUpdated    = false;
static volatile bool deauthAlertFlash = false;

// ─── BLE state ───────────────────────────────────────────────────────────────
#define BLE_MAX      32
#define BLE_ROW_H    24
#define BLE_VISIBLE   8
struct BLEDevInfo { char mac[18]; char name[24]; int rssi; bool suspicious; unsigned long lastSeen; };
static BLEDevInfo bleDevs[BLE_MAX];
static int bleDevCount = 0;
static portMUX_TYPE bleMux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool bleUpdated   = false;
static volatile bool bleThreatFlash = false;
static bool bleInitialized = false;
static volatile bool bleScanActive = false;
static TaskHandle_t bleScanTaskHandle = NULL;
static int sc_bleScroll = 0;

// Suspicious BLE name fragments
static const char* BLE_SUSPICIOUS_NAMES[] = {
  "HC-03","HC-05","HC-06","HC-08","RNBT","AT-09","DSD TECH","JDY-",
  "SKIMMER","READER","CARD","PAY","CREDIT","DEBIT","ATM"
};
static const int BLE_SUSPICIOUS_COUNT = sizeof(BLE_SUSPICIOUS_NAMES)/sizeof(BLE_SUSPICIOUS_NAMES[0]);

static bool isSuspiciousBLE(const char* name, const char* mac) {
  String upperName = String(name); upperName.toUpperCase();
  for (int i = 0; i < BLE_SUSPICIOUS_COUNT; i++) {
    if (upperName.indexOf(BLE_SUSPICIOUS_NAMES[i]) != -1) return true;
  }
  String macStr = String(mac);
  // Known ESP32/Chinese BLE module OUI prefixes + RN4020 (skimmer common)
  if (macStr.startsWith("00:06:66") || macStr.startsWith("00:12:") ||
      macStr.indexOf("RNBT-") != -1)     return true;
  return false;
}

static void addBLEDevice(const char* mac, const char* name, int rssi) {
  portENTER_CRITICAL_ISR(&bleMux);
  for (int i = 0; i < bleDevCount; i++) {
    if (strcmp(bleDevs[i].mac, mac) == 0) {
      bleDevs[i].rssi    = rssi;
      bleDevs[i].lastSeen = millis();
      portEXIT_CRITICAL_ISR(&bleMux);
      return;
    }
  }
  if (bleDevCount < BLE_MAX) {
    BLEDevInfo& d = bleDevs[bleDevCount++];
    strncpy(d.mac, mac, 17);   d.mac[17]  = '\0';
    strncpy(d.name, name, 23); d.name[23] = '\0';
    d.rssi       = rssi;
    d.lastSeen   = millis();
    d.suspicious = isSuspiciousBLE(name, mac);
    if (d.suspicious) { bleThreatFlash = true; bleUpdated = true; }
  }
  bleUpdated = true;
  portEXIT_CRITICAL_ISR(&bleMux);
}

class BLECallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) {
    addBLEDevice(dev.getAddress().toString().c_str(),
                 dev.getName().c_str(),
                 dev.getRSSI());
  }
};

static void bleScanTask(void* param) {
  BLEScan* s = BLEDevice::getScan();
  s->setAdvertisedDeviceCallbacks(new BLECallback(), false);
  s->setActiveScan(true);
  s->setInterval(100); s->setWindow(99);
  while (bleScanActive) {
    s->clearResults();
    s->start(3, false);   // blocks ~3 s
    delay(500);
  }
  s->stop();
  vTaskDelete(NULL);
}

// ─── SHADY state ─────────────────────────────────────────────────────────────
#define SHADY_MAX      20
#define SHADY_ROW_H    26
#define SHADY_VISIBLE   7
#define SHADY_INTERVAL 15000UL

struct ShadyNet {
  char ssid[27]; char bssid[18];
  int rssi; int channel; char enc[5]; char reason[16];
};
static ShadyNet shadyNets[SHADY_MAX];
static int shadyNetCount  = 0;
static int shadyTotalNets = 0;
static unsigned long sc_shadyLast    = 0;
static bool          sc_shadyRunning = false;
static int sc_shadyScroll = 0;

// PineAP tracking: same BSSID advertising multiple SSIDs
#define PINEAP_MAX 12
struct PineAPEntry { char bssid[18]; char ssids[4][33]; int ssidCount; };
static PineAPEntry pineapTable[PINEAP_MAX];
static int         pineapCount = 0;

static bool checkPineAP(const char* bssid, const char* ssid) {
  for (int i = 0; i < pineapCount; i++) {
    if (strcmp(pineapTable[i].bssid, bssid) == 0) {
      for (int j = 0; j < pineapTable[i].ssidCount; j++) {
        if (strcmp(pineapTable[i].ssids[j], ssid) == 0) return (pineapTable[i].ssidCount >= 3);
      }
      if (pineapTable[i].ssidCount < 4) {
        strncpy(pineapTable[i].ssids[pineapTable[i].ssidCount++], ssid, 32);
      }
      return (pineapTable[i].ssidCount >= 3);
    }
  }
  if (pineapCount < PINEAP_MAX) {
    PineAPEntry& e = pineapTable[pineapCount++];
    strncpy(e.bssid, bssid, 17); e.bssid[17] = '\0';
    strncpy(e.ssids[0], ssid, 32); e.ssidCount = 1;
  }
  return false;
}

static const char* shadySuspicionReason(const char* ssid, int rssi, wifi_auth_mode_t enc) {
  if (rssi > -30)              return "VERY STRONG";
  if (enc == WIFI_AUTH_OPEN)   return "OPEN NET";
  if (ssid[0] == '\0')         return "HIDDEN";
  String s = String(ssid); s.toUpperCase();
  static const char* keywords[] = {"FREE","WIFI","GUEST","OPEN","HOTEL","AIRPORT",
                                    "STARBUCKS","MCDONALDS","XFINITY","ANDROID",
                                    "IPHONE","SAMSUNG","LINKSYS","NETGEAR"};
  for (auto& kw : keywords) { if (s.indexOf(kw) != -1) return "SUSP NAME"; }
  // Too many special chars → random beacon spam
  int special = 0;
  for (int i = 0; ssid[i]; i++) { if (!isalnum(ssid[i]) && ssid[i]!='-' && ssid[i]!='_') special++; }
  if (special > 2) return "BEACON SPAM";
  return nullptr;
}

// ─── HASH state (WPA2 handshake / EAPOL capture) ─────────────────────────────
#define HASH_AP_MAX      80    // known APs tracked from beacons
#define HASH_CAP_MAX     20    // captured handshakes (for SD logging)
#define HASH_HOP_MS     500UL  // channel-hop interval
#define HASH_PKT_QUEUE    8    // in-RAM PCAP packet queue (ISR→main loop SD writes)
#define HASH_PKT_MAXLEN 296    // max raw 802.11 frame size to capture
#define HASH_HIST_W     280    // history ring-buffer width (pixels / seconds)

struct HashAP      { uint8_t mac[6]; char ssid[33]; uint8_t ssid_len; };
struct HashCapture { char ssid[33]; char bssid[18]; unsigned long ts; };
struct PcapPkt     { uint8_t data[HASH_PKT_MAXLEN]; uint16_t len; unsigned long ts; };

static HashAP      hashAPs[HASH_AP_MAX];
static int         hashAPCount      = 0;
static HashCapture hashCaptures[HASH_CAP_MAX];
static int         hashCaptureHead  = 0;
static int         hashCaptureCount = 0;
static int         hashEapolTotal   = 0;
static int         hashDeauthCount  = 0;
static portMUX_TYPE hashMux         = portMUX_INITIALIZER_UNLOCKED;
static volatile bool hashUpdated    = false;
static uint8_t     sc_hashChan      = 1;
static unsigned long sc_hashLastHop  = 0;
static unsigned long sc_hashLastDraw = 0;

// Lock-free single-producer (ISR) / single-consumer (loop) PCAP packet queue
static PcapPkt      hashPktQueue[HASH_PKT_QUEUE];
static volatile int hashPktHead = 0;
static volatile int hashPktTail = 0;
static File         hashPcapFile;
static bool         hashPcapOpen = false;

// Per-second stats fed by ISR, consumed by loop every second
static volatile uint32_t hashTmpPktCount = 0; // all frames this second
static volatile int32_t  hashRssiSum     = 0; // RSSI sum for averaging
static volatile uint32_t hashEapolSec    = 0; // EAPOL this second
static volatile uint32_t hashDeauthSec   = 0; // deauth this second

// Scrolling history ring-buffers (written from loop, read in renderHash)
static uint32_t hashPktsBuf[HASH_HIST_W];    // packets per second
static int8_t   hashRssiBuf[HASH_HIST_W];    // average RSSI per second
static uint8_t  hashEapolBuf[HASH_HIST_W];   // EAPOL per second (capped 60)
static uint8_t  hashDeauthBuf[HASH_HIST_W];  // deauth per second (capped 60)
static int      hashHistHead = 0;             // next write position
static bool     hashHistFull = false;

// Last-seen info updated by ISR
static char hashLastSSID[33]      = "[none]";
static char hashLastSSIDMac[18]   = {0};
static int8_t hashLastRSSI        = 0;
static char hashLastEapolSSID[33] = "[none]";
static char hashLastEapolMac[18]  = {0};
static uint8_t hashOldChan        = 0; // track channel changes for graph annotation

// ─── AP mode state (Board 1: soft-AP + UDP ping broadcaster) ─────────────────
#define AP_SSID      "CYD_CSI"
#define AP_PASS      "cydscanner123"
#define AP_PORT      1234
#define AP_BCAST_IP  "192.168.4.255"
#define AP_PING_MS   20UL   // 50 pings/sec → ~50 CSI frames/sec on the STA side

static WiFiUDP       apUdp;
static bool          apUdpStarted = false;
static unsigned long apPingCount  = 0;
static unsigned long apLastPing   = 0;
static unsigned long apLastDraw   = 0;

// ─── PRESENCE mode state (Board 2: CSI human-presence detector) ──────────────
// Layout constants for renderPresence()
#define P_STATUS_Y  (BODY_Y + 8)    // big PRESENT/CLEAR label
#define P_CONF_Y    (BODY_Y + 48)   // confidence bar
#define P_CONF_H    14
#define P_CONF_W    200
#define P_SPARK_Y   (BODY_Y + 72)   // CSI variance sparkline
#define P_SPARK_H   72
#define P_UNITS_W   36              // left units column width
#define P_SPARK_X   P_UNITS_W
#define P_SPARK_W   (SCREEN_W - P_UNITS_W) // 284
#define P_STATS_Y   (BODY_Y + 152)  // stats strip

#define CSI_WIN      30    // rolling variance window (frames)
#define CSI_HIST_W   284   // sparkline history depth = P_SPARK_W
#define CSI_VAR_LO   3.0f  // variance below this → empty room
#define CSI_VAR_HI   6.0f  // variance above this → definitely present (tuned to observed range)
#define CSI_CAL_DELAY_MS 6000UL  // ms countdown before empty-room calibration fires

#define PRES_CONNECTING  0
#define PRES_CSI_ACTIVE  1

static uint8_t       presState           = PRES_CONNECTING;
static unsigned long presConnStart       = 0;
static unsigned long presLastDraw        = 0;
static unsigned long presLastKeepalive   = 0;
static TaskHandle_t  psKillerHandle      = NULL;
static WiFiUDP       presUdp;
static bool          presUdpStarted      = false;
static portMUX_TYPE  csiMux         = portMUX_INITIALIZER_UNLOCKED;

// ISR-side rolling amplitude window (one entry per received CSI frame)
static volatile float    csiWin[CSI_WIN];
static volatile int      csiWinHead   = 0;
static volatile bool     csiWinFull   = false;
static volatile int8_t   csiLastRSSI  = 0;
static volatile bool     csiUpdated   = false;
static volatile uint32_t csiFrameSec  = 0;  // frames received this 100 ms tick

// Loop-side processed state
static float    csiVariance    = 0.0f;
static float    csiPeakVar     = 0.0f;   // highest variance seen this session
static uint8_t  csiConfidence  = 0;      // 0-100
static float    csiVarBaseline    = 0.0f;   // calibrated empty-room offset
static bool     csiCalibrated     = false;
static bool     csiCalPending     = false;  // countdown in progress
static unsigned long csiCalCountStart = 0;
static uint32_t csiFrameRate   = 0;      // frames/sec (approx)

// Sparkline history (loop-written, render-read)
static float csiHistBuf[CSI_HIST_W];
static int   csiHistHead = 0;
static bool  csiHistFull = false;
static unsigned long csiLastSec = 0;

// CSI receive callback — called from WiFi task context
static void IRAM_ATTR onCSI(void* ctx, wifi_csi_info_t* data) {
  if (!data || !data->buf || data->len == 0) return;
  float sum = 0;
  for (int i = 0; i < data->len; i++) sum += (float)abs(data->buf[i]);
  float amp = sum / (float)data->len;
  portENTER_CRITICAL_ISR(&csiMux);
  csiWin[csiWinHead] = amp;
  csiWinHead = (csiWinHead + 1) % CSI_WIN;
  if (csiWinHead == 0) csiWinFull = true;
  csiLastRSSI = (int8_t)data->rx_ctrl.rssi;
  csiFrameSec++;
  csiUpdated = true;
  portEXIT_CRITICAL_ISR(&csiMux);
}

// Continuously re-asserts WIFI_PS_NONE — the WiFi stack can silently
// re-enable power-save after internal events, killing CSI frame delivery.
static void psKillerTask(void* arg) {
  while (1) {
    esp_wifi_set_ps(WIFI_PS_NONE);
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

// ─── PCAP helpers ─────────────────────────────────────────────────────────────
static bool hashOpenPcap() {
  if (!sdOK) return false;
  char fname[32];
  snprintf(fname, sizeof(fname), "/hash%lu.pcap", millis());
  hashPcapFile = SD.open(fname, FILE_WRITE);
  if (!hashPcapFile) return false;
  // PCAP global header (little-endian, 802.11 link type = 105)
  uint8_t hdr[24] = {};
  uint32_t magic = 0xa1b2c3d4; uint16_t vmaj = 2, vmin = 4;
  int32_t zone = 0; uint32_t sig = 0, snap = 2500, net = 105;
  memcpy(hdr+ 0, &magic, 4); memcpy(hdr+ 4, &vmaj,  2);
  memcpy(hdr+ 6, &vmin,  2); memcpy(hdr+ 8, &zone,  4);
  memcpy(hdr+12, &sig,   4); memcpy(hdr+16, &snap,  4);
  memcpy(hdr+20, &net,   4);
  hashPcapFile.write(hdr, 24);
  hashPcapFile.flush();
  Serial.printf("[HASH] PCAP open: %s\n", fname);
  return true;
}

static void hashClosePcap() {
  if (hashPcapOpen) { hashPcapFile.close(); hashPcapOpen = false; }
}

// Call from main loop to drain packet queue → SD card
static void hashFlushQueue() {
  while (hashPktTail != hashPktHead) {
    int idx = hashPktTail;
    if (hashPcapOpen) {
      uint8_t phdr[16];
      uint32_t ts_sec  = hashPktQueue[idx].ts / 1000;
      uint32_t ts_usec = (hashPktQueue[idx].ts % 1000) * 1000;
      uint32_t incl = hashPktQueue[idx].len, orig = hashPktQueue[idx].len;
      memcpy(phdr+ 0, &ts_sec,  4); memcpy(phdr+ 4, &ts_usec, 4);
      memcpy(phdr+ 8, &incl,    4); memcpy(phdr+12, &orig,    4);
      hashPcapFile.write(phdr, 16);
      hashPcapFile.write(hashPktQueue[idx].data, hashPktQueue[idx].len);
      hashPcapFile.flush();
    }
    hashPktTail = (hashPktTail + 1) % HASH_PKT_QUEUE;
  }
}

// ─── Promiscuous callback ─────────────────────────────────────────────────────
static void IRAM_ATTR onPromisc(void* buf, wifi_promiscuous_pkt_type_t ptype) {
  if (sc_mode == MODE_CHANNEL) {
    int ch = ((wifi_promiscuous_pkt_t*)buf)->rx_ctrl.channel;
    if (ch >= 1 && ch <= CHAN_COUNT) {
      portENTER_CRITICAL_ISR(&chanMux); chanFrames[ch-1]++; portEXIT_CRITICAL_ISR(&chanMux);
    }
    return;
  }

  if (sc_mode == MODE_HASH) {
    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* f = pkt->payload;
    uint32_t sig_len = pkt->rx_ctrl.sig_len;
    if (ptype == WIFI_PKT_MGMT && sig_len >= 4) sig_len -= 4; // strip FCS
    if (sig_len < 12 || sig_len > HASH_PKT_MAXLEN) return;

    // Count every packet + RSSI for per-second stats
    hashTmpPktCount++;
    hashRssiSum += pkt->rx_ctrl.rssi;

    uint8_t ftype    = (f[0] >> 2) & 0x3;
    uint8_t fsubtype = (f[0] >> 4) & 0xF;

    // Beacon (type=0, subtype=8): track AP MAC → SSID + update last-seen info
    if (ftype == 0 && fsubtype == 8 && sig_len >= 42) {
      uint8_t ssid_len = f[37];
      if (ssid_len > 0 && ssid_len <= 32 && (uint32_t)(38 + ssid_len) <= sig_len) {
        const uint8_t* ap_mac = &f[16];
        portENTER_CRITICAL_ISR(&hashMux);
        // Store last-seen beacon info for footer display
        memcpy(hashLastSSID, &f[38], ssid_len); hashLastSSID[ssid_len] = '\0';
        snprintf(hashLastSSIDMac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);
        hashLastRSSI = (int8_t)pkt->rx_ctrl.rssi;
        // Add to AP table if new
        bool known = false;
        for (int i = 0; i < hashAPCount; i++) {
          if (memcmp(hashAPs[i].mac, ap_mac, 6) == 0) { known = true; break; }
        }
        if (!known && hashAPCount < HASH_AP_MAX) {
          memcpy(hashAPs[hashAPCount].mac, ap_mac, 6);
          memcpy(hashAPs[hashAPCount].ssid, &f[38], ssid_len);
          hashAPs[hashAPCount].ssid[ssid_len] = '\0';
          hashAPs[hashAPCount].ssid_len = ssid_len;
          hashAPCount++;
        }
        portEXIT_CRITICAL_ISR(&hashMux);
      }
    }

    // EAPOL: EtherType 0x888E at offset 30-31 or 32-33
    if (sig_len >= 34 &&
        ((f[30] == 0x88 && f[31] == 0x8E) || (f[32] == 0x88 && f[33] == 0x8E))) {
      const uint8_t* src_mac = &f[16];
      portENTER_CRITICAL_ISR(&hashMux);
      hashEapolTotal++;
      hashEapolSec++;
      // Resolve SSID from AP table
      char ssid_buf[33] = "???";
      for (int i = 0; i < hashAPCount; i++) {
        if (memcmp(hashAPs[i].mac, src_mac, 6) == 0) {
          memcpy(ssid_buf, hashAPs[i].ssid, hashAPs[i].ssid_len + 1); break;
        }
      }
      // Update last EAPOL display strings
      strncpy(hashLastEapolSSID, ssid_buf, 32); hashLastEapolSSID[32] = '\0';
      snprintf(hashLastEapolMac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
               src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
      // Circular capture log (for SD)
      HashCapture& cap = hashCaptures[hashCaptureHead];
      strncpy(cap.ssid, ssid_buf, 32); cap.ssid[32] = '\0';
      snprintf(cap.bssid, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
               src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
      cap.ts = millis();
      hashCaptureHead = (hashCaptureHead + 1) % HASH_CAP_MAX;
      if (hashCaptureCount < HASH_CAP_MAX) hashCaptureCount++;
      // Queue PCAP write
      int next = (hashPktHead + 1) % HASH_PKT_QUEUE;
      if (next != hashPktTail) {
        PcapPkt& q = hashPktQueue[hashPktHead];
        q.len = (uint16_t)sig_len; memcpy(q.data, f, sig_len); q.ts = millis();
        hashPktHead = next;
      }
      hashUpdated = true;
      portEXIT_CRITICAL_ISR(&hashMux);
      ledFlash(false, true, false, 20);
    }

    // Deauth / disassoc
    if (ptype == WIFI_PKT_MGMT && (f[0] == 0xA0 || f[0] == 0xC0)) {
      portENTER_CRITICAL_ISR(&hashMux);
      hashDeauthCount++;
      hashDeauthSec++;
      portEXIT_CRITICAL_ISR(&hashMux);
    }
    return;
  }

  if (ptype != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;
  uint8_t type    = (f[0] >> 2) & 0x3;
  uint8_t subtype = (f[0] >> 4) & 0xF;
  if (type != 0) return;

  if (subtype == 4 && sc_mode == MODE_PROBE) {
    const uint8_t* sa = &f[10];
    char mac[18]; snprintf(mac,18,"%02X:%02X:%02X:%02X:%02X:%02X",sa[0],sa[1],sa[2],sa[3],sa[4],sa[5]);
    char ssid[33] = "";
    if (len > 25 && f[24] == 0x00) {
      uint8_t sl = f[25];
      if (sl > 0 && sl <= 32 && len >= 26+sl) { memcpy(ssid,&f[26],sl); ssid[sl]='\0'; }
    }
    portENTER_CRITICAL_ISR(&probeMux);
    strncpy(probeList[probeHead].mac, mac, 17);  probeList[probeHead].mac[17] = '\0';
    strncpy(probeList[probeHead].ssid, ssid, 32); probeList[probeHead].ssid[32] = '\0';
    probeHead = (probeHead+1) % PROBE_MAX;
    if (probeCount < PROBE_MAX) probeCount++;
    probeUpdated = true;
    portEXIT_CRITICAL_ISR(&probeMux);
  }
  else if ((subtype==12||subtype==10) && sc_mode==MODE_DEAUTH) {
    const uint8_t* bssid = &f[16];
    if (bssid[0]==0xFF && bssid[1]==0xFF) return;
    unsigned long now = millis();
    portENTER_CRITICAL_ISR(&deauthMux);
    int found = -1;
    for (int i = 0; i < deauthCount; i++) { if (memcmp(deauthList[i].bssid,bssid,6)==0){found=i;break;} }
    if (found<0 && deauthCount<DEAUTH_MAX) {
      found = deauthCount++;
      memcpy(deauthList[found].bssid,bssid,6);
      snprintf(deauthList[found].bssidStr,18,"%02X:%02X:%02X:%02X:%02X:%02X",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
      deauthList[found].totalCount=0; deauthList[found].windowStart=now; deauthList[found].windowCount=0; deauthList[found].rate=0; deauthList[found].alert=false;
    }
    if (found>=0) {
      DeauthEntry& de = deauthList[found];
      de.totalCount++; de.lastSeen=now;
      if (now-de.windowStart>=3000) { de.rate=de.windowCount/3.0f; de.windowStart=now; de.windowCount=1; }
      else { de.windowCount++; unsigned long el=max(1UL,(now-de.windowStart+999)/1000); de.rate=(float)de.windowCount/(float)el; }
      de.alert=(de.rate>=DEAUTH_ALERT_RATE);
      if (de.alert) deauthAlertFlash=true;
    }
    deauthUpdated=true;
    portEXIT_CRITICAL_ISR(&deauthMux);
  }
}

// ─── Mode transitions ────────────────────────────────────────────────────────
static void enablePromisc(bool all) {
  wifi_promiscuous_filter_t filt;
  filt.filter_mask = all ? WIFI_PROMIS_FILTER_MASK_ALL : WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&onPromisc);
  esp_wifi_set_promiscuous(true);
}

static void enterMode(int m) {
  if (m == sc_mode) return;
  // Cleanup
  if (sc_mode == MODE_SCAN || sc_mode == MODE_SHADY) {
    WiFi.scanDelete(); sc_scanRunning = false; sc_shadyRunning = false;
  } else if (sc_mode == MODE_BLE) {
    bleScanActive = false; delay(200);
  } else if (sc_mode == MODE_HASH) {
    esp_wifi_set_promiscuous(false);
    hashClosePcap();
  } else if (sc_mode == MODE_AP) {
    if (apUdpStarted) { apUdp.stop(); apUdpStarted = false; }
    WiFi.softAPdisconnect(true);
  } else if (sc_mode == MODE_PRESENCE) {
    esp_wifi_set_csi(false);
    esp_wifi_set_csi_rx_cb(NULL, NULL);
    if (presUdpStarted) { presUdp.stop(); presUdpStarted = false; }
    if (psKillerHandle) { vTaskDelete(psKillerHandle); psKillerHandle = NULL; }
    presState = PRES_CONNECTING;
  } else if (sc_mode >= 0) {
    esp_wifi_set_promiscuous(false);
  }
  sc_mode   = m;
  sc_redraw = true;
  WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
  switch (m) {
    case MODE_SCAN:
      sc_scanScroll=0; sc_scanLast=0; sc_scanRunning=false;
      break;
    case MODE_PROBE:
      probeHead=0; probeCount=0; sc_probeScroll=0; probeUpdated=false;
      enablePromisc(false);
      break;
    case MODE_CHANNEL:
      portENTER_CRITICAL(&chanMux); memset((void*)chanFrames,0,sizeof(uint32_t)*CHAN_COUNT); portEXIT_CRITICAL(&chanMux);
      sc_chanCurrent=1; sc_chanLocked=false; sc_chanLastHop=0; sc_chanLastDraw=0;
      esp_wifi_set_channel(1,WIFI_SECOND_CHAN_NONE);
      enablePromisc(true);
      break;
    case MODE_DEAUTH:
      portENTER_CRITICAL(&deauthMux); memset(deauthList,0,sizeof(deauthList)); deauthCount=0; deauthUpdated=false; deauthAlertFlash=false; portEXIT_CRITICAL(&deauthMux);
      enablePromisc(false);
      break;
    case MODE_BLE:
      portENTER_CRITICAL(&bleMux); memset(bleDevs,0,sizeof(bleDevs)); bleDevCount=0; portEXIT_CRITICAL(&bleMux);
      sc_bleScroll=0; bleUpdated=false; bleThreatFlash=false;
      if (!bleInitialized) { BLEDevice::init("CYDWiFiScanner"); bleInitialized=true; }
      bleScanActive = true;
      xTaskCreatePinnedToCore(bleScanTask,"BLEScan",4096,NULL,1,&bleScanTaskHandle,0);
      break;
    case MODE_SHADY:
      shadyNetCount=0; shadyTotalNets=0; sc_shadyScroll=0; sc_shadyLast=0; sc_shadyRunning=false;
      pineapCount=0;
      break;
    case MODE_HASH:
      portENTER_CRITICAL(&hashMux);
      hashAPCount=0; hashCaptureHead=0; hashCaptureCount=0;
      hashEapolTotal=0; hashDeauthCount=0;
      hashTmpPktCount=0; hashRssiSum=0; hashEapolSec=0; hashDeauthSec=0;
      hashPktHead=0; hashPktTail=0;
      hashUpdated=false;
      memset(hashPktsBuf,  0, sizeof(hashPktsBuf));
      memset(hashRssiBuf,  0, sizeof(hashRssiBuf));
      memset(hashEapolBuf, 0, sizeof(hashEapolBuf));
      memset(hashDeauthBuf,0, sizeof(hashDeauthBuf));
      hashHistHead=0; hashHistFull=false;
      hashOldChan=0;
      strcpy(hashLastSSID,"[none]");      hashLastSSIDMac[0]='\0';
      strcpy(hashLastEapolSSID,"[none]"); hashLastEapolMac[0]='\0';
      hashLastRSSI=0;
      portEXIT_CRITICAL(&hashMux);
      sc_hashChan=1; sc_hashLastHop=0; sc_hashLastDraw=0;
      esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
      enablePromisc(true);
      hashPcapOpen = hashOpenPcap();
      break;
    case MODE_AP:
      apPingCount=0; apLastPing=0; apLastDraw=0; apUdpStarted=false;
      WiFi.mode(WIFI_AP);
      esp_wifi_set_ps(WIFI_PS_NONE);
      WiFi.softAP(AP_SSID, AP_PASS);
      { wifi_config_t ap_cfg={};
        esp_wifi_get_config(WIFI_IF_AP, &ap_cfg);
        ap_cfg.ap.beacon_interval=40;
        esp_wifi_set_config(WIFI_IF_AP, &ap_cfg); }
      esp_wifi_set_inactive_time(WIFI_IF_AP, 300);
      esp_wifi_set_ps(WIFI_PS_NONE);
      apUdp.begin(AP_PORT); apUdpStarted=true;
      Serial.printf("[AP] SSID=%s  IP=%s\n", AP_SSID, WiFi.softAPIP().toString().c_str());
      sdLog("AP","soft-AP started SSID=" AP_SSID);
      break;
    case MODE_PRESENCE:
      portENTER_CRITICAL(&csiMux);
      csiWinHead=0; csiWinFull=false;
      memset((void*)csiWin,0,sizeof(csiWin));
      csiLastRSSI=0; csiUpdated=false; csiFrameSec=0;
      portEXIT_CRITICAL(&csiMux);
      csiVariance=0; csiPeakVar=0; csiConfidence=0; csiVarBaseline=0;
      csiCalibrated=false; csiCalPending=false; csiCalCountStart=0; csiFrameRate=0;
      memset(csiHistBuf,0,sizeof(csiHistBuf));
      csiHistHead=0; csiHistFull=false; csiLastSec=0;
      presState=PRES_CONNECTING; presConnStart=millis(); presLastDraw=0; presLastKeepalive=0;
      presUdpStarted=false;
      WiFi.begin(AP_SSID, AP_PASS);
      xTaskCreate(psKillerTask,"ps_killer",2048,NULL,6,&psKillerHandle);
      Serial.printf("[PRES] Connecting to %s...\n", AP_SSID);
      break;
  }
}

// ─── UI helpers ──────────────────────────────────────────────────────────────
static void drawHeader(const char* status, bool scanning=false) {
  gfx->fillRect(0,0,SCREEN_W,HEADER_H,COL_HDR_BG);
  gfx->setTextSize(1);
  gfx->setTextColor(COL_GREEN);
  gfx->setCursor(4,6);
  gfx->print("["); gfx->print(MODE_NAMES[sc_mode]); gfx->print("]");
  int labW = (strlen(MODE_NAMES[sc_mode])+2)*6;
  if (scanning) {
    gfx->setTextColor(COL_YELLOW);
    gfx->setCursor(labW+8,6); gfx->print("\xf8"); // degree symbol as spinner placeholder
  }
  if (status) {
    gfx->setTextColor(COL_DIM);
    gfx->setCursor(labW+18,6); gfx->print(status);
  }
}

static void drawFooter() {
  gfx->fillRect(0,FOOTER_Y,SCREEN_W,FOOTER_H,COL_FTR_BG);
  int zoneW = SCREEN_W / NUM_MODES;
  for (int i = 0; i < NUM_MODES; i++) {
    int x = i * zoneW;
    if (i>0) gfx->drawFastVLine(x,FOOTER_Y,FOOTER_H,COL_DIVIDER);
    uint16_t col = (i==sc_mode) ? COL_GREEN : COL_DIM;
    gfx->setTextColor(col); gfx->setTextSize(1);
    int tw = strlen(MODE_NAMES[i])*6;
    gfx->setCursor(x+(zoneW-tw)/2, FOOTER_Y+10); gfx->print(MODE_NAMES[i]);
    if (i==sc_mode) gfx->drawFastHLine(x+2,FOOTER_Y+2,zoneW-4,COL_GREEN);
  }
}

static void drawRSSIBar(int x, int y, int rssi) {
  int bars = (rssi>-50)?5:(rssi>-60)?4:(rssi>-70)?3:(rssi>-80)?2:1;
  uint16_t col = (bars>=4)?COL_GREEN:(bars>=3?COL_YELLOW:COL_RED);
  for (int i=0;i<5;i++) gfx->fillRect(x+i*5,y,4,8,(i<bars)?col:COL_DIM);
}

// ─── SCAN renderer ───────────────────────────────────────────────────────────
// Layout per row (18px tall, AntiPMatrix-style):
//   [14 char SSID] [*lock] [====bar====] [ dBm] [Ch]
//   Col:  0        90      102           214    249
static void renderScan() {
  gfx->fillRect(0,BODY_Y,SCREEN_W,BODY_H,COL_BG);

  if (sc_scanCount == 0) {
    drawHeader(sc_scanRunning ? "first scan..." : "no networks", sc_scanRunning);
    gfx->setTextColor(COL_DIM); gfx->setTextSize(1);
    gfx->setCursor(76,108);
    gfx->print(sc_scanRunning ? "Scanning WiFi..." : "No networks found");
    return;
  }

  // Column positions
  const int COL_SSID  =   4;   // SSID start
  const int COL_LOCK  =  90;   // lock * indicator
  const int COL_BAR   = 100;   // signal bar start
  const int BAR_W     = 110;   // signal bar width
  const int BAR_H     =   7;
  const int COL_DBM   = 216;   // dBm value
  const int COL_CH    = 252;   // channel
  const int COL_ENC   = 284;   // enc tag

  // Sub-header labels
  int hdrY = BODY_Y + 1;
  gfx->setTextSize(1);
  gfx->setTextColor(COL_DIM);
  gfx->setCursor(COL_SSID, hdrY); gfx->print("SSID");
  gfx->setCursor(COL_BAR,  hdrY); gfx->print("SIGNAL");
  gfx->setCursor(COL_DBM,  hdrY); gfx->print(" dBm");
  gfx->setCursor(COL_CH,   hdrY); gfx->print("CH");
  gfx->setCursor(COL_ENC,  hdrY); gfx->print("ENC");
  gfx->drawFastHLine(0, BODY_Y+11, SCREEN_W, COL_DIVIDER);

  char hdr[40];
  int hidden = 0; for(int i=0;i<sc_scanCount;i++) if(scanNets[i].hidden) hidden++;
  snprintf(hdr,sizeof(hdr),"%d nets (%d hidden)",sc_scanCount,hidden);
  drawHeader(hdr, sc_scanRunning);

  // Rows start below sub-header
  const int ROW_START = BODY_Y + 13;
  for (int i = 0; i < SCAN_VISIBLE; i++) {
    int idx = sc_scanScroll + i;
    if (idx >= sc_scanCount) break;
    const ScanNet& net = scanNets[idx];
    int y = ROW_START + i * SCAN_ROW_H;

    // Color: hidden = dim, weak signal = yellow, normal = green
    uint16_t textCol;
    bool isOpen = (net.enc == WIFI_AUTH_OPEN);
    if      (net.hidden)      textCol = COL_DIM;
    else if (net.rssi < -75)  textCol = COL_YELLOW;
    else                      textCol = COL_GREEN;

    // SSID (14 chars max)
    gfx->setTextColor(textCol); gfx->setTextSize(1);
    gfx->setCursor(COL_SSID, y+2);
    char name[15];
    if (net.hidden) strcpy(name, "[Hidden]");
    else { strncpy(name, net.ssid, 14); name[14] = '\0'; }
    gfx->printf("%-14s", name);

    // Lock indicator
    gfx->setTextColor(!isOpen ? COL_YELLOW : COL_DIM);
    gfx->setCursor(COL_LOCK, y+2);
    gfx->print(!isOpen ? "*" : " ");

    // Continuous signal bar — map RSSI -90..-30 → 0..BAR_W
    int fill = map(constrain(net.rssi,-90,-30), -90,-30, 0, BAR_W);
    uint16_t barCol;
    if      (net.rssi >= -60) barCol = gfx->color565(0,230,60);   // strong = green
    else if (net.rssi >= -75) barCol = gfx->color565(230,200,0);  // medium = yellow
    else                      barCol = gfx->color565(220,50,0);   // weak   = red
    gfx->fillRect(COL_BAR, y+3, BAR_W,   BAR_H, gfx->color565(28,28,28)); // bg
    if (fill > 0) gfx->fillRect(COL_BAR, y+3, fill, BAR_H, barCol);

    // dBm (right-aligned 4 chars)
    gfx->setTextColor(barCol);
    gfx->setCursor(COL_DBM, y+2);
    gfx->printf("%4d", net.rssi);

    // Channel
    gfx->setTextColor(COL_DIM);
    gfx->setCursor(COL_CH, y+2);
    gfx->printf("%-2d", net.channel);

    // Encryption tag (WPA2, WPA3, OPEN, etc.)
    gfx->setTextColor(!isOpen ? gfx->color565(100,100,200) : gfx->color565(200,80,0));
    gfx->setCursor(COL_ENC, y+2);
    gfx->print(encLabel(net.enc));

    gfx->drawFastHLine(0, y + SCAN_ROW_H - 1, SCREEN_W, COL_DIVIDER);
  }

  // Scroll arrows
  if (sc_scanScroll > 0) {
    gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10, ROW_START+2); gfx->print("^");
  }
  if (sc_scanScroll + SCAN_VISIBLE < sc_scanCount) {
    gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10, BODY_Y+BODY_H-10); gfx->print("v");
  }
}

// ─── PROBE renderer ──────────────────────────────────────────────────────────
static void renderProbe() {
  gfx->fillRect(0,BODY_Y,SCREEN_W,BODY_H,COL_BG);
  char hdr[32]; snprintf(hdr,sizeof(hdr),"captured: %d",probeCount);
  drawHeader(hdr,true);
  if (probeCount==0) { gfx->setTextColor(COL_DIM); gfx->setTextSize(1); gfx->setCursor(28,108); gfx->print("Listening for probe requests..."); return; }
  int total = (probeCount<PROBE_MAX)?probeCount:PROBE_MAX;
  gfx->setTextSize(1);
  for (int i=0;i<PROBE_VISIBLE;i++) {
    if (sc_probeScroll+i>=total) break;
    int idx=(probeHead-1-(sc_probeScroll+i)+PROBE_MAX*2)%PROBE_MAX;
    const ProbeEntry& e=probeList[idx]; int y=BODY_Y+i*PROBE_ROW_H;
    gfx->setTextColor(COL_DIM); gfx->setCursor(4,y+3); gfx->print(e.mac);
    bool wild=(e.ssid[0]=='\0');
    gfx->setTextColor(wild?COL_DIM:COL_GREEN); gfx->setCursor(4,y+14); gfx->print(wild?"<wildcard>":e.ssid);
    gfx->drawFastHLine(0,y+PROBE_ROW_H-1,SCREEN_W,COL_DIVIDER);
  }
  if (sc_probeScroll>0){ gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10,BODY_Y+4); gfx->print("^"); }
  if (sc_probeScroll+PROBE_VISIBLE<total){ gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10,BODY_Y+BODY_H-12); gfx->print("v"); }
}

// ─── CHANNEL renderer ────────────────────────────────────────────────────────
static void renderChannel() {
  gfx->fillRect(0,BODY_Y,SCREEN_W,BODY_H,COL_BG);
  char hdr[32];
  if (sc_chanLocked) snprintf(hdr,sizeof(hdr),"locked CH %d",sc_chanCurrent);
  else               snprintf(hdr,sizeof(hdr),"hopping 1-13");
  drawHeader(hdr,!sc_chanLocked);
  uint32_t snap[CHAN_COUNT];
  portENTER_CRITICAL(&chanMux); memcpy(snap,(void*)chanFrames,sizeof(uint32_t)*CHAN_COUNT); portEXIT_CRITICAL(&chanMux);
  uint32_t mx=1; for(int i=0;i<CHAN_COUNT;i++) if(snap[i]>mx) mx=snap[i];
  const int barAreaH=BODY_H-20; const int barW=(SCREEN_W-2)/CHAN_COUNT; const int labelY=BODY_Y+BODY_H-14;
  for (int i=0;i<CHAN_COUNT;i++) {
    int x=1+i*barW; int barH=(int)((float)snap[i]/mx*barAreaH); int barY=BODY_Y+barAreaH-barH;
    bool locked=(sc_chanLocked&&(i+1==sc_chanCurrent)); bool active=(!sc_chanLocked&&(i+1==sc_chanCurrent));
    uint16_t col=locked?COL_CYAN:(active?COL_YELLOW:COL_GREEN);
    gfx->drawRect(x,BODY_Y,barW-2,barAreaH,COL_DIVIDER);
    if (barH>0) gfx->fillRect(x,barY,barW-2,barH,col);
    char lbl[3]; snprintf(lbl,3,"%2d",i+1);
    gfx->setTextSize(1); gfx->setTextColor(locked?COL_CYAN:(active?COL_YELLOW:COL_DIM));
    gfx->setCursor(x,labelY); gfx->print(lbl);
  }
}

// ─── DEAUTH renderer ─────────────────────────────────────────────────────────
static void renderDeauth() {
  gfx->fillRect(0,BODY_Y,SCREEN_W,BODY_H,COL_BG);
  char hdr[40]; snprintf(hdr,sizeof(hdr),"%d detected  tap=clear",deauthCount);
  drawHeader(hdr,true);
  if (deauthCount==0) {
    gfx->setTextColor(COL_DIM); gfx->setTextSize(1);
    gfx->setCursor(24,100); gfx->print("Monitoring for deauth attacks...");
    gfx->setCursor(24,116); gfx->print("deauth/disassoc frames logged");
    return;
  }
  gfx->setTextSize(1);
  for (int i=0;i<deauthCount&&i<BODY_H/DEAUTH_ROW_H;i++) {
    const DeauthEntry& de=deauthList[i]; int y=BODY_Y+i*DEAUTH_ROW_H;
    uint16_t col=de.alert?COL_RED:COL_GREEN;
    gfx->setTextColor(col); gfx->setCursor(4,y+3); gfx->print(de.bssidStr);
    char info[44]; snprintf(info,sizeof(info),"cnt:%-4d  %.1f/s  %s",de.totalCount,de.rate,de.alert?"<<ATTACK>>":"");
    gfx->setTextColor(de.alert?COL_RED:COL_DIM); gfx->setCursor(4,y+14); gfx->print(info);
    gfx->drawFastHLine(0,y+DEAUTH_ROW_H-1,SCREEN_W,COL_DIVIDER);
  }
}

// ─── BLE renderer ────────────────────────────────────────────────────────────
static void renderBLE() {
  gfx->fillRect(0,BODY_Y,SCREEN_W,BODY_H,COL_BG);
  int susp=0; for(int i=0;i<bleDevCount;i++) if(bleDevs[i].suspicious) susp++;
  char hdr[40]; snprintf(hdr,sizeof(hdr),"dev:%d  sus:%d  tap=clear",bleDevCount,susp);
  drawHeader(hdr,true);
  if (bleDevCount==0) {
    gfx->setTextColor(COL_DIM); gfx->setTextSize(1);
    gfx->setCursor(20,100); gfx->print("Scanning for BLE devices...");
    gfx->setCursor(20,116); gfx->print("Flags skimmers & HC-0x modules");
    return;
  }
  gfx->setTextSize(1);
  for (int i=0;i<BLE_VISIBLE;i++) {
    if (sc_bleScroll+i>=bleDevCount) break;
    const BLEDevInfo& d=bleDevs[sc_bleScroll+i]; int y=BODY_Y+i*BLE_ROW_H;
    uint16_t col=d.suspicious?COL_RED:COL_GREEN;
    // Row 1: suspicious marker + name
    gfx->setTextColor(col); gfx->setCursor(4,y+3);
    gfx->print(d.suspicious?"[!] ":"    ");
    gfx->print(d.name[0]?d.name:"<unnamed>");
    // Row 2: MAC + RSSI
    gfx->setTextColor(COL_DIM); gfx->setCursor(4,y+13);
    char line[40]; snprintf(line,sizeof(line),"%s  %ddBm",d.mac,d.rssi);
    gfx->print(line);
    gfx->drawFastHLine(0,y+BLE_ROW_H-1,SCREEN_W,COL_DIVIDER);
  }
  if (sc_bleScroll>0){ gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10,BODY_Y+4); gfx->print("^"); }
  if (sc_bleScroll+BLE_VISIBLE<bleDevCount){ gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10,BODY_Y+BODY_H-12); gfx->print("v"); }
}

// ─── SHADY renderer ──────────────────────────────────────────────────────────
static void renderShady() {
  gfx->fillRect(0,BODY_Y,SCREEN_W,BODY_H,COL_BG);
  char hdr[48]; snprintf(hdr,sizeof(hdr),"total:%d  threats:%d",shadyTotalNets,shadyNetCount);
  drawHeader(hdr,sc_shadyRunning);
  if (shadyNetCount==0) {
    gfx->setTextColor(COL_DIM); gfx->setTextSize(1);
    gfx->setCursor(16,100); gfx->print(sc_shadyRunning?"Analyzing networks...":"No threats found");
    gfx->setCursor(16,116); gfx->print("Open/hidden/PineAP/spam detected");
    return;
  }
  gfx->setTextSize(1);
  for (int i=0;i<SHADY_VISIBLE;i++) {
    if (sc_shadyScroll+i>=shadyNetCount) break;
    const ShadyNet& n=shadyNets[sc_shadyScroll+i]; int y=BODY_Y+i*SHADY_ROW_H;
    gfx->setTextColor(COL_ORANGE); gfx->setCursor(4,y+3);
    gfx->print(n.ssid[0]?n.ssid:"<hidden>");
    // Right-align RSSI
    char rssiStr[10]; snprintf(rssiStr,sizeof(rssiStr),"%ddBm",n.rssi);
    gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-strlen(rssiStr)*6-4,y+3); gfx->print(rssiStr);
    // Row 2: reason + CH + ENC
    char meta[32]; snprintf(meta,sizeof(meta),"%-12s CH%02d %s",n.reason,n.channel,n.enc);
    gfx->setTextColor(COL_RED); gfx->setCursor(4,y+14); gfx->print(meta);
    gfx->drawFastHLine(0,y+SHADY_ROW_H-1,SCREEN_W,COL_DIVIDER);
  }
  if (sc_shadyScroll>0){ gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10,BODY_Y+4); gfx->print("^"); }
  if (sc_shadyScroll+SHADY_VISIBLE<shadyNetCount){ gfx->setTextColor(COL_DIM); gfx->setCursor(SCREEN_W-10,BODY_Y+BODY_H-12); gfx->print("v"); }
}

// ─── HASH renderer ───────────────────────────────────────────────────────────
// Faithfully ports Hash Monster display layout (minus the monster sprite):
//
//  y=20-115  [units|  packets/sec bar chart (green), 95px tall        ]
//  y=117-197 [         RSSI(yellow)/EAPOL(green)/deauth(red) dot graph  |units2]
//  y=198-212 [footer: last SSID + rssi + mac  |  last EAPOL SSID + mac  ]
//
// Layout constants (mirrored from Hash Monster geometry, adapted to CYD body):
#define H_UNITS1_W   36   // left units strip for bar chart
#define H_BAR_X      36   // bar chart start x
#define H_BAR_W     284   // bar chart width  (H_BAR_X .. 319)
#define H_BAR_Y      20   // bar chart top y  (= BODY_Y)
#define H_BAR_H      95   // bar chart height
#define H_DOT_Y     117   // dot chart top y
#define H_DOT_H      80   // dot chart height
#define H_UNITS2_W   40   // right units strip for dot chart
#define H_DOT_W     280   // dot chart width  (0 .. H_DOT_W-1)
#define H_FOOT_Y    198   // status footer y  (within body)
#define H_FOOT_H     14   // status footer height

static void renderHash() {
  gfx->fillRect(0, BODY_Y, SCREEN_W, BODY_H, COL_BG);

  // ── Header ──────────────────────────────────────────────────────────────────
  char hdr[56];
  snprintf(hdr, sizeof(hdr), "CH:%02d AP:%d Pk:%lu E/D:%d/%d SD:%s",
           sc_hashChan, hashAPCount, (unsigned long)hashPktsBuf[(hashHistHead+HASH_HIST_W-1)%HASH_HIST_W],
           hashEapolTotal, hashDeauthCount, hashPcapOpen ? "On" : "Off");
  drawHeader(hdr);

  // ── Bar chart: packets/sec (graph1 equivalent) ───────────────────────────────
  // Find max value over the history window for scaling
  uint32_t maxPkt = 1;
  int histLen = hashHistFull ? HASH_HIST_W : hashHistHead;
  for (int i = 0; i < histLen; i++) { if (hashPktsBuf[i] > maxPkt) maxPkt = hashPktsBuf[i]; }

  // Round max up to nearest 10 for cleaner scale
  uint32_t scaledMax = ((maxPkt / 10) + 1) * 10;
  float mult = (float)H_BAR_H / (float)scaledMax;

  // Units strip (scale labels, right-aligned in 36px column)
  gfx->setTextSize(1); gfx->setTextColor(COL_DIM);
  for (int s = 0; s <= 4; s++) {
    int val = (scaledMax * s) / 4;
    int y   = H_BAR_Y + H_BAR_H - (int)(val * mult) - 6;
    char buf[8]; snprintf(buf, sizeof(buf), "%4d", val);
    gfx->setCursor(0, y); gfx->print(buf);
  }

  // Draw bars oldest→newest left→right
  for (int col = 0; col < H_BAR_W; col++) {
    int histIdx;
    if (hashHistFull) {
      histIdx = (hashHistHead + col - H_BAR_W + HASH_HIST_W) % HASH_HIST_W;
    } else {
      int offset = col - (H_BAR_W - hashHistHead);
      if (offset < 0) { continue; } // no data yet for this column
      histIdx = offset;
    }
    int barH = (int)(hashPktsBuf[histIdx] * mult);
    barH = constrain(barH, 0, H_BAR_H);
    int bx = H_BAR_X + col;
    // Erase column
    gfx->drawFastVLine(bx, H_BAR_Y, H_BAR_H, COL_BG);
    // Draw bar (green)
    if (barH > 0) gfx->drawFastVLine(bx, H_BAR_Y + H_BAR_H - barH, barH, COL_GREEN);
  }
  gfx->drawFastHLine(0, H_BAR_Y + H_BAR_H, SCREEN_W, COL_DIVIDER);

  // ── Dot chart: RSSI / EAPOL / deauth (graph2 equivalent) ────────────────────
  gfx->fillRect(0, H_DOT_Y, H_DOT_W, H_DOT_H, COL_BG);

  for (int col = 0; col < H_DOT_W; col++) {
    int histIdx;
    if (hashHistFull) {
      histIdx = (hashHistHead + col - H_DOT_W + HASH_HIST_W) % HASH_HIST_W;
    } else {
      int offset = col - (H_DOT_W - hashHistHead);
      if (offset < 0) { continue; }
      histIdx = offset;
    }
    int cx = col;

    // Vertical grid every 10 pixels (navy/dim)
    if ((H_DOT_W - 1 - col) % 10 == 0) {
      gfx->drawFastVLine(cx, H_DOT_Y, H_DOT_H, 0x000F); // dim navy
    }

    // RSSI dot (yellow): map -100..-30 → top..bottom of H_DOT_H
    int8_t rssi = hashRssiBuf[histIdx];
    if (rssi < 0) {
      int ry = constrain((-rssi - 30) * H_DOT_H / 70, 0, H_DOT_H - 2);
      gfx->drawPixel(cx, H_DOT_Y + ry, COL_YELLOW);
      gfx->drawPixel(cx, H_DOT_Y + ry + 1, COL_YELLOW);
    }

    // EAPOL dot (green): from bottom
    uint8_t ep = hashEapolBuf[histIdx];
    if (ep > 0) {
      int ey = constrain((int)ep, 1, H_DOT_H);
      gfx->drawPixel(cx, H_DOT_Y + H_DOT_H - ey,     COL_GREEN);
      gfx->drawPixel(cx, H_DOT_Y + H_DOT_H - ey + 1, COL_GREEN);
    }

    // Deauth dot (red): from bottom
    uint8_t da = hashDeauthBuf[histIdx];
    if (da > 0) {
      int dy = constrain((int)da, 1, H_DOT_H);
      gfx->drawPixel(cx, H_DOT_Y + H_DOT_H - dy,     COL_RED);
      gfx->drawPixel(cx, H_DOT_Y + H_DOT_H - dy + 1, COL_RED);
    }
  }

  // Units2 strip (right side of dot chart)
  gfx->fillRect(H_DOT_W, H_DOT_Y, H_UNITS2_W, H_DOT_H, COL_BG);
  gfx->setTextSize(1);
  // RSSI
  gfx->setTextColor(COL_YELLOW);
  gfx->setCursor(H_DOT_W + 1, H_DOT_Y + 2);
  gfx->printf("%4d", (int)hashLastRSSI);
  // Total EAPOL
  gfx->setTextColor(COL_GREEN);
  gfx->setCursor(H_DOT_W + 1, H_DOT_Y + 18);
  gfx->printf("%4d", hashEapolTotal);
  // Total deauth
  gfx->setTextColor(COL_RED);
  gfx->setCursor(H_DOT_W + 1, H_DOT_Y + 34);
  gfx->printf("%4d", hashDeauthCount);
  // AP count
  gfx->setTextColor(COL_WHITE);
  gfx->setCursor(H_DOT_W + 1, H_DOT_Y + 50);
  gfx->printf("%4d", hashAPCount);

  // ── Status footer (last SSID + last EAPOL) ───────────────────────────────────
  gfx->fillRect(0, H_FOOT_Y, SCREEN_W, H_FOOT_H, 0x00C0);
  gfx->setTextSize(1);
  // Last beacon: SSID rssi mac
  char foot1[48];
  snprintf(foot1, sizeof(foot1), "%-14.14s %4d %s", hashLastSSID, (int)hashLastRSSI, hashLastSSIDMac);
  gfx->setTextColor(COL_DIM); gfx->setCursor(2, H_FOOT_Y + 3); gfx->print(foot1);
  // Last EAPOL: SSID mac  (on same line, right half)
  char foot2[40];
  snprintf(foot2, sizeof(foot2), " %-12.12s %s", hashLastEapolSSID, hashLastEapolMac);
  gfx->setTextColor(COL_GREEN); gfx->setCursor(162, H_FOOT_Y + 3); gfx->print(foot2);

  gfx->drawFastHLine(0, H_FOOT_Y + H_FOOT_H, SCREEN_W, COL_DIVIDER);
}

// ─── AP renderer ─────────────────────────────────────────────────────────────
static void renderAP() {
  gfx->fillRect(0, BODY_Y, SCREEN_W, BODY_H, COL_BG);
  int clients = WiFi.softAPgetStationNum();
  char hdr[52];
  snprintf(hdr, sizeof(hdr), "%s  %s  clients:%d",
           AP_SSID, WiFi.softAPIP().toString().c_str(), clients);
  drawHeader(hdr);

  gfx->setTextSize(2); gfx->setTextColor(COL_GREEN);
  gfx->setCursor(52, BODY_Y + 10); gfx->print("AP  ACTIVE");

  gfx->drawFastHLine(0, BODY_Y + 34, SCREEN_W, COL_DIVIDER);
  gfx->setTextSize(1);
  gfx->setTextColor(COL_DIM);  gfx->setCursor(4, BODY_Y + 42); gfx->print("SSID:");
  gfx->setTextColor(COL_GREEN); gfx->print(" " AP_SSID);
  gfx->setTextColor(COL_DIM);  gfx->setCursor(4, BODY_Y + 56); gfx->print("PASS:");
  gfx->setTextColor(COL_WHITE); gfx->print(" " AP_PASS);
  gfx->setTextColor(COL_DIM);  gfx->setCursor(4, BODY_Y + 70); gfx->print("IP:  ");
  gfx->setTextColor(COL_CYAN);  gfx->print(" "); gfx->print(WiFi.softAPIP().toString().c_str());

  gfx->drawFastHLine(0, BODY_Y + 84, SCREEN_W, COL_DIVIDER);
  char buf[48];
  gfx->setTextColor(COL_WHITE); gfx->setTextSize(1);
  snprintf(buf, sizeof(buf), "Clients: %d", clients);
  gfx->setCursor(4, BODY_Y + 92); gfx->print(buf);
  snprintf(buf, sizeof(buf), "Pings:   %lu  (50/sec)", apPingCount);
  gfx->setCursor(4, BODY_Y + 106); gfx->print(buf);
  gfx->setTextColor(COL_DIM);
  gfx->setCursor(4, BODY_Y + 120); gfx->print("Beacon:  40ms interval");

  gfx->drawFastHLine(0, BODY_Y + 134, SCREEN_W, COL_DIVIDER);
  gfx->setTextColor(COL_DIM); gfx->setTextSize(1);
  gfx->setCursor(4, BODY_Y + 142); gfx->print("Board 1: keep this CYD in AP mode.");
  gfx->setCursor(4, BODY_Y + 156); gfx->print("Board 2: connect to this AP,");
  gfx->setCursor(4, BODY_Y + 170); gfx->print("         then tap [PRES] below.");
}

// ─── PRESENCE renderer ───────────────────────────────────────────────────────
static void renderPresence() {
  gfx->fillRect(0, BODY_Y, SCREEN_W, BODY_H, COL_BG);

  // Header
  char hdr[56];
  if (presState == PRES_CONNECTING) {
    unsigned long elapsed = (millis() - presConnStart) / 1000;
    snprintf(hdr, sizeof(hdr), "connecting... %lus", elapsed);
  } else {
    snprintf(hdr, sizeof(hdr), "linked %ddBm  var:%.1f  %s",
             (int)csiLastRSSI, csiVariance, csiCalibrated ? "[CAL]" : "");
  }
  drawHeader(hdr, presState == PRES_CONNECTING);

  if (presState == PRES_CONNECTING) {
    gfx->setTextColor(COL_DIM); gfx->setTextSize(1);
    gfx->setCursor(16, BODY_Y + 60); gfx->print("Connecting to: " AP_SSID);
    gfx->setCursor(16, BODY_Y + 76); gfx->print("Make sure Board 1 is in [AP] mode.");
    gfx->setCursor(16, BODY_Y + 92); gfx->print("Retries every 15s automatically.");
    return;
  }

  // Big PRESENT / MAYBE / CLEAR status
  bool present = (csiConfidence >= 60);
  bool maybe   = (csiConfidence >= 30 && csiConfidence < 60);
  uint16_t statusCol = present ? COL_RED : (maybe ? COL_YELLOW : COL_GREEN);
  const char* statusStr = present ? ">> PRESENT" : (maybe ? "??  MAYBE " : "--  CLEAR ");
  gfx->setTextSize(2); gfx->setTextColor(statusCol);
  int sw = strlen(statusStr) * 12;
  gfx->setCursor((SCREEN_W - sw) / 2, P_STATUS_Y);
  gfx->print(statusStr);

  // Confidence bar
  gfx->setTextSize(1); gfx->setTextColor(COL_DIM);
  gfx->setCursor(4, P_CONF_Y + 2); gfx->print("CONF");
  int barFill = (P_CONF_W * csiConfidence) / 100;
  gfx->fillRect(40, P_CONF_Y, barFill, P_CONF_H, statusCol);
  gfx->fillRect(40 + barFill, P_CONF_Y, P_CONF_W - barFill, P_CONF_H, COL_DIM);
  char pct[8]; snprintf(pct, sizeof(pct), " %3d%%", csiConfidence);
  gfx->setTextColor(COL_WHITE); gfx->setCursor(40 + P_CONF_W + 4, P_CONF_Y + 3);
  gfx->print(pct);

  gfx->drawFastHLine(0, P_CONF_Y + P_CONF_H + 4, SCREEN_W, COL_DIVIDER);

  // CSI variance sparkline
  float lo = csiCalibrated ? csiVarBaseline + CSI_VAR_LO : CSI_VAR_LO;
  float hi = csiCalibrated ? csiVarBaseline + CSI_VAR_HI : CSI_VAR_HI;
  float maxVar = hi * 1.5f;  // always show at least 1.5× HI so threshold lines are visible
  int histLen = csiHistFull ? CSI_HIST_W : csiHistHead;
  for (int i = 0; i < histLen; i++) { if (csiHistBuf[i] > maxVar) maxVar = csiHistBuf[i]; }
  float scaledMax = ((int)(maxVar / 5.0f) + 1) * 5.0f;
  if (scaledMax < hi * 1.5f) scaledMax = hi * 1.5f;  // never shrink below threshold range
  float mult = (float)P_SPARK_H / scaledMax;

  // Scale labels
  gfx->setTextSize(1); gfx->setTextColor(COL_DIM);
  for (int s = 0; s <= 2; s++) {
    float val = (scaledMax * s) / 2.0f;
    int y = P_SPARK_Y + P_SPARK_H - (int)(val * mult) - 6;
    char lbl[8]; snprintf(lbl, sizeof(lbl), "%4.0f", val);
    gfx->setCursor(0, y); gfx->print(lbl);
  }

  // Draw bars oldest→newest left→right
  for (int col = 0; col < P_SPARK_W; col++) {
    int histIdx;
    if (csiHistFull) {
      histIdx = (csiHistHead + col - P_SPARK_W + CSI_HIST_W) % CSI_HIST_W;
    } else {
      int offset = col - (P_SPARK_W - csiHistHead);
      if (offset < 0) continue;
      histIdx = offset;
    }
    float v = csiHistBuf[histIdx];
    int barH = constrain((int)(v * mult), 0, P_SPARK_H);
    int bx = P_SPARK_X + col;
    gfx->drawFastVLine(bx, P_SPARK_Y, P_SPARK_H, COL_BG);
    if (barH > 0) {
      uint16_t barCol = (v > scaledMax * 0.6f) ? COL_RED
                      : (v > scaledMax * 0.3f)  ? COL_YELLOW : COL_GREEN;
      gfx->drawFastVLine(bx, P_SPARK_Y + P_SPARK_H - barH, barH, barCol);
    }
  }

  // Threshold lines on sparkline
  int loY = P_SPARK_Y + P_SPARK_H - constrain((int)(lo * mult), 0, P_SPARK_H);
  int hiY = P_SPARK_Y + P_SPARK_H - constrain((int)(hi * mult), 0, P_SPARK_H);
  gfx->drawFastHLine(P_SPARK_X, loY, P_SPARK_W, COL_YELLOW);
  gfx->drawFastHLine(P_SPARK_X, hiY, P_SPARK_W, COL_RED);

  gfx->drawFastHLine(P_SPARK_X, P_SPARK_Y + P_SPARK_H, P_SPARK_W, COL_DIVIDER);

  // Stats strip — two rows of debug data
  gfx->setTextSize(1); gfx->setTextColor(COL_DIM);
  char stats[64];
  // Row 1: live signal data + peak tracker
  snprintf(stats, sizeof(stats), "VAR:%-5.1f PK:%-5.1f FR:%d/s RSSI:%d",
           csiVariance, csiPeakVar, csiFrameRate, (int)csiLastRSSI);
  gfx->setCursor(4, P_STATS_Y); gfx->print(stats);
  // Row 2: threshold info / countdown / calibration status
  if (csiCalPending) {
    int secsLeft = (int)((CSI_CAL_DELAY_MS - (millis() - csiCalCountStart)) / 1000) + 1;
    secsLeft = constrain(secsLeft, 0, 6);
    gfx->setTextColor(COL_YELLOW);
    snprintf(stats, sizeof(stats), "LEAVE ROOM — calibrating in %ds...", secsLeft);
    gfx->setCursor(4, P_STATS_Y + 14); gfx->print(stats);
  } else if (csiCalibrated) {
    gfx->setTextColor(COL_GREEN);
    snprintf(stats, sizeof(stats), "CAL base:%.1f lo:%.1f hi:%.1f  tap=reset",
             csiVarBaseline, lo, hi);
    gfx->setCursor(4, P_STATS_Y + 14); gfx->print(stats);
  } else {
    snprintf(stats, sizeof(stats), "UNCAL lo:%.1f hi:%.1f  tap=calibrate",
             lo, hi);
    gfx->setCursor(4, P_STATS_Y + 14); gfx->print(stats);
  }
}
static void redrawAll() {
  switch (sc_mode) {
    case MODE_SCAN:    renderScan();    break;
    case MODE_PROBE:   renderProbe();   break;
    case MODE_CHANNEL: renderChannel(); break;
    case MODE_DEAUTH:  renderDeauth();  break;
    case MODE_BLE:     renderBLE();     break;
    case MODE_SHADY:   renderShady();   break;
    case MODE_HASH:    renderHash();    break;
    case MODE_AP:      renderAP();      break;
    case MODE_PRESENCE:renderPresence();break;
  }
  drawFooter();
  sc_redraw = false;
}

// ─── Touch handler ───────────────────────────────────────────────────────────
static void handleTouch() {
  if (!ts.touched()) return;
  unsigned long now = millis();
  if (now-lastTouchTime < TOUCH_DEBOUNCE) return;
  lastTouchTime = now;
  TS_Point p = ts.getPoint();
  int tx = constrain(map(p.x,200,3900,0,SCREEN_W),0,SCREEN_W-1);
  int ty = constrain(map(p.y,240,3900,0,SCREEN_H),0,SCREEN_H-1);
  ledFlash(false,true,false,60);   // green flash on touch

  if (ty >= FOOTER_Y) {
    int zone = constrain(tx/(SCREEN_W/NUM_MODES),0,NUM_MODES-1);
    enterMode(zone); return;
  }
  if (ty >= BODY_Y) {
    bool upper = (ty < BODY_Y+BODY_H/2);
    switch (sc_mode) {
      case MODE_SCAN:
        if (upper){ if(sc_scanScroll>0){sc_scanScroll--;sc_redraw=true;} }
        else      { if(sc_scanScroll+SCAN_VISIBLE<sc_scanCount){sc_scanScroll++;sc_redraw=true;} }
        break;
      case MODE_PROBE:
        { int tot=(probeCount<PROBE_MAX)?probeCount:PROBE_MAX;
          if(upper){ if(sc_probeScroll>0){sc_probeScroll--;sc_redraw=true;} }
          else     { if(sc_probeScroll+PROBE_VISIBLE<tot){sc_probeScroll++;sc_redraw=true;} } }
        break;
      case MODE_CHANNEL:
        { int barW=(SCREEN_W-2)/CHAN_COUNT; int ch=constrain((tx-1)/barW+1,1,13);
          if(sc_chanLocked&&sc_chanCurrent==ch) sc_chanLocked=false;
          else { sc_chanCurrent=ch; sc_chanLocked=true; esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE); }
          sc_redraw=true; }
        break;
      case MODE_DEAUTH:
        portENTER_CRITICAL(&deauthMux); memset(deauthList,0,sizeof(deauthList)); deauthCount=0; deauthAlertFlash=false; portEXIT_CRITICAL(&deauthMux);
        sc_redraw=true;
        break;
      case MODE_BLE:
        if(upper){ if(sc_bleScroll>0){sc_bleScroll--;sc_redraw=true;} }
        else     { if(sc_bleScroll+BLE_VISIBLE<bleDevCount){sc_bleScroll++;sc_redraw=true;} }
        break;
      case MODE_SHADY:
        if(upper){ if(sc_shadyScroll>0){sc_shadyScroll--;sc_redraw=true;} }
        else     { if(sc_shadyScroll+SHADY_VISIBLE<shadyNetCount){sc_shadyScroll++;sc_redraw=true;} }
        break;
      case MODE_HASH:
        // Tap body to reset EAPOL capture log
        portENTER_CRITICAL(&hashMux);
        hashCaptureHead=0; hashCaptureCount=0;
        hashEapolTotal=0; hashDeauthCount=0;
        portEXIT_CRITICAL(&hashMux);
        sc_redraw=true;
        break;
      case MODE_AP:
        break; // no tap action in AP mode
      case MODE_PRESENCE:
        if (csiCalibrated) {
          // Second tap resets bad calibration back to uncalibrated state
          csiCalibrated    = false;
          csiVarBaseline   = 0.0f;
          csiCalPending    = false;
          sc_redraw        = true;
          Serial.println("[PRES] Calibration reset");
        } else if (!csiCalPending) {
          // First tap: start 6-second countdown — user leaves signal path
          csiCalPending      = true;
          csiCalCountStart   = millis();
          sc_redraw          = true;
          Serial.println("[PRES] Calibration countdown started — leave the room!");
        }
        break;
    }
  }
}

// ─── SHADY scan logic ────────────────────────────────────────────────────────
static void runShadyScan() {
  int n = WiFi.scanComplete();
  if (n < 0) return;   // still running or not started
  // n == WIFI_SCAN_FAILED or >= 0
  sc_shadyRunning = false;
  sc_shadyLast    = millis();
  shadyTotalNets  = (n > 0) ? n : 0;
  shadyNetCount   = 0;
  if (n > 0) {
    for (int i=0; i<n && shadyNetCount<SHADY_MAX; i++) {
      String bssidStr = WiFi.BSSIDstr(i);
      String ssidStr  = WiFi.SSID(i);
      int rssi        = WiFi.RSSI(i);
      int ch          = WiFi.channel(i);
      wifi_auth_mode_t enc = WiFi.encryptionType(i);
      char bssid[18]; strncpy(bssid,bssidStr.c_str(),17); bssid[17]='\0';
      char ssid[27];  strncpy(ssid,ssidStr.c_str(),26);   ssid[26]='\0';
      bool pine = checkPineAP(bssid, ssid);
      const char* reason = pine ? "PINEAP" : shadySuspicionReason(ssid,rssi,enc);
      if (reason) {
        ShadyNet& sn = shadyNets[shadyNetCount++];
        strncpy(sn.ssid,ssid,26); sn.ssid[26]='\0';
        strncpy(sn.bssid,bssid,17); sn.bssid[17]='\0';
        sn.rssi=rssi; sn.channel=ch;
        strncpy(sn.enc, encLabel(enc), 4); sn.enc[4]='\0';
        strncpy(sn.reason,reason,15); sn.reason[15]='\0';
        char logMsg[80]; snprintf(logMsg,sizeof(logMsg),"SSID:\"%s\" BSSID:%s CH:%d RSSI:%d ENC:%s REASON:%s",ssid,bssid,ch,rssi,encLabel(enc),reason);
        Serial.printf("[SHADY] %s\n",logMsg);
        sdLog("SHADY",logMsg);
      }
    }
    WiFi.scanDelete();
  }
  sc_redraw = true;
}

// ─── Setup ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  Serial.println("\n[CYDWiFiScanner] booting...");

  // RGB LED
  pinMode(LED_R,OUTPUT); pinMode(LED_G,OUTPUT); pinMode(LED_B,OUTPUT); ledOff();

  // Display + backlight
  pinMode(GFX_BL,OUTPUT); digitalWrite(GFX_BL,HIGH);
  gfx->begin(); gfx->invertDisplay(true); gfx->fillScreen(COL_BG);

  // Touch
  touchSPI.begin(XPT2046_CLK,XPT2046_MISO,XPT2046_MOSI,XPT2046_CS);
  ts.begin(touchSPI); ts.setRotation(1);

  // SD card (optional)
  sdSPI.begin(SD_SCK,SD_MISO,SD_MOSI,SD_CS);
  if (SD.begin(SD_CS,sdSPI)) {
    sdOK = true;
    File f = SD.open("/cydscan.txt",FILE_APPEND);
    if (f) { f.println("# CYDWiFiScanner session start"); f.close(); }
    Serial.println("[SD] Card OK → /cydscan.txt");
  } else {
    Serial.println("[SD] No card — logging to serial only");
  }

  WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(100);

  // Boot splash
  gfx->setTextColor(COL_GREEN); gfx->setTextSize(2);
  gfx->setCursor(28,60);  gfx->print("CYD WiFi Scanner");
  gfx->setTextSize(1); gfx->setTextColor(COL_DIM);
  gfx->setCursor(48,88);  gfx->print("Advanced 802.11 + BLE Scanner");
  gfx->setTextColor(COL_GREEN);
  gfx->setCursor(4,108);  gfx->print("[SCAN|PROBE|CHAN|DAUTH|BLE|SHADY|HASH|AP|PRES]");
  gfx->setTextColor(COL_DIM);
  gfx->setCursor(64,128); gfx->print("Serial @ 115200 baud");
  gfx->setCursor(64,140); gfx->print(sdOK ? "SD card: OK" : "SD card: none");
  ledFlash(true,false,false,100); ledFlash(false,true,false,100); ledFlash(false,false,true,100);
  delay(1400);

  enterMode(MODE_SCAN);
  Serial.println("[CYDWiFiScanner] ready.");
}

// ─── Loop ────────────────────────────────────────────────────────────────────
void loop() {
  handleTouch();
  unsigned long now = millis();

  switch (sc_mode) {

    // ── SCAN ─────────────────────────────────────────────────────────────────
    case MODE_SCAN:
      if (!sc_scanRunning) {
        // Time to start a new async scan?
        if (now - sc_scanLast >= SCAN_INTERVAL || sc_scanLast == 0) {
          sc_scanRunning = true;
          sc_redraw = true;  // spinner in header; old results stay visible in body
          WiFi.scanNetworks(true /*async*/, false /*no hidden*/);
          sc_scanLast = now;
        }
      } else {
        int r = WiFi.scanComplete();
        if (r >= 0) {
          // Scan done — process results into scanNets[]
          processScanResults(r);
          sc_scanRunning = false;
          sc_redraw = true;
          Serial.printf("[SCAN] %d networks found\n", sc_scanCount);
          for (int i = 0; i < sc_scanCount; i++) {
            const ScanNet& net = scanNets[i];
            char line[80];
            snprintf(line, sizeof(line), "SSID:\"%-26s\" CH:%02d RSSI:%-4d %s %s",
              net.hidden ? "<hidden>" : net.ssid, net.channel, net.rssi,
              encLabel(net.enc), net.bssid);
            Serial.printf("  %s\n", line);
            sdLog("SCAN", line);
          }
        } else if (r == WIFI_SCAN_FAILED) {
          sc_scanRunning = false;
          sc_scanLast = now;  // back off before retry
          sc_redraw = true;
        }
      }
      break;

    // ── PROBE ─────────────────────────────────────────────────────────────────
    case MODE_PROBE:
      if (probeUpdated) {
        probeUpdated=false;
        portENTER_CRITICAL(&probeMux);
        int li=(probeHead-1+PROBE_MAX)%PROBE_MAX;
        bool wild=(probeList[li].ssid[0]=='\0');
        char mac[18]; strncpy(mac,probeList[li].mac,17); mac[17]='\0';
        char ssid[33]; strncpy(ssid,probeList[li].ssid,32); ssid[32]='\0';
        portEXIT_CRITICAL(&probeMux);
        char line[60]; snprintf(line,sizeof(line),"MAC:%s SSID:\"%s\"",mac,wild?"<wildcard>":ssid);
        Serial.printf("[PROBE] %s\n",line); sdLog("PROBE",line);
        sc_redraw=true;
      }
      break;

    // ── CHANNEL ───────────────────────────────────────────────────────────────
    case MODE_CHANNEL:
      if (!sc_chanLocked && now-sc_chanLastHop>=CHAN_HOP_MS) {
        sc_chanCurrent=(sc_chanCurrent%CHAN_COUNT)+1;
        esp_wifi_set_channel(sc_chanCurrent,WIFI_SECOND_CHAN_NONE);
        sc_chanLastHop=now;
      }
      if (now-sc_chanLastDraw>=500) {
        sc_chanLastDraw=now; sc_redraw=true;
        uint32_t snap[CHAN_COUNT];
        portENTER_CRITICAL(&chanMux); memcpy(snap,(void*)chanFrames,sizeof(uint32_t)*CHAN_COUNT); portEXIT_CRITICAL(&chanMux);
        Serial.print("[CHAN] ");
        for (int i=0;i<CHAN_COUNT;i++) Serial.printf("CH%02d:%lu ",i+1,(unsigned long)snap[i]);
        Serial.println();
      }
      break;

    // ── DEAUTH ────────────────────────────────────────────────────────────────
    case MODE_DEAUTH:
      if (deauthAlertFlash) {
        deauthAlertFlash=false;
        ledFlash(true,false,false,300);
        gfx->fillRect(0,0,SCREEN_W,HEADER_H,COL_RED);
        gfx->setTextColor(COL_WHITE); gfx->setTextSize(1); gfx->setCursor(60,6);
        gfx->print("!!! DEAUTH ATTACK DETECTED !!!");
        Serial.println("[DEAUTH] *** ATTACK ALERT ***"); sdLog("DEAUTH","ATTACK DETECTED");
        delay(300); sc_redraw=true;
      }
      if (deauthUpdated) {
        deauthUpdated=false;
        for (int i=0;i<deauthCount;i++) {
          const DeauthEntry& de=deauthList[i];
          char line[60]; snprintf(line,sizeof(line),"BSSID:%s cnt:%d rate:%.1f/s%s",de.bssidStr,de.totalCount,de.rate,de.alert?"  ALERT":"");
          Serial.printf("[DEAUTH] %s\n",line); if(de.alert) sdLog("DEAUTH",line);
        }
        sc_redraw=true;
      }
      break;

    // ── BLE ───────────────────────────────────────────────────────────────────
    case MODE_BLE:
      if (bleThreatFlash) {
        bleThreatFlash=false;
        ledFlash(false,false,true,300);
        gfx->fillRect(0,0,SCREEN_W,HEADER_H,0x001F);
        gfx->setTextColor(COL_WHITE); gfx->setTextSize(1); gfx->setCursor(80,6);
        gfx->print("! SUSPICIOUS BLE DEVICE !");
        delay(300); sc_redraw=true;
      }
      if (bleUpdated) {
        bleUpdated=false;
        portENTER_CRITICAL(&bleMux);
        int li=bleDevCount-1;
        char mac[18]; strncpy(mac,bleDevs[li].mac,17); mac[17]='\0';
        char name[24]; strncpy(name,bleDevs[li].name,23); name[23]='\0';
        int rssi=bleDevs[li].rssi; bool sus=bleDevs[li].suspicious;
        portEXIT_CRITICAL(&bleMux);
        char line[64]; snprintf(line,sizeof(line),"MAC:%s NAME:\"%s\" RSSI:%d %s",mac,name[0]?name:"<unnamed>",rssi,sus?"[SUSPICIOUS]":"");
        Serial.printf("[BLE] %s\n",line); if(sus){ sdLog("BLE",line); }
        sc_redraw=true;
      }
      break;

    // ── SHADY ─────────────────────────────────────────────────────────────────
    case MODE_SHADY:
      if (!sc_shadyRunning) {
        if (now-sc_shadyLast >= SHADY_INTERVAL || sc_shadyLast==0) {
          sc_shadyRunning=true; WiFi.scanNetworks(true,true); sc_shadyLast=now;
          sc_redraw=true;
        }
      } else {
        runShadyScan();
        if (shadyNetCount>0) ledFlash(true,true,false,100); // yellow = shady network
      }
      break;

    // ── HASH ──────────────────────────────────────────────────────────────────
    case MODE_HASH:
      // Channel hop every HASH_HOP_MS
      if (now - sc_hashLastHop >= HASH_HOP_MS) {
        sc_hashChan = (sc_hashChan % 13) + 1;
        esp_wifi_set_channel(sc_hashChan, WIFI_SECOND_CHAN_NONE);
        sc_hashLastHop = now;
      }
      // Drain EAPOL packet queue to SD
      hashFlushQueue();
      // Every second: commit per-second stats into history ring buffers
      if (now - sc_hashLastDraw >= 1000) {
        sc_hashLastDraw = now;
        // Snapshot volatile counters atomically
        portENTER_CRITICAL(&hashMux);
        uint32_t pktSnap    = hashTmpPktCount; hashTmpPktCount = 0;
        int32_t  rssiSnap   = hashRssiSum;     hashRssiSum     = 0;
        uint32_t eapolSnap  = hashEapolSec;    hashEapolSec    = 0;
        uint32_t deauthSnap = hashDeauthSec;   hashDeauthSec   = 0;
        portEXIT_CRITICAL(&hashMux);

        int8_t rssiAvg = (pktSnap > 0) ? (int8_t)(rssiSnap / (int32_t)pktSnap) : 0;

        hashPktsBuf[hashHistHead]   = pktSnap;
        hashRssiBuf[hashHistHead]   = rssiAvg;
        hashEapolBuf[hashHistHead]  = (uint8_t)min((uint32_t)255, eapolSnap);
        hashDeauthBuf[hashHistHead] = (uint8_t)min((uint32_t)255, deauthSnap);
        hashHistHead = (hashHistHead + 1) % HASH_HIST_W;
        if (hashHistHead == 0) hashHistFull = true;

        Serial.printf("[HASH] CH:%02d pkt:%lu RSSI:%d EAPOL:%d/%d D:%d AP:%d\n",
          sc_hashChan, (unsigned long)pktSnap, (int)rssiAvg, (int)eapolSnap,
          hashEapolTotal, hashDeauthCount, hashAPCount);
        sc_redraw = true;
      }
      // Log new EAPOL captures to SD text
      if (hashUpdated) {
        hashUpdated = false;
        portENTER_CRITICAL(&hashMux);
        int idx = (hashCaptureHead - 1 + HASH_CAP_MAX) % HASH_CAP_MAX;
        char ssid[33]; strncpy(ssid, hashCaptures[idx].ssid, 32); ssid[32]='\0';
        char bssid[18]; strncpy(bssid, hashCaptures[idx].bssid, 17); bssid[17]='\0';
        portEXIT_CRITICAL(&hashMux);
        char line[64]; snprintf(line, sizeof(line), "SSID:\"%s\" BSSID:%s EAPOL#%d", ssid, bssid, hashEapolTotal);
        Serial.printf("[HASH EAPOL] %s\n", line); sdLog("HASH", line);
        ledFlash(false, true, false, 150);
      }
      break;

    // ── AP ────────────────────────────────────────────────────────────────────
    case MODE_AP:
      if (apUdpStarted && now - apLastPing >= AP_PING_MS) {
        apUdp.beginPacket(AP_BCAST_IP, AP_PORT);
        apUdp.print("ping");
        apUdp.endPacket();
        apPingCount++;
        apLastPing = now;
      }
      if (now - apLastDraw >= 2000) {
        apLastDraw = now;
        sc_redraw  = true;
        Serial.printf("[AP] clients:%d  pings:%lu\n", WiFi.softAPgetStationNum(), apPingCount);
      }
      break;

    // ── PRESENCE ──────────────────────────────────────────────────────────────
    case MODE_PRESENCE:
      if (presState == PRES_CONNECTING) {
        if (WiFi.status() == WL_CONNECTED) {
          presState = PRES_CSI_ACTIVE;
          esp_wifi_set_ps(WIFI_PS_NONE);
          // Start keepalive UDP — sends unicast to AP so 802.11 ACKs flow back,
          // which is what actually triggers CSI callbacks on the STA side.
          presUdp.begin(AP_PORT); presUdpStarted = true;
          presLastKeepalive = now;
          // Enable CSI capture with all subcarrier types
          wifi_csi_config_t cfg = {};
          cfg.lltf_en=true; cfg.htltf_en=true; cfg.stbc_htltf2_en=true;
          cfg.ltf_merge_en=true; cfg.channel_filter_en=true;
          cfg.manu_scale=false; cfg.shift=0;
          esp_wifi_set_csi_config(&cfg);
          esp_wifi_set_csi_rx_cb(onCSI, NULL);
          esp_wifi_set_csi(true);
          csiLastSec = now;
          sc_redraw = true;
          Serial.printf("[PRES] Connected IP=%s RSSI=%d  CSI active\n",
                        WiFi.localIP().toString().c_str(), WiFi.RSSI());
          sdLog("PRES","CSI active SSID=" AP_SSID);
        } else if (now - presConnStart > 15000) {
          presConnStart = now;
          WiFi.disconnect(); delay(100); WiFi.begin(AP_SSID, AP_PASS);
          Serial.println("[PRES] Connection timeout, retrying...");
        }
        if (now - presLastDraw >= 500) { presLastDraw = now; sc_redraw = true; }
      } else {  // PRES_CSI_ACTIVE
        if (WiFi.status() != WL_CONNECTED) {
          presState = PRES_CONNECTING; presConnStart = now;
          esp_wifi_set_csi(false);
          if (presUdpStarted) { presUdp.stop(); presUdpStarted = false; }
          WiFi.begin(AP_SSID, AP_PASS);
          Serial.println("[PRES] Connection lost, reconnecting...");
          sc_redraw = true;
        }
        // Keepalive: send unicast UDP to AP every 50ms → AP sends 802.11 ACKs → CSI fires
        if (presUdpStarted && now - presLastKeepalive >= 50) {
          presLastKeepalive = now;
          presUdp.beginPacket("192.168.4.1", AP_PORT);
          presUdp.print("ka");
          presUdp.endPacket();
        }
        // Calibration countdown: fire after CSI_CAL_DELAY_MS with room empty
        if (csiCalPending && now - csiCalCountStart >= CSI_CAL_DELAY_MS) {
          csiCalPending    = false;
          csiVarBaseline   = csiVariance;
          csiCalibrated    = true;
          sc_redraw        = true;
          Serial.printf("[PRES] Calibrated: baseline=%.2f\n", csiVarBaseline);
          ledSet(false, true, false); delay(150); ledOff(); // green flash = calibrated
        }
        // Every 100ms: compute variance from rolling window
        if (csiUpdated && now - csiLastSec >= 100) {
          csiLastSec = now;
          portENTER_CRITICAL(&csiMux);
          int winN = csiWinFull ? CSI_WIN : csiWinHead;
          float win[CSI_WIN];
          for (int i = 0; i < winN; i++) win[i] = csiWin[i];
          int8_t rssiSnap = csiLastRSSI;
          uint32_t frSnap = csiFrameSec; csiFrameSec = 0;
          csiUpdated = false;
          portEXIT_CRITICAL(&csiMux);

          if (winN > 1) {
            float mean = 0;
            for (int i = 0; i < winN; i++) mean += win[i];
            mean /= winN;
            float var = 0;
            for (int i = 0; i < winN; i++) { float d=win[i]-mean; var+=d*d; }
            csiVariance = var / winN;
            if (csiVariance > csiPeakVar) csiPeakVar = csiVariance;
          }
          csiFrameRate = frSnap * 10;  // 100ms tick → frames/sec

          csiHistBuf[csiHistHead] = csiVariance;
          csiHistHead = (csiHistHead + 1) % CSI_HIST_W;
          if (csiHistHead == 0) csiHistFull = true;

          float lo = csiCalibrated ? csiVarBaseline + CSI_VAR_LO : CSI_VAR_LO;
          float hi = csiCalibrated ? csiVarBaseline + CSI_VAR_HI : CSI_VAR_HI;
          if      (csiVariance < lo) csiConfidence = 0;
          else if (csiVariance > hi) csiConfidence = 100;
          else csiConfidence = (uint8_t)((csiVariance - lo) / (hi - lo) * 100.0f);

          // LED feedback: red=present, yellow=maybe, off=clear
          if      (csiConfidence >= 60) ledSet(true, false, false);
          else if (csiConfidence >= 30) ledSet(true, true,  false);
          else                          ledOff();

          Serial.printf("[PRES] var:%.2f conf:%d%% rssi:%d fr:%d/s\n",
                        csiVariance, csiConfidence, (int)rssiSnap, csiFrameRate);
          char logline[48];
          snprintf(logline, sizeof(logline), "var:%.2f conf:%d rssi:%d",
                   csiVariance, csiConfidence, (int)rssiSnap);
          sdLog("PRES", logline);
          sc_redraw = true;
        }
        // Force redraw every 500ms even if no new CSI data (keeps display feeling live)
        if (now - presLastDraw >= 500) { presLastDraw = now; sc_redraw = true; }
      }
      break;
  }

  if (sc_redraw) redrawAll();
}
