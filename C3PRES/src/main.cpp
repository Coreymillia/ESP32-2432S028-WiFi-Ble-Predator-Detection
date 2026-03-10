/*
 * C3PRES — Headless WiFi Presence Detector
 * ESP32-C3 · No screen · No extra hardware
 *
 * Boots directly into presence detection mode.
 * Connects to a CYD running MODE_AP (SSID: CYD_CSI, pass: cydscanner123).
 * Monitors RSSI with a moving average and detects human presence
 * when signal deviates from a calibrated empty-room baseline.
 *
 * LED (GPIO 8, active LOW) status codes:
 *   Connecting        → fast blink (100ms)
 *   Connected, CLEAR  → slow heartbeat (200ms ON / 2000ms OFF)
 *   MAYBE (30-59%)    → medium blink (300ms ON / 300ms OFF)
 *   PRESENT (≥60%)    → solid ON
 *   Calibrating       → rapid triple-flash every 500ms
 *
 * Calibration:
 *   Auto-calibrates 10 seconds after a stable connection is established.
 *   Re-calibrates automatically if RSSI is stable for 30 seconds (room empty).
 *   Serial output (115200) shows all state changes and RSSI readings.
 */

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

// ── Config ───────────────────────────────────────────────────────────────────
#define AP_SSID           "CYD_CSI"
#define AP_PASS           "cydscanner123"
#define AP_PORT           1234           // UDP keepalive port (matches CYD AP mode)

#define LED_PIN           8              // onboard LED, active LOW

#define RSSI_AVG_ALPHA    0.15f          // EMA smoothing (lower = smoother, slower)
#define RSSI_DIFF_LO      3.0f           // dBm deviation → MAYBE
#define RSSI_DIFF_HI      8.0f           // dBm deviation → PRESENT
#define CONF_MAYBE        30             // confidence % threshold for MAYBE
#define CONF_PRESENT      60             // confidence % threshold for PRESENT

#define SAMPLE_INTERVAL_MS   100UL       // RSSI sample rate
#define KEEPALIVE_INTERVAL_MS 100UL      // UDP keepalive to AP
#define AUTO_CAL_DELAY_MS    10000UL     // wait after connect before first auto-cal
#define RECONNECT_TIMEOUT_MS 15000UL     // retry connection after this long

// ── State ────────────────────────────────────────────────────────────────────
enum PresState { CONNECTING, CALIBRATING, DETECTING };
static PresState state        = CONNECTING;

static float    rssiMovAvg    = 0.0f;
static float    rssiBaseline  = 0.0f;
static bool     calibrated    = false;

static uint8_t  confidence    = 0;       // 0-100
static float    rssiDiff      = 0.0f;

static unsigned long lastSample      = 0;
static unsigned long lastKeepalive   = 0;
static unsigned long connectedSince  = 0;
static unsigned long connStart       = 0;

static WiFiUDP  udp;
static bool     udpStarted    = false;

// ── LED blinking state ───────────────────────────────────────────────────────
static unsigned long lastLedToggle = 0;
static bool          ledOn         = false;
static int           tripleCount   = 0;    // for triple-flash calibrating pattern

static void ledSet(bool on) {
  ledOn = on;
  digitalWrite(LED_PIN, on ? LOW : HIGH);  // active LOW
}

// ── Calibration ──────────────────────────────────────────────────────────────
static void calibrate() {
  rssiBaseline = rssiMovAvg;
  calibrated   = true;
  Serial.printf("[C3PRES] Calibrated: baseline=%.1f dBm\n", rssiBaseline);
}

// ── Setup ────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n[C3PRES] Booting...");

  pinMode(LED_PIN, OUTPUT);
  ledSet(false);

  esp_wifi_set_ps(WIFI_PS_NONE);
  WiFi.mode(WIFI_STA);
  WiFi.begin(AP_SSID, AP_PASS);
  connStart = millis();

  Serial.printf("[C3PRES] Connecting to '%s'...\n", AP_SSID);
}

// ── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
  unsigned long now = millis();

  // ── Connection management ─────────────────────────────────────────────────
  if (WiFi.status() != WL_CONNECTED) {
    if (state != CONNECTING) {
      state       = CONNECTING;
      calibrated  = false;
      rssiMovAvg  = 0.0f;
      rssiDiff    = 0.0f;
      confidence  = 0;
      if (udpStarted) { udp.stop(); udpStarted = false; }
      Serial.println("[C3PRES] Connection lost — reconnecting...");
    }
    // Retry after timeout
    if (now - connStart > RECONNECT_TIMEOUT_MS) {
      connStart = now;
      WiFi.disconnect();
      delay(100);
      WiFi.begin(AP_SSID, AP_PASS);
      Serial.println("[C3PRES] Retry connect...");
    }
  } else if (state == CONNECTING) {
    // Just connected
    esp_wifi_set_ps(WIFI_PS_NONE);
    connectedSince = now;
    connStart      = now;
    rssiMovAvg     = (float)WiFi.RSSI();   // seed EMA with current RSSI
    if (!udpStarted) { udp.begin(AP_PORT); udpStarted = true; }
    state = CALIBRATING;
    Serial.printf("[C3PRES] Connected! IP=%s RSSI=%d  calibrating in 10s...\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());
  }

  if (WiFi.status() != WL_CONNECTED) {
    // Fast blink while connecting
    if (now - lastLedToggle > 100) {
      lastLedToggle = now;
      ledSet(!ledOn);
    }
    return;
  }

  // ── Keepalive UDP → keeps WiFi stack active + AP builds RSSI stats ────────
  if (udpStarted && now - lastKeepalive >= KEEPALIVE_INTERVAL_MS) {
    lastKeepalive = now;
    // Send telemetry to AP — format: "PRES,<conf>,<diff10>,<rssi>"
    char telem[32];
    snprintf(telem, sizeof(telem), "PRES,%hhu,%d,%d",
             confidence,
             (int)(rssiDiff * 10.0f),
             (int)WiFi.RSSI());
    udp.beginPacket("192.168.4.1", AP_PORT);
    udp.print(telem);
    udp.endPacket();
  }

  // ── RSSI sampling ─────────────────────────────────────────────────────────
  if (now - lastSample >= SAMPLE_INTERVAL_MS) {
    lastSample = now;

    int rawRSSI = WiFi.RSSI();
    rssiMovAvg  = rssiMovAvg * (1.0f - RSSI_AVG_ALPHA) + (float)rawRSSI * RSSI_AVG_ALPHA;

    // Auto-calibrate 10s after connecting (assumes room is empty at boot)
    if (state == CALIBRATING && now - connectedSince >= AUTO_CAL_DELAY_MS) {
      calibrate();
      state = DETECTING;
    }

    if (calibrated) {
      rssiDiff   = fabsf(rssiMovAvg - rssiBaseline);
      float lo   = RSSI_DIFF_LO;
      float hi   = RSSI_DIFF_HI;
      if      (rssiDiff < lo) confidence = 0;
      else if (rssiDiff > hi) confidence = 100;
      else    confidence = (uint8_t)((rssiDiff - lo) / (hi - lo) * 100.0f);
    } else {
      rssiDiff   = 0.0f;
      confidence = 0;
    }

    Serial.printf("[C3PRES] rssi:%d avg:%.1f diff:%.1f conf:%d%%  %s\n",
                  rawRSSI, rssiMovAvg, rssiDiff, confidence,
                  confidence >= CONF_PRESENT ? "PRESENT" :
                  confidence >= CONF_MAYBE   ? "MAYBE"   : "CLEAR");
  }

  // ── LED status ────────────────────────────────────────────────────────────
  if (state == CALIBRATING) {
    // Triple-flash pattern during calibration countdown
    unsigned long phase = (now / 150) % 8;
    ledSet(phase < 5 && (phase % 2 == 0));
  } else if (confidence >= CONF_PRESENT) {
    ledSet(true);                          // solid on = PRESENT
  } else if (confidence >= CONF_MAYBE) {
    if (now - lastLedToggle > 300) {       // medium blink = MAYBE
      lastLedToggle = now;
      ledSet(!ledOn);
    }
  } else {
    // Slow heartbeat = CLEAR
    unsigned long onTime  = ledOn ? 200UL  : 2000UL;
    if (now - lastLedToggle > onTime) {
      lastLedToggle = now;
      ledSet(!ledOn);
    }
  }
}
