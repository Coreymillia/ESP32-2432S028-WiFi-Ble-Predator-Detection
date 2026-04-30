#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <PNGdec.h>
#include <Arduino_GFX_Library.h>
#include <time.h>
#include <math.h>

extern Arduino_GFX *gfx;

static const int WX_HEADER_H = 20;
static const int WX_IMAGE_W = 320;
static const int WX_IMAGE_H = 220;
static const size_t WX_RESPONSE_MAX = 48 * 1024;
static const size_t WX_RESPONSE_CHUNK = 1024;
static const unsigned long WX_RADAR_INTERVAL = 5UL * 60UL * 1000UL;
static const unsigned long WX_CLOCK_INTERVAL = 60UL * 1000UL;
static const char *WX_AP_NAME = "CYDScanner_Weather";
static const int WX_ERR_FETCH_OVERSIZE = -7001;
static const int WX_ERR_FETCH_NOMEM = -7002;

struct WxZoomLevel {
  const char *name;
  float degrees;
};

static const WxZoomLevel WX_ZOOM_LEVELS[] = {
  {"Local", 1.5f},
  {"Regional", 3.5f},
  {"Wide", 7.0f},
};
static const int WX_VIEW_COUNT = sizeof(WX_ZOOM_LEVELS) / sizeof(WX_ZOOM_LEVELS[0]);

enum WxState {
  WX_STATE_IDLE = 0,
  WX_STATE_PORTAL,
  WX_STATE_CONNECTING,
  WX_STATE_ACTIVE,
};

static PNG *wx_png = nullptr;
static WebServer *wx_portalServer = nullptr;
static DNSServer *wx_portalDNS = nullptr;
static bool wx_portalDone = false;
static WxState wx_state = WX_STATE_IDLE;
static bool wx_has_settings = false;
static char wx_wifi_ssid[64] = "";
static char wx_wifi_pass[64] = "";
static char wx_lat[16] = "";
static char wx_lon[16] = "";
static int wx_view_idx = 0;
static unsigned long wx_connectStart = 0;
static unsigned long wx_lastConnectDraw = 0;
static unsigned long wx_lastUpdate = 0;
static unsigned long wx_lastClock = 0;
static unsigned long wx_activeSince = 0;
static bool wx_hasRenderedRadar = false;
static int wx_last_http_code = 0;
static uint8_t *wx_response_buf = nullptr;
static int wx_response_len = 0;
static uint16_t wx_lineBuffer[WX_IMAGE_W];
static char wx_radarUrl[512];
static char wx_ipText[20];

static void wxFreeResponseBuffer() {
  if (wx_response_buf) {
    free(wx_response_buf);
    wx_response_buf = nullptr;
  }
  wx_response_len = 0;
}

static void wxFreePNGDecoder() {
  if (wx_png) {
    delete wx_png;
    wx_png = nullptr;
  }
}

static void wxDrawHeader(const char *title, const char *status = nullptr) {
  gfx->fillRect(0, 0, 320, WX_HEADER_H, 0x0106);

  gfx->drawRect(2, 2, 48, 16, 0x07FF);
  gfx->setTextSize(1);
  gfx->setTextColor(0x07FF);
  gfx->setCursor(10, 7);
  gfx->print("SCAN");

  gfx->drawRect(268, 2, 50, 16, 0xFFE0);
  gfx->setTextColor(0xFFE0);
  gfx->setCursor(276, 7);
  gfx->print("SETUP");

  gfx->setTextColor(0xFFFF);
  gfx->setCursor(58, 3);
  gfx->print("RADAR");

  if (title && title[0]) {
    gfx->setTextColor(0x07E0);
    gfx->setCursor(58, 11);
    gfx->print(title);
  }

  if (status && status[0]) {
    gfx->setTextColor(0x7BEF);
    int maxChars = 25;
    char clipped[26];
    strncpy(clipped, status, maxChars);
    clipped[maxChars] = '\0';
    gfx->setCursor(130, 11);
    gfx->print(clipped);
  }
}

static void wxDrawTimestamp() {
  time_t now = time(nullptr);
  if (now < 1577836800) return;  // avoid blocking while SNTP is still syncing
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);

  char buf[12];
  strftime(buf, sizeof(buf), "%H:%M UTC", &timeinfo);
  int tw = strlen(buf) * 6;
  int tx = 320 - tw - 3;
  int ty = 229;

  gfx->fillRect(tx - 1, ty - 1, tw + 2, 10, 0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xFFFF);
  gfx->setCursor(tx, ty);
  gfx->print(buf);
}

static void wxDrawHomeMarker() {
  const int cx = 160;
  const int cy = WX_HEADER_H + (WX_IMAGE_H / 2);
  const uint16_t col = 0xFD20;

  gfx->drawFastHLine(cx - 7, cy, 15, col);
  gfx->drawFastVLine(cx, cy - 7, 15, col);
  gfx->fillCircle(cx, cy, 2, col);
}

static int wxPNGDraw(PNGDRAW *pDraw) {
  if (!wx_png) return 0;
  wx_png->getLineAsRGB565(pDraw, wx_lineBuffer, PNG_RGB565_BIG_ENDIAN, 0xffffffff);
  gfx->draw16bitBeRGBBitmap(0, WX_HEADER_H + pDraw->y, wx_lineBuffer, pDraw->iWidth, 1);
  if ((pDraw->y & 0x07) == 0) yield();
  return 1;
}

static const char *wxCurrentIPText() {
  IPAddress ip = WiFi.localIP();
  snprintf(wx_ipText, sizeof(wx_ipText), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return wx_ipText;
}

static void wxShowPortalScreen() {
  wxDrawHeader("Setup required");
  gfx->fillRect(0, WX_HEADER_H, 320, 220, 0x0000);

  gfx->setTextColor(0x07FF);
  gfx->setTextSize(2);
  gfx->setCursor(36, 34);
  gfx->print("Weather Setup");

  gfx->setTextSize(1);
  gfx->setTextColor(0xFFE0);
  gfx->setCursor(6, 68);
  gfx->print("1. Connect to WiFi AP:");

  gfx->setTextColor(0x07FF);
  gfx->setTextSize(2);
  gfx->setCursor(12, 82);
  gfx->print("CYDScanner_Weather");

  gfx->setTextSize(1);
  gfx->setTextColor(0xFFE0);
  gfx->setCursor(6, 116);
  gfx->print("2. Browse to 192.168.4.1");
  gfx->setCursor(6, 132);
  gfx->print("3. Enter WiFi + lat/lon");
  gfx->setCursor(6, 148);
  gfx->print("4. Save to start radar");

  gfx->setTextColor(0x7BEF);
  gfx->setCursor(6, 182);
  gfx->print("Top-left SCAN returns to scanner.");
}

static void wxShowConnectingScreen(const char *detail = nullptr) {
  char title[32];
  snprintf(title, sizeof(title), "%s view", WX_ZOOM_LEVELS[wx_view_idx].name);
  wxDrawHeader(title, "Connecting");

  gfx->fillRect(0, WX_HEADER_H, 320, 220, 0x0000);
  gfx->setTextColor(0x07E0);
  gfx->setTextSize(2);
  gfx->setCursor(52, 60);
  gfx->print("Connecting");

  gfx->setTextSize(1);
  gfx->setTextColor(0xFFFF);
  gfx->setCursor(10, 96);
  gfx->print("WiFi:");
  gfx->setCursor(46, 96);
  gfx->print(wx_wifi_ssid[0] ? wx_wifi_ssid : "<not set>");

  gfx->setTextColor(0x7BEF);
  gfx->setCursor(10, 118);
  gfx->print(detail ? detail : "Waiting for home WiFi...");

  gfx->setCursor(10, 154);
  gfx->print("Tap SETUP to change weather WiFi.");
}

static void wxShowLoadingScreen(const char *detail = nullptr) {
  char title[32];
  snprintf(title, sizeof(title), "%s view", WX_ZOOM_LEVELS[wx_view_idx].name);
  wxDrawHeader(title, "Loading");

  gfx->fillRect(0, WX_HEADER_H, 320, 220, 0x0000);
  gfx->setTextColor(0x07FF);
  gfx->setTextSize(2);
  gfx->setCursor(36, 58);
  gfx->print("Fetching Radar");

  gfx->setTextSize(1);
  gfx->setTextColor(0xFFFF);
  gfx->setCursor(10, 96);
  gfx->print(detail ? detail : "Pulling latest NOAA composite...");
}

static void wxShowErrorScreen(const char *detail) {
  char title[32];
  snprintf(title, sizeof(title), "%s view", WX_ZOOM_LEVELS[wx_view_idx].name);
  wxDrawHeader(title, "Error");

  gfx->fillRect(0, WX_HEADER_H, 320, 220, 0x0000);
  gfx->setTextColor(0xF800);
  gfx->setTextSize(2);
  gfx->setCursor(58, 56);
  gfx->print("Radar Error");

  gfx->setTextSize(1);
  gfx->setTextColor(0xFFFF);
  gfx->setCursor(10, 96);
  gfx->print(detail ? detail : "Unable to fetch radar.");

  gfx->setTextColor(0x7BEF);
  gfx->setCursor(10, 130);
  gfx->print("Will retry in 60 seconds.");
}

static void wxLoadSettings() {
  Preferences prefs;
  prefs.begin("cydweather", true);
  String ssid = prefs.getString("ssid", "");
  String pass = prefs.getString("pass", "");
  String lat = prefs.getString("lat", "");
  String lon = prefs.getString("lon", "");
  wx_view_idx = prefs.getInt("view", 0);
  prefs.end();

  wx_view_idx = constrain(wx_view_idx, 0, WX_VIEW_COUNT - 1);
  ssid.toCharArray(wx_wifi_ssid, sizeof(wx_wifi_ssid));
  pass.toCharArray(wx_wifi_pass, sizeof(wx_wifi_pass));
  lat.toCharArray(wx_lat, sizeof(wx_lat));
  lon.toCharArray(wx_lon, sizeof(wx_lon));
  wx_has_settings = ssid.length() > 0 && lat.length() > 0 && lon.length() > 0;
}

static void wxSaveSettings(const char *ssid, const char *pass, int view, const char *lat, const char *lon) {
  Preferences prefs;
  prefs.begin("cydweather", false);
  prefs.putString("ssid", ssid);
  prefs.putString("pass", pass);
  prefs.putString("lat", lat);
  prefs.putString("lon", lon);
  prefs.putInt("view", constrain(view, 0, WX_VIEW_COUNT - 1));
  prefs.end();

  strncpy(wx_wifi_ssid, ssid, sizeof(wx_wifi_ssid) - 1);
  wx_wifi_ssid[sizeof(wx_wifi_ssid) - 1] = '\0';
  strncpy(wx_wifi_pass, pass, sizeof(wx_wifi_pass) - 1);
  wx_wifi_pass[sizeof(wx_wifi_pass) - 1] = '\0';
  strncpy(wx_lat, lat, sizeof(wx_lat) - 1);
  wx_lat[sizeof(wx_lat) - 1] = '\0';
  strncpy(wx_lon, lon, sizeof(wx_lon) - 1);
  wx_lon[sizeof(wx_lon) - 1] = '\0';
  wx_view_idx = constrain(view, 0, WX_VIEW_COUNT - 1);
  wx_has_settings = true;
}

static void wxSaveViewIndex() {
  Preferences prefs;
  prefs.begin("cydweather", false);
  prefs.putInt("view", wx_view_idx);
  prefs.end();
}

static void wxHandlePortalRoot() {
  String html =
    "<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>CYD Weather Setup</title>"
    "<style>"
    "body{background:#08101d;color:#d6f4ff;font-family:Arial,sans-serif;"
         "max-width:480px;margin:auto;padding:20px;}"
    "h1{color:#45d6ff;margin-bottom:6px;}"
    "p{color:#94b6c7;}"
    "label{display:block;margin:14px 0 6px;color:#ffe27a;font-weight:bold;}"
    "input,select{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;"
                 "border:1px solid #3d86aa;background:#10243b;color:#ffffff;}"
    "button{width:100%;margin-top:18px;padding:14px;border:none;border-radius:8px;"
           "background:#167bb8;color:#fff;font-weight:bold;font-size:1em;}"
    ".alt{background:#243042;color:#c9d7e0;}"
    "</style></head><body>"
    "<h1>CYD Weather Radar</h1>"
    "<p>Set the home WiFi and location used by the NEXRAD view.</p>"
    "<form method='post' action='/save'>"
    "<label>WiFi SSID</label>"
    "<input type='text' name='ssid' maxlength='63' required value='";
  html += String(wx_wifi_ssid);
  html += "'>"
    "<label>WiFi Password</label>"
    "<input type='password' name='pass' maxlength='63' value='";
  html += String(wx_wifi_pass);
  html += "'>"
    "<label>Default Radar View</label>"
    "<select name='view'>";

  for (int i = 0; i < WX_VIEW_COUNT; i++) {
    html += "<option value='" + String(i) + "'";
    if (i == wx_view_idx) html += " selected";
    html += ">" + String(WX_ZOOM_LEVELS[i].name) + "</option>";
  }

  html += "</select>"
    "<label>Latitude</label>"
    "<input type='text' name='lat' maxlength='15' placeholder='38.8894' value='";
  html += String(wx_lat);
  html += "'>"
    "<label>Longitude</label>"
    "<input type='text' name='lon' maxlength='15' placeholder='-77.0352' value='";
  html += String(wx_lon);
  html += "'>"
    "<button type='submit'>Save &amp; Connect</button>"
    "</form>";

  if (wx_has_settings) {
    html += "<form method='post' action='/nochange'>"
            "<button class='alt' type='submit'>Use Current Settings</button>"
            "</form>";
  }

  html += "<p>Radar is centered on the latitude and longitude you save here.</p>"
          "</body></html>";

  wx_portalServer->send(200, "text/html", html);
}

static void wxHandlePortalSave() {
  String ssid = wx_portalServer->arg("ssid");
  String pass = wx_portalServer->arg("pass");
  String lat = wx_portalServer->arg("lat");
  String lon = wx_portalServer->arg("lon");
  int view = wx_portalServer->hasArg("view") ? wx_portalServer->arg("view").toInt() : 0;

  if (ssid.length() == 0 || lat.length() == 0 || lon.length() == 0) {
    wx_portalServer->send(400, "text/html",
      "<html><body style='background:#08101d;color:#ff7777;font-family:Arial;padding:40px'>"
      "<h2>SSID, latitude, and longitude are required.</h2>"
      "<a href='/' style='color:#45d6ff'>Go Back</a></body></html>");
    return;
  }

  wxSaveSettings(ssid.c_str(), pass.c_str(), view, lat.c_str(), lon.c_str());
  wx_portalServer->send(200, "text/html",
    "<html><body style='background:#08101d;color:#d6f4ff;font-family:Arial;padding:40px'>"
    "<h2 style='color:#45d6ff'>Saved</h2>"
    "<p>The CYD is connecting to your WiFi now.</p>"
    "</body></html>");
  delay(1200);
  wx_portalDone = true;
}

static void wxHandlePortalNoChange() {
  wx_portalServer->send(200, "text/html",
    "<html><body style='background:#08101d;color:#d6f4ff;font-family:Arial;padding:40px'>"
    "<h2 style='color:#45d6ff'>Using saved settings</h2>"
    "<p>The CYD is connecting now.</p>"
    "</body></html>");
  delay(1200);
  wx_portalDone = true;
}

static void wxOpenPortal() {
  wxFreePNGDecoder();
  wxFreeResponseBuffer();

  if (wx_portalServer || wx_portalDNS) {
    if (wx_portalServer) wx_portalServer->stop();
    if (wx_portalDNS) wx_portalDNS->stop();
    delete wx_portalServer;
    delete wx_portalDNS;
    wx_portalServer = nullptr;
    wx_portalDNS = nullptr;
  }

  WiFi.disconnect(true);
  delay(200);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(WX_AP_NAME, "");
  delay(300);

  wx_portalDNS = new DNSServer();
  wx_portalServer = new WebServer(80);
  wx_portalDNS->start(53, "*", WiFi.softAPIP());
  wx_portalServer->on("/", wxHandlePortalRoot);
  wx_portalServer->on("/save", HTTP_POST, wxHandlePortalSave);
  wx_portalServer->on("/nochange", HTTP_POST, wxHandlePortalNoChange);
  wx_portalServer->onNotFound(wxHandlePortalRoot);
  wx_portalServer->begin();

  wx_portalDone = false;
  wx_state = WX_STATE_PORTAL;
  wx_hasRenderedRadar = false;
  wxShowPortalScreen();
}

static void wxClosePortal() {
  if (wx_portalServer) {
    wx_portalServer->stop();
    delete wx_portalServer;
    wx_portalServer = nullptr;
  }
  if (wx_portalDNS) {
    wx_portalDNS->stop();
    delete wx_portalDNS;
    wx_portalDNS = nullptr;
  }
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(200);
}

static void wxStartConnection() {
  wxFreePNGDecoder();
  wxClosePortal();
  wx_state = WX_STATE_CONNECTING;
  wx_connectStart = millis();
  wx_lastConnectDraw = 0;
  wx_lastUpdate = 0;
  wx_lastClock = 0;
  wx_activeSince = 0;
  wx_hasRenderedRadar = false;
  wxShowConnectingScreen();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(250);
  WiFi.begin(wx_wifi_ssid, wx_wifi_pass);
}

static void wxBuildRadarUrl(char *buf, size_t buflen) {
  float lat = atof(wx_lat);
  float lon = atof(wx_lon);
  float lat_half = WX_ZOOM_LEVELS[wx_view_idx].degrees;
  float lon_half = lat_half * ((float)WX_IMAGE_W / (float)WX_IMAGE_H) / cosf(lat * (M_PI / 180.0f));

  float minLon = lon - lon_half;
  float maxLon = lon + lon_half;
  float minLat = lat - lat_half;
  float maxLat = lat + lat_half;

  snprintf(buf, buflen,
    "https://opengeo.ncep.noaa.gov/geoserver/ows"
    "?service=WMS&VERSION=1.1.1&REQUEST=GetMap"
    "&FORMAT=image/png8"
    "&WIDTH=%d&HEIGHT=%d"
    "&SRS=EPSG:4326"
    "&LAYERS=geopolitical,conus_bref_qcd"
    "&BGCOLOR=0x0D1B2A"
    "&BBOX=%.4f,%.4f,%.4f,%.4f",
    WX_IMAGE_W, WX_IMAGE_H, minLon, minLat, maxLon, maxLat);
}

static void wxFetchResponseBuffer(const char *uri) {
  wxFreeResponseBuffer();
  wx_last_http_code = 0;

  WiFiClientSecure *client = new WiFiClientSecure;
  if (!client) return;

  client->setInsecure();
  HTTPClient https;
  https.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  https.addHeader("User-Agent", "ESP32/CYDScannerWeather");
  https.setTimeout(15000);

  if (!https.begin(*client, uri)) {
    delete client;
    return;
  }

  int httpCode = https.GET();
  wx_last_http_code = httpCode;

  if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
    int contentLen = https.getSize();
    if (contentLen > 0 && (size_t)contentLen > WX_RESPONSE_MAX) {
      wx_last_http_code = WX_ERR_FETCH_OVERSIZE;
    } else {
      WiFiClient *stream = https.getStreamPtr();
      stream->setTimeout(15000);
      size_t capacity = 0;
      int remaining = contentLen;
      unsigned long deadline = millis() + 20000UL;

      while (millis() < deadline) {
        if (remaining == 0) break;

        int avail = stream->available();
        if (avail <= 0) {
          if (!https.connected()) break;
          delay(1);
          yield();
          continue;
        }

        size_t toRead = (size_t)avail;
        if (toRead > WX_RESPONSE_CHUNK) toRead = WX_RESPONSE_CHUNK;
        if (remaining > 0 && toRead > (size_t)remaining) toRead = (size_t)remaining;
        if ((size_t)wx_response_len + toRead > WX_RESPONSE_MAX) {
          wx_last_http_code = WX_ERR_FETCH_OVERSIZE;
          wxFreeResponseBuffer();
          break;
        }

        size_t needed = (size_t)wx_response_len + toRead;
        if (needed > capacity) {
          size_t newCapacity = capacity ? capacity : WX_RESPONSE_CHUNK;
          while (newCapacity < needed && newCapacity < WX_RESPONSE_MAX) {
            size_t grown = newCapacity * 2;
            newCapacity = (grown > WX_RESPONSE_MAX) ? WX_RESPONSE_MAX : grown;
          }
          if (newCapacity < needed) {
            wx_last_http_code = WX_ERR_FETCH_OVERSIZE;
            wxFreeResponseBuffer();
            break;
          }
          uint8_t *grownBuf = (uint8_t *)realloc(wx_response_buf, newCapacity);
          if (!grownBuf) {
            wx_last_http_code = WX_ERR_FETCH_NOMEM;
            wxFreeResponseBuffer();
            break;
          }
          wx_response_buf = grownBuf;
          capacity = newCapacity;
        }

        int n = stream->readBytes(wx_response_buf + wx_response_len, toRead);
        if (n <= 0) continue;
        wx_response_len += n;
        if (remaining > 0) remaining -= n;
        yield();
      }

      if (wx_response_len > 0) {
        uint8_t *shrunk = (uint8_t *)realloc(wx_response_buf, wx_response_len);
        if (shrunk) wx_response_buf = shrunk;
      } else {
        wxFreeResponseBuffer();
      }
    }
  }

  https.end();
  delete client;
}

static bool wxFetchAndDrawRadar() {
  if (WiFi.status() != WL_CONNECTED) return false;

  wxBuildRadarUrl(wx_radarUrl, sizeof(wx_radarUrl));
  wxShowLoadingScreen();
  Serial.printf("[WX] heap before fetch: %u stack: %u\n",
                ESP.getFreeHeap(),
                (unsigned)uxTaskGetStackHighWaterMark(NULL));
  wxFetchResponseBuffer(wx_radarUrl);
  Serial.printf("[WX] heap after fetch: %u len:%d http:%d stack:%u\n",
                ESP.getFreeHeap(),
                wx_response_len,
                wx_last_http_code,
                (unsigned)uxTaskGetStackHighWaterMark(NULL));

  wxFreePNGDecoder();
  wx_png = new PNG;

  if (wx_png && wx_response_buf && wx_response_len > 0 &&
      wx_png->openRAM(wx_response_buf, wx_response_len, wxPNGDraw) == PNG_SUCCESS) {
    Serial.printf("[WX] decode start heap:%u stack:%u\n",
                  ESP.getFreeHeap(),
                  (unsigned)uxTaskGetStackHighWaterMark(NULL));
    gfx->fillRect(0, WX_HEADER_H, 320, 220, 0x0000);
    int decodeResult = wx_png->decode(NULL, 0);
    wx_png->close();
    if (decodeResult == PNG_SUCCESS) {
      wxDrawHomeMarker();
      wxDrawTimestamp();
      wxDrawHeader(WX_ZOOM_LEVELS[wx_view_idx].name, wxCurrentIPText());
      wx_lastUpdate = millis();
      wx_lastClock = millis();
      wx_hasRenderedRadar = true;
      Serial.printf("[WX] decode done heap:%u stack:%u\n",
                    ESP.getFreeHeap(),
                    (unsigned)uxTaskGetStackHighWaterMark(NULL));
      wxFreePNGDecoder();
      wxFreeResponseBuffer();
      return true;
    }
    wx_last_http_code = decodeResult;
  }

  char err[48];
  snprintf(err, sizeof(err), "HTTP %d / len %d", wx_last_http_code, wx_response_len);
  wxShowErrorScreen(err);
  wx_lastUpdate = millis() - WX_RADAR_INTERVAL + 60000UL;
  wx_hasRenderedRadar = false;
  wxFreePNGDecoder();
  wxFreeResponseBuffer();
  return false;
}

static void wxDrawCountdownBar() {
  if (wx_state != WX_STATE_ACTIVE || wx_lastUpdate == 0) {
    gfx->drawFastHLine(0, 239, 320, 0x0000);
    return;
  }

  unsigned long elapsed = millis() - wx_lastUpdate;
  if (elapsed > WX_RADAR_INTERVAL) elapsed = WX_RADAR_INTERVAL;
  int barW = (int)((long)(WX_RADAR_INTERVAL - elapsed) * 320L / WX_RADAR_INTERVAL);
  gfx->drawFastHLine(0, 239, barW, 0x001F);
  gfx->drawFastHLine(barW, 239, 320 - barW, 0x0000);
}

static void wxEnter() {
  wxLoadSettings();
  if (!wx_has_settings) wxOpenPortal();
  else wxStartConnection();
}

static void wxLeave() {
  wxFreeResponseBuffer();
  wxFreePNGDecoder();
  if (wx_state == WX_STATE_PORTAL) wxClosePortal();
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  wx_state = WX_STATE_IDLE;
  wx_activeSince = 0;
  wx_hasRenderedRadar = false;
}

static void wxOpenSetup() {
  wxOpenPortal();
}

static void wxCycleView(int dir) {
  wx_view_idx = (wx_view_idx + dir + WX_VIEW_COUNT) % WX_VIEW_COUNT;
  wxSaveViewIndex();
  wx_lastUpdate = 0;
  wx_lastClock = 0;

  if (wx_state == WX_STATE_ACTIVE) {
    wxShowLoadingScreen("Switching radar view...");
    wx_hasRenderedRadar = false;
  } else if (wx_state == WX_STATE_CONNECTING) {
    wxShowConnectingScreen("View changed. Waiting for WiFi...");
  }
}

static void wxLoop() {
  if (wx_state == WX_STATE_PORTAL) {
    if (wx_portalDNS) wx_portalDNS->processNextRequest();
    if (wx_portalServer) wx_portalServer->handleClient();
    if (wx_portalDone) wxStartConnection();
    return;
  }

  if (wx_state == WX_STATE_CONNECTING) {
    if (WiFi.status() == WL_CONNECTED) {
      configTime(0, 0, "pool.ntp.org", "time.nist.gov");
      wx_state = WX_STATE_ACTIVE;
      wx_activeSince = millis();
      wx_lastUpdate = 0;
      wx_lastClock = 0;
      wxShowLoadingScreen("Connected. Loading radar...");
      return;
    }

    if (millis() - wx_lastConnectDraw > 1000UL) {
      wx_lastConnectDraw = millis();
      char detail[64];
      unsigned long secs = (millis() - wx_connectStart) / 1000UL;
      snprintf(detail, sizeof(detail), "Waiting for WiFi... %lus", secs);
      wxShowConnectingScreen(detail);
    }

    if (millis() - wx_connectStart > 30000UL) {
      wx_connectStart = millis();
      WiFi.disconnect(true);
      delay(250);
      WiFi.begin(wx_wifi_ssid, wx_wifi_pass);
      wxShowConnectingScreen("Retrying WiFi connection...");
    }
    return;
  }

  if (wx_state != WX_STATE_ACTIVE) return;

  if (WiFi.status() != WL_CONNECTED) {
    wx_state = WX_STATE_CONNECTING;
    wx_connectStart = millis();
    wxShowConnectingScreen("WiFi lost. Reconnecting...");
    WiFi.disconnect(true);
    delay(250);
    WiFi.begin(wx_wifi_ssid, wx_wifi_pass);
    return;
  }

  if (wx_lastUpdate == 0 && millis() - wx_activeSince < 250UL) {
    return;
  }

  if (wx_lastUpdate == 0 || millis() - wx_lastUpdate >= WX_RADAR_INTERVAL) {
    wxFetchAndDrawRadar();
  } else if (wx_hasRenderedRadar && millis() - wx_lastClock >= WX_CLOCK_INTERVAL) {
    wxDrawTimestamp();
    wx_lastClock = millis();
    wxDrawHeader(WX_ZOOM_LEVELS[wx_view_idx].name, wxCurrentIPText());
  }

  wxDrawCountdownBar();
}
