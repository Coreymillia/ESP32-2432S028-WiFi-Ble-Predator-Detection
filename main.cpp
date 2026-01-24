// AntiPredCYD - Security Detection Framework for ESP32 CYD
// Clean framework with touch menu system

#include <Arduino_GFX_Library.h>
#include <XPT2046_Touchscreen.h>
#include <WiFi.h>
#include <Preferences.h>
#include <esp_wifi.h>
#include <vector>
#include <map>
#include <algorithm>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <SD.h>
#include <FS.h>
#include <set>

// Touch screen pins for CYD
#define XPT2046_IRQ 36   
#define XPT2046_MOSI 32  
#define XPT2046_MISO 39
#define XPT2046_CLK 25   
#define XPT2046_CS 33    

// Display pins
#define BL_PIN 21
#define BOOT_PIN 0

// RGB LED pins (active low)
#define LED_RED_PIN 4
#define LED_GREEN_PIN 16  
#define LED_BLUE_PIN 17

// LDR sensor
#define LDR_PIN 34

// SD Card pins 
#define SD_CS 5
#define SD_MISO 19
#define SD_MOSI 23
#define SD_SCK 18

// Hardware objects
Arduino_DataBus *bus = new Arduino_HWSPI(2 /* DC */, 15 /* CS */, 14 /* SCK */, 13 /* MOSI */, 12 /* MISO */);
Arduino_GFX *gfx = new Arduino_ILI9341(bus);
SPIClass touchSPI = SPIClass(VSPI);
SPIClass sdSPI = SPIClass(HSPI);
XPT2046_Touchscreen ts(XPT2046_CS, XPT2046_IRQ);
Preferences preferences;

// Menu system
enum MenuState {
  MAIN_MENU,
  DEAUTH_HUNTER,
  NETWORK_SCANNER,
  BLE_SKIMMER_HUNTER,
  WIFI_SCANNER,
  HANDSHAKE_HUNTER,
  MORE_OPTIONS,
  SETTINGS,
  ABOUT_INFO,
  MATRIX_SCREENSAVER,
  SYSTEM_STATS,
  COUNTERMEASURES
};

MenuState currentMenu = MAIN_MENU;

// Touch handling
#define TOUCH_DEBOUNCE 200
unsigned long lastTouchTime = 0;

// Display constants
#define SCREEN_WIDTH 320
#define SCREEN_HEIGHT 240
#define MENU_ITEM_HEIGHT 30
#define MENU_ITEMS_PER_PAGE 6

// Menu items for main menu
const char* mainMenuItems[] = {
  "Deauth Hunter",
  "All Available Networks", 
  "BLE/Card Skimmer Hunter",
  "Shady WiFi Scanner",
  "Credential Alert",
  "MORE OPTIONS"
};
const int mainMenuCount = 6;
// Menu items for more options menu
const char* moreOptionsItems[] = {
  "Export Logs",
  "System Stats", 
  "Matrix Screensaver",
  "Countermeasures",
  "About/Info"
};
const int moreOptionsCount = 5;
int selectedMenuItem = 0;
int selectedMoreOption = 0;

// Status variables
bool isScanning = false;
String statusMessage = "Ready";

// Navigation variables for scrollable lists
int network_scroll_offset = 0;
const int NETWORKS_PER_PAGE = 6;
int shady_scroll_offset = 0;
const int SHADY_NETWORKS_PER_PAGE = 6;

// SD Card logging variables
bool sdCardAvailable = false;
String currentLogFile = "";
unsigned long lastLogTime = 0;
const unsigned long LOG_INTERVAL = 5000; // Log every 5 seconds
std::set<String> loggedThreats; // Track logged threats to avoid duplicates

// Deauth Hunter variables
struct DeauthStats {
  uint32_t total_deauths = 0;
  uint32_t unique_aps = 0;
  int32_t rssi_sum = 0;
  uint32_t rssi_count = 0;
  int32_t avg_rssi = -90;
  uint32_t last_reset_time = 0;
} deauth_stats;

const uint8_t WIFI_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
const uint8_t NUM_CHANNELS = sizeof(WIFI_CHANNELS) / sizeof(WIFI_CHANNELS[0]);
uint8_t current_channel_idx = 0;
uint32_t last_channel_change = 0;
uint32_t scan_cycle_start = 0;
bool deauth_hunter_active = false;
std::vector<String> seen_ap_macs;

bool pineap_hunter_active = false;

// PineAP Hunter variables
struct SSIDRecord {
  String essid;
  int32_t rssi;
  uint32_t last_seen;

  SSIDRecord(const String& ssid, int32_t signal) : essid(ssid), rssi(signal), last_seen(millis()) {}
};

struct PineRecord {
  uint8_t bssid[6];
  std::vector<SSIDRecord> essids;
  int32_t rssi;
  uint32_t last_seen;

  PineRecord() : rssi(-100), last_seen(0) {
    memset(bssid, 0, 6);
  }
};

struct PineAPHunterStats {
  std::vector<PineRecord> detected_pineaps;
  std::map<String, std::vector<SSIDRecord>> scan_buffer;
  uint32_t total_scans = 0;
  uint32_t last_scan_time = 0;
  uint32_t scan_cycle_start = 0;
  bool list_changed = false;
} pineap_hunter_stats;

const int ph_alert_ssids = 3; // Alert threshold for multiple SSIDs

// BLE Hunter variables
struct BLEStats {
  uint32_t total_devices = 0;
  uint32_t unique_devices = 0;
  int32_t rssi_sum = 0;
  uint32_t rssi_count = 0;
  int32_t avg_rssi = -70;
  uint32_t last_reset_time = 0;
} ble_stats;

struct BLEDeviceInfo {
  String mac;
  String name;
  int32_t rssi;
  uint32_t last_seen;
  String device_type;
  bool is_suspicious;
};

const uint32_t BLE_SCAN_TIME = 5; // Scan for 5 second intervals  
const uint32_t BLE_SCAN_INTERVAL = 100; // Scan interval
const uint32_t BLE_SCAN_WINDOW = 99; // Scan window
const uint32_t MAX_BLE_DEVICES = 50; // Limit to prevent memory overflow
bool ble_hunter_active = false;
BLEScan* ble_scanner = nullptr;
std::vector<BLEDeviceInfo> seen_ble_devices;

bool shady_wifi_scanner_active = false; // Move here for global access

// Simple Network Scanner variables
struct SimpleNetworkInfo {
  String ssid;
  String bssid;
  int32_t rssi;
  wifi_auth_mode_t encryption;
  uint8_t channel;
  
  SimpleNetworkInfo(const String& s, const String& b, int32_t r, wifi_auth_mode_t e, uint8_t c) 
    : ssid(s), bssid(b), rssi(r), encryption(e), channel(c) {}
};

std::vector<SimpleNetworkInfo> all_networks;
uint32_t last_network_scan = 0;
const uint32_t NETWORK_SCAN_INTERVAL = 30000; // 30 second refresh

// Shady WiFi Scanner stats (move to global scope)
struct ShadyWiFiStats {
  uint32_t total_networks = 0;
  uint32_t hidden_networks = 0;
  uint32_t open_networks = 0;
  uint32_t suspicious_networks = 0;
  uint32_t last_scan_time = 0;
  uint32_t scan_start_time = 0;
  int32_t strongest_rssi = -100;
  String strongest_network = "";
} shady_wifi_stats;

// Credential Harvesting Alert variables
struct CredentialHarvestingStats {
  uint32_t deauth_count = 0;
  uint32_t eapol_count = 0;
  uint32_t targeted_aps = 0;
  uint32_t risk_score = 0;
  uint32_t last_reset_time = 0;
  uint32_t scan_start_time = 0;
} cred_harvest_stats;

struct TargetedAP {
  String bssid;
  String ssid;
  uint32_t deauth_count;
  uint32_t eapol_count;
  uint32_t risk_score;
  int32_t rssi;
  uint32_t last_activity;
  
  TargetedAP(const String& b, const String& s, int32_t r) 
    : bssid(b), ssid(s), deauth_count(0), eapol_count(0), risk_score(0), rssi(r), last_activity(millis()) {}
};

std::vector<TargetedAP> targeted_aps;
bool cred_harvest_active = false;
const uint32_t CRED_HARVEST_RESET_INTERVAL = 60000; // Reset stats every 60 seconds
const uint32_t MAX_TRACKED_APS = 20; // Limit memory usage

// ShadyNetwork struct (move to global scope too)
struct ShadyNetwork {
  String ssid;
  String bssid;
  int32_t rssi;
  uint8_t channel;
  String encryption;
  bool is_suspicious;
  String suspicion_reason;
  uint32_t first_seen;
  uint32_t last_seen;
};

std::vector<ShadyNetwork> detected_shady_networks;

// Matrix Screensaver variables
struct MatrixColumn {
  int x;
  int y;
  int speed;
  char chars[12];  // Trail of characters
  uint8_t brightness[12];  // Brightness for each char
};

std::vector<MatrixColumn> matrix_columns;
unsigned long last_matrix_update = 0;
const int MATRIX_UPDATE_INTERVAL = 100; // ms
const char matrix_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";

// Suspicious device patterns for card skimmers
const char* suspicious_names[] = {
  "HC-03", "HC-05", "HC-06", "HC-08", "RNBT", "AT-09", "DSD TECH", "JDY-", 
  "ESP32", "Arduino", "SKIMMER", "READER", "CARD", "PAY", "CREDIT", "DEBIT", "ATM"
};
const int suspicious_names_count = sizeof(suspicious_names) / sizeof(suspicious_names[0]);

// Portal Killer (Countermeasures) variables
bool countermeasures_active = false;
uint32_t portals_found = 0;
uint32_t counter_messages_sent = 0;
uint32_t last_portal_scan = 0;
uint32_t last_counter_message = 0;
const uint32_t PORTAL_SCAN_INTERVAL = 10000; // Scan every 10 seconds (more aggressive)
const uint32_t COUNTER_MESSAGE_INTERVAL = 5000; // Attack every 5 seconds

struct PortalInfo {
  String ssid;
  String bssid;
  int32_t rssi;
  uint8_t channel;
  uint32_t last_seen;
  bool is_portal;
  
  PortalInfo(const String& s, const String& b, int32_t r, uint8_t c) 
    : ssid(s), bssid(b), rssi(r), channel(c), last_seen(millis()), is_portal(false) {}
};

std::vector<PortalInfo> detected_portals;

// Portal patterns to detect (common captive portal SSIDs + Evil portals)
const char* portal_patterns[] = {
  "Free WiFi", "Guest", "Public", "Hotel", "Airport", "Coffee", "McDonald", 
  "Starbucks", "xfinitywifi", "attwifi", "AndroidAP", "iPhone", "Samsung",
  "TP-Link", "NETGEAR", "Linksys", "Belkin", "D-Link", "Motorola",
  // Evil portal patterns
  "Evil", "Portal", "Captive", "Login", "WiFi", "Internet", "Access",
  "M5Stack", "Bruce", "Nemo", "Flipper", "Pwnagotchi"
};
const int portal_patterns_count = sizeof(portal_patterns) / sizeof(portal_patterns[0]);

// Counter message beacon packet template
uint8_t counter_beacon_packet[] = {
  0x80, 0x00, 0x00, 0x00, // Frame Control, Flags, Duration
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC (broadcast)
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC (will be randomized)
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (same as source)
  0x00, 0x00, // Sequence number
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
  0x64, 0x00, // Beacon interval
  0x01, 0x04, // Capability info
  0x00, 0x00, // SSID length (will be set)
  // SSID will be inserted here (32 bytes max)
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, // Supported rates
  0x03, 0x01, 0x06 // DS Parameter (channel 6, will be updated)
};

// Function prototypes
void displayMainMenu();
void displayMoreOptionsMenu();
void displayStatusScreen(const char* title, const char* status);
void displaySystemStats();
void handleTouch();
void setLED(uint8_t r, uint8_t g, uint8_t b);
void flashLED(uint8_t r, uint8_t g, uint8_t b, int duration);
void drawButton(int x, int y, int w, int h, const char* text, bool selected);
void drawCenteredText(const char* text, int y, uint16_t color);
void drawGridBackground();

// Matrix Screensaver functions
void initMatrixScreensaver();
void updateMatrixScreensaver();
void displayMatrixScreensaver();

// Deauth Hunter functions
void start_deauth_monitoring();
void stop_deauth_monitoring();
void hop_channel();
void reset_stats_if_needed();
void add_unique_ap(const char* mac);
void extract_mac(char *addr, uint8_t* data, uint16_t offset);
static void deauth_sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type);
static void cred_harvest_sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type);

// PineAP Hunter functions  
void start_pineap_monitoring();
void stop_pineap_monitoring();
void scan_and_analyze_pineap();
void scan_all_networks(); // Simple network scanner
void add_scan_result(const String& bssid_str, const String& essid, int32_t rssi);
void process_pineap_scan_results();
void maintain_buffer_size();
String bssid_to_string(const uint8_t* bssid);
void string_to_bssid(const String& bssid_str, uint8_t* bssid);

// BLE Hunter functions
void start_ble_monitoring();
void stop_ble_monitoring();
void scan_and_analyze_ble();
void reset_ble_stats_if_needed();
void add_unique_ble_device(const String& mac, const String& name, int32_t rssi);

// Shady WiFi Scanner functions (Marauder-style)
void start_shady_wifi_monitoring();
void stop_shady_wifi_monitoring();
void scan_and_analyze_shady_wifi();
bool is_suspicious_ble_device(const String& name, const String& mac);

// Credential Harvesting Alert functions
void start_cred_harvest_monitoring();
void stop_cred_harvest_monitoring();
void process_cred_harvest_detection();
void reset_cred_harvest_stats();
uint32_t calculate_risk_score(const TargetedAP& ap);

// SD Card logging functions
void logThreat(const String& threatType, const String& details, int rssi = 0, int channel = 0);
bool isNewThreat(const String& threatType, const String& details);
void initializeLogFile();

// Countermeasures (Portal Killer) functions
void start_countermeasures();
void stop_countermeasures();
void scan_for_portals();
void send_counter_messages();
void attack_bruce_portal(const String& gateway);
void attack_nemo_portal(const String& gateway);
bool is_portal_network(const String& ssid);
void send_counter_beacon(const String& ssid, uint8_t channel);
void displayCountermeasures();

// BLE Callback class
class BLEHunterCallback : public BLEAdvertisedDeviceCallbacks {
public:
  void onResult(BLEAdvertisedDevice advertisedDevice);
};

void setup() {
    Serial.begin(115200);
    Serial.println("AntiPredCYD Security Framework Starting...");
    
    // Initialize preferences
    preferences.begin("antipredcyd", false);
    
    // Initialize backlight
    pinMode(BL_PIN, OUTPUT);
    digitalWrite(BL_PIN, HIGH);
    
    // Initialize display
    gfx->begin();
    gfx->setRotation(1); // Landscape
    gfx->fillScreen(BLACK);
    
    // Startup screen - NEON STYLE!
    gfx->setTextColor(WHITE);
    gfx->setTextSize(2);
    drawCenteredText("PREDATOR DEFENSE", 50, RGB565(255, 0, 0));  // BRIGHT RED!
    
    // Add neon accent line
    gfx->drawFastHLine(50, 70, 220, RGB565(255, 0, 255));  // Bright magenta line
    
    gfx->setTextSize(1);
    drawCenteredText(">> SECURITY FRAMEWORK <<", 85, RGB565(0, 255, 0));  // Bright green
    drawCenteredText("INITIALIZING SYSTEMS...", 130, RGB565(255, 255, 0));  // Bright yellow
    
    delay(2000);
    
    // Initialize touch
    touchSPI.begin(XPT2046_CLK, XPT2046_MISO, XPT2046_MOSI, XPT2046_CS);
    ts.begin(touchSPI);
    ts.setRotation(1);
    
    // Initialize LEDs
    pinMode(LED_RED_PIN, OUTPUT);
    pinMode(LED_GREEN_PIN, OUTPUT);
    pinMode(LED_BLUE_PIN, OUTPUT);
    setLED(0, 0, 0);
    
    // Initialize boot button
    pinMode(BOOT_PIN, INPUT_PULLUP);
    
    // Initialize WiFi in promiscuous mode for scanning
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    // Initialize SD Card
    sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
    if (SD.begin(SD_CS, sdSPI)) {
        sdCardAvailable = true;
        Serial.println("SD Card initialized successfully");
        
        // Create logs directory if it doesn't exist
        if (!SD.exists("/logs")) {
            SD.mkdir("/logs");
        }
        
        // Generate timestamp-based filename  
        currentLogFile = "/logs/threats_" + String(millis()) + ".txt";
        
        // Write initial log entry
        File logFile = SD.open(currentLogFile, FILE_WRITE);
        if (logFile) {
            logFile.println("# AntiPredCYD Threat Log");
            logFile.println("# Timestamp,ThreatType,Details,RSSI,Channel");
            logFile.close();
        }
    } else {
        sdCardAvailable = false;
        Serial.println("SD Card initialization failed");
    }
    
    // Startup animation
    flashLED(255, 0, 0, 200);   
    flashLED(0, 255, 0, 200);   
    flashLED(0, 0, 255, 200);   
    
    // Display main menu
    displayMainMenu();
    
    Serial.println("Setup complete!");
}

void loop() {
    handleTouch();
    
    // Handle different menu states
    switch(currentMenu) {
        case MAIN_MENU:
            // Main menu is static, just handle touch
            break;
            
        case DEAUTH_HUNTER:
            if (isScanning) {
                hop_channel();
                reset_stats_if_needed();
                
                // Update status display with live stats
                gfx->setTextSize(1);
                gfx->setCursor(20, 120);
                gfx->setTextColor(WHITE, BLACK);
                gfx->printf("Ch: %-2d  APs: %-2d        ", WIFI_CHANNELS[current_channel_idx], deauth_stats.unique_aps);
                gfx->setCursor(20, 140);
                gfx->printf("Deauths: %-5d        ", deauth_stats.total_deauths);
                gfx->setCursor(20, 160);
                gfx->printf("Avg RSSI: %-3d        ", deauth_stats.avg_rssi);
                
                // Flash red LED when deauths detected
                if (deauth_stats.total_deauths > 0 && millis() % 500 < 100) {
                    flashLED(255, 0, 0, 50);
                }
            }
            break;
            
        case NETWORK_SCANNER:
            if (isScanning) {
                scan_all_networks();
                
                // COMPACT HORIZONTAL STATS - matching perfect layout
                gfx->setTextSize(1);
                gfx->setCursor(10, 50);
                gfx->setTextColor(WHITE, BLACK);
                
                // Count networks and show stats
                int open_networks = 0;
                int hidden_networks = 0;
                for (const auto& network : all_networks) {
                    if (network.encryption == WIFI_AUTH_OPEN) open_networks++;
                    if (network.ssid == "") hidden_networks++;
                }
                
                gfx->printf("Networks:%d  Open:%d  Hidden:%d", 
                           all_networks.size(), open_networks, hidden_networks);
                
                // Show available networks header with page info
                if (!all_networks.empty()) {
                    gfx->setCursor(10, 70);
                    gfx->setTextColor(YELLOW, BLACK);
                    
                    int total_pages = (all_networks.size() + NETWORKS_PER_PAGE - 1) / NETWORKS_PER_PAGE;
                    int current_page = (network_scroll_offset / NETWORKS_PER_PAGE) + 1;
                    gfx->printf("Networks (Page %d/%d):", current_page, total_pages);
                    
                    // Display networks with scrolling
                    int end_index = min(network_scroll_offset + NETWORKS_PER_PAGE, (int)all_networks.size());
                    for (int i = network_scroll_offset; i < end_index; i++) {
                        int display_row = i - network_scroll_offset;
                        gfx->setCursor(10, 90 + display_row * 18);
                        gfx->setTextColor(WHITE, BLACK);
                        
                        // Calculate available width for SSID
                        int rssi_width = 8; // "-XXdBm" 
                        int available_chars = (SCREEN_WIDTH - 20 - rssi_width * 6) / 6;
                        
                        String display_ssid = all_networks[i].ssid;
                        if (display_ssid == "") {
                            display_ssid = "Hidden Network";
                        }
                        
                        // Truncate SSID if needed
                        if (display_ssid.length() > available_chars) {
                            display_ssid = display_ssid.substring(0, available_chars - 3) + "...";
                        }
                        
                        // Print network with right-aligned signal strength
                        gfx->printf("%-*s %ddBm", available_chars, display_ssid.c_str(), all_networks[i].rssi);
                    }
                    
                    // Draw navigation buttons AFTER the network list
                    if (total_pages > 1) {
                        // Up button (moved up to top-right corner)
                        drawButton(250, 25, 60, 25, "▲ Up", false);
                        
                        // Down button (moved up, tight below up button)  
                        drawButton(250, 55, 60, 25, "▼ Down", false);
                    }
                }
            }
            break;
            
        case BLE_SKIMMER_HUNTER:
            if (isScanning) {
                scan_and_analyze_ble();
                
                // COMPACT HORIZONTAL STATS - matching WiFi scanner layout
                gfx->setTextSize(1);
                gfx->setCursor(10, 50);
                gfx->setTextColor(WHITE, BLACK);
                
                // Count suspicious devices
                int suspicious_count = 0;
                for (const auto& device : seen_ble_devices) {
                    if (device.is_suspicious) suspicious_count++;
                }
                
                gfx->printf("Dev:%d Sus:%d Avg:%d", ble_stats.unique_devices, suspicious_count, ble_stats.avg_rssi);
                
                // Show suspicious devices if any found
                if (suspicious_count > 0) {
                    gfx->setCursor(10, 70);
                    gfx->setTextColor(YELLOW, BLACK);
                    gfx->print("Threat Types Found:");
                    
                    // Create vector of suspicious devices and sort by RSSI strength
                    std::vector<BLEDeviceInfo> suspicious_devices;
                    for (const auto& device : seen_ble_devices) {
                        if (device.is_suspicious) {
                            suspicious_devices.push_back(device);
                        }
                    }
                    
                    // Sort by RSSI (strongest signal first - higher RSSI = closer to 0)
                    std::sort(suspicious_devices.begin(), suspicious_devices.end(),
                        [](const BLEDeviceInfo& a, const BLEDeviceInfo& b) {
                            return a.rssi > b.rssi;
                        });
                    
                    // Show up to 6 strongest suspicious devices with signal strength
                    int y_pos = 90;
                    int devices_to_show = min(6, (int)suspicious_devices.size());
                    
                    // Calculate available character width dynamically (same as WiFi)
                    int total_chars = 320 / 6;  // ~53 characters total width
                    int rssi_space = 6;         // Space for "-67dBm"
                    int prefix_space = 2;       // Space for "• "
                    int available_name_chars = total_chars - rssi_space - prefix_space - 2; // -2 for safety margin
                    
                    for (int i = 0; i < devices_to_show; i++) {
                        gfx->setCursor(10, y_pos);
                        gfx->setTextColor(MAGENTA, BLACK);
                        
                        // Use device name if available, otherwise use MAC
                        String device_name = suspicious_devices[i].name;
                        if (device_name.length() == 0 || device_name == "Unknown") {
                            device_name = suspicious_devices[i].mac;
                        }
                        
                        if (device_name.length() > available_name_chars) {
                            device_name = device_name.substring(0, available_name_chars - 3) + "...";
                        }
                        
                        // Display device name on left, RSSI on right
                        gfx->printf("• %s", device_name.c_str());
                        
                        // Calculate right-aligned position for RSSI
                        int rssi_x = 320 - (rssi_space * 6) - 10; // Right align with margin
                        gfx->setCursor(rssi_x, y_pos);
                        gfx->setTextColor(WHITE, BLACK);
                        gfx->printf("%ddBm", suspicious_devices[i].rssi); // RSSI already negative
                        
                        y_pos += 20;
                        
                        // Stop if we run out of screen space (before back button)
                        if (y_pos > 180) break;
                    }
                }
                
                // Flash magenta LED when suspicious devices detected
                if (suspicious_count > 0 && millis() % 600 < 100) {
                    flashLED(255, 0, 255, 50); // Magenta
                }
            }
            break;
            
        case WIFI_SCANNER:
            if (isScanning) {
                scan_and_analyze_shady_wifi();
                
                // COMPACT HORIZONTAL STATS - all on one row under "Scanning..."
                gfx->setTextSize(1);
                gfx->setCursor(10, 50);
                gfx->setTextColor(WHITE, BLACK);
                gfx->printf("Net:%d Sus:%d Hid:%d Open:%d", 
                    shady_wifi_stats.total_networks,
                    shady_wifi_stats.suspicious_networks,
                    shady_wifi_stats.hidden_networks,
                    shady_wifi_stats.open_networks);
                
                // Show threat details with scrollable list
                if (shady_wifi_stats.suspicious_networks > 0 && !detected_shady_networks.empty()) {
                    gfx->setCursor(10, 70);
                    gfx->setTextColor(YELLOW, BLACK);
                    
                    // Page info for shady networks
                    int total_pages = (detected_shady_networks.size() + SHADY_NETWORKS_PER_PAGE - 1) / SHADY_NETWORKS_PER_PAGE;
                    int current_page = (shady_scroll_offset / SHADY_NETWORKS_PER_PAGE) + 1;
                    gfx->printf("Threats (Page %d/%d):", current_page, total_pages);
                    
                    // Display scrollable shady networks
                    int end_index = min(shady_scroll_offset + SHADY_NETWORKS_PER_PAGE, (int)detected_shady_networks.size());
                    int y_pos = 90;
                    
                    for (int i = shady_scroll_offset; i < end_index; i++) {
                        gfx->setCursor(10, y_pos);
                        gfx->setTextColor(ORANGE, BLACK);
                        
                        // Calculate available character width dynamically
                        int total_chars = 320 / 6;  // ~53 characters total width
                        int rssi_space = 7;         // Space for "-67dBm" 
                        int prefix_space = 2;       // Space for "• "
                        int available_ssid_chars = total_chars - rssi_space - prefix_space - 2;
                        
                        String network_name = detected_shady_networks[i].ssid;
                        if (network_name.length() > available_ssid_chars) {
                            network_name = network_name.substring(0, available_ssid_chars - 3) + "...";
                        }
                        
                        // Display network name on left, signal strength on right
                        gfx->printf("• %s", network_name.c_str());
                        
                        // Calculate right-aligned position for RSSI
                        int rssi_x = 320 - (rssi_space * 6) - 10; // Right align with margin
                        gfx->setCursor(rssi_x, y_pos);
                        gfx->setTextColor(WHITE, BLACK);
                        gfx->printf("-%ddBm", detected_shady_networks[i].rssi);
                        
                        y_pos += 20;
                    }
                    
                    // Draw navigation buttons AFTER the threat list
                    if (total_pages > 1) {
                        // Up button (top-right corner)
                        drawButton(250, 25, 60, 25, "▲ Up", false);
                        
                        // Down button (tight below up button)  
                        drawButton(250, 55, 60, 25, "▼ Down", false);
                    }
                }
                
                // Flash yellow LED when suspicious networks detected
                if (shady_wifi_stats.suspicious_networks > 0 && millis() % 800 < 100) {
                    flashLED(255, 255, 0, 50); // Yellow
                }
            }
            break;
            
        case HANDSHAKE_HUNTER:
            if (isScanning) {
                process_cred_harvest_detection();
                
                // COMPACT HORIZONTAL STATS
                gfx->setTextSize(1);
                gfx->setCursor(10, 50);
                gfx->setTextColor(WHITE, BLACK);
                gfx->printf("Threats:%d APs:%d Deauth:%d EAPOL:%d", 
                    cred_harvest_stats.risk_score,
                    cred_harvest_stats.targeted_aps,
                    cred_harvest_stats.deauth_count,
                    cred_harvest_stats.eapol_count);
                
                // Show active harvesting attempts if detected
                if (cred_harvest_stats.risk_score >= 4) {
                    gfx->setCursor(10, 70);
                    gfx->setTextColor(YELLOW, BLACK);
                    
                    // Show different messages based on risk level
                    if (cred_harvest_stats.risk_score >= 8) {
                        gfx->printf("HIGH RISK: Active Credential Harvesting!");
                    } else if (cred_harvest_stats.risk_score >= 6) {
                        gfx->printf("MEDIUM: Suspicious Wi-Fi Activity");
                    } else {
                        gfx->printf("LOW: Possible Attack Preparation");
                    }
                    
                    // Display up to 4 targeted APs with risk levels
                    int y_pos = 90;
                    int displayed = 0;
                    
                    // Sort targeted APs by risk score (highest first)
                    std::sort(targeted_aps.begin(), targeted_aps.end(), 
                        [](const TargetedAP& a, const TargetedAP& b) {
                            return a.risk_score > b.risk_score;
                        });
                    
                    for (const auto& ap : targeted_aps) {
                        if (displayed >= 4 || y_pos > 180) break;
                        if (ap.risk_score < 3) break; // Only show significant threats
                        
                        // Determine risk level color
                        uint16_t risk_color = GREEN;
                        String risk_level = "LOW";
                        if (ap.risk_score >= 7) {
                            risk_color = RED;
                            risk_level = "HIGH";
                        } else if (ap.risk_score >= 4) {
                            risk_color = YELLOW;  
                            risk_level = "MED";
                        }
                        
                        gfx->setCursor(10, y_pos);
                        gfx->setTextColor(risk_color, BLACK);
                        
                        // Calculate available space for SSID (similar to other scanners)
                        int risk_space = 8; // " MED-XXX" format
                        int available_chars = (320 - 20 - (risk_space * 6)) / 6; // Rough char width calc
                        
                        String display_ssid = ap.ssid;
                        if (display_ssid.length() == 0) display_ssid = "[Hidden]";
                        if (display_ssid.length() > available_chars) {
                            display_ssid = display_ssid.substring(0, available_chars - 3) + "...";
                        }
                        
                        gfx->printf("• %s", display_ssid.c_str());
                        
                        // Right-aligned risk level and RSSI
                        int risk_x = 320 - (risk_space * 6) - 10;
                        gfx->setCursor(risk_x, y_pos);
                        gfx->printf("%s %ddBm", risk_level.c_str(), ap.rssi);
                        
                        y_pos += 20;
                        displayed++;
                    }
                }
                
                // Flash red LED for high risk, yellow for medium
                if (cred_harvest_stats.risk_score >= 7 && millis() % 400 < 100) {
                    flashLED(255, 0, 0, 50); // Red for HIGH risk
                } else if (cred_harvest_stats.risk_score >= 4 && millis() % 800 < 100) {
                    flashLED(255, 255, 0, 50); // Yellow for MEDIUM risk
                }
            }
            break;
            
        case MORE_OPTIONS:
            // Handle more options menu - MORE_OPTIONS removed
            break;
            
        case ABOUT_INFO:
            // About/Info screen - static display
            break;
            
        case SYSTEM_STATS:
            // System Stats screen - static display
            break;
            
        case COUNTERMEASURES:
            if (isScanning) {
                scan_for_portals();
                send_counter_messages();
                
                // Update display with live stats
                displayCountermeasures();
                
                // Flash blue LED when counter-attacking
                if (counter_messages_sent > 0 && millis() % 1000 < 100) {
                    flashLED(0, 0, 255, 50); // Blue flash
                }
            }
            break;
            
        case MATRIX_SCREENSAVER:
            updateMatrixScreensaver();
            break;
            
        case SETTINGS:
            // Settings menu - static for now
            break;
    }
    
    delay(10);
}

void displayMainMenu() {
    gfx->fillScreen(BLACK);
    
    // Add subtle grid background
    drawGridBackground();
    
    // Title - NEON BRIGHT RETRO STYLE!
    gfx->setTextSize(2);
    drawCenteredText("PREDATOR DEFENSE", 12, RGB565(255, 0, 0));  // BRIGHT RED!
    
    // Add a bright accent line under title  
    gfx->drawFastHLine(50, 32, 220, RGB565(255, 0, 255));  // Bright magenta line
    
    // Subtitle - BRIGHT GREEN like old terminal
    gfx->setTextSize(1);
    drawCenteredText(">> SECURITY DETECTION SYSTEM <<", 40, RGB565(0, 255, 0));  // Bright green
    
    // Menu items with enhanced spacing - TRIMMED BUTTONS!
    gfx->setTextSize(1);
    for (int i = 0; i < mainMenuCount; i++) {
        int y = 70 + (i * MENU_ITEM_HEIGHT);  // More space from header
        bool selected = (i == selectedMenuItem);
        // Centered, trimmed buttons: 220px wide, centered on 320px screen
        drawButton(50, y, 220, 25, mainMenuItems[i], selected);
    }
}

void displayMoreOptionsMenu() {
    gfx->fillScreen(BLACK);
    
    // Add subtle grid background
    drawGridBackground();
    
    // Title
    gfx->setTextSize(2);
    drawCenteredText("MORE OPTIONS", 20, WHITE);
    
    // Menu items
    gfx->setTextSize(1);
    for (int i = 0; i < moreOptionsCount; i++) {
        int y = 60 + (i * MENU_ITEM_HEIGHT);
        bool selected = (i == selectedMoreOption);
        drawButton(50, y, 220, 25, moreOptionsItems[i], selected);
    }
    
    // Back button
    drawButton(20, 200, 100, 30, "< Back", false);
}

void displayStatusScreen(const char* title, const char* status) {
    gfx->fillScreen(BLACK);
    
    // Title - SMALLER text, no wrapping
    gfx->setTextSize(1);
    drawCenteredText(title, 10, WHITE);
    
    // Status - right below title
    gfx->setTextSize(1);
    drawCenteredText(status, 30, GREEN);
    
    // Back button
    drawButton(20, 200, 100, 30, "< Back", false);
    
    // Toggle scan button
    const char* buttonText = isScanning ? "Stop" : "Start";
    uint16_t buttonColor = isScanning ? RED : GREEN;
    drawButton(200, 200, 100, 30, buttonText, false);
}

void displayAboutInfo() {
    gfx->fillScreen(BLACK);
    
    // Add subtle grid background
    drawGridBackground();
    
    // Title - NEON BRIGHT matching main menu!
    gfx->setTextSize(2);
    drawCenteredText("PREDATOR DEFENSE", 10, RGB565(255, 0, 0));  // BRIGHT RED!
    
    // Add bright accent line
    gfx->drawFastHLine(50, 28, 220, RGB565(255, 0, 255));  // Bright magenta line
    
    // Subtitle - BRIGHT GREEN
    gfx->setTextSize(1);
    drawCenteredText(">> SECURITY DETECTION SYSTEM <<", 35, RGB565(0, 255, 0));  // Bright green
    
    // Version and info with NEON colors
    gfx->setTextSize(1);
    gfx->setCursor(10, 55);
    gfx->setTextColor(RGB565(255, 255, 0));  // Bright yellow
    gfx->println("Version: 1.3.0 NEON Enhanced");
    
    gfx->setCursor(10, 75);
    gfx->setTextColor(RGB565(0, 255, 255));  // Bright cyan
    gfx->println("ESP32-2432S028 Security Suite");
    
    gfx->setCursor(10, 95);
    gfx->setTextColor(RGB565(255, 128, 0));  // Bright orange
    gfx->println("Features:");
    gfx->setCursor(20, 110);
    gfx->setTextColor(RGB565(255, 0, 255));  // Bright magenta
    gfx->println("• Deauth Attack Detection");
    gfx->setCursor(20, 125);
    gfx->println("• Rogue AP/Evil Twin Scanner");
    gfx->setCursor(20, 140);
    gfx->println("• BLE/Card Skimmer Hunter");
    gfx->setCursor(20, 155);
    gfx->println("• WiFi Network Monitor");
    gfx->setCursor(20, 170);
    gfx->println("• Credential Harvesting Alert");
    
    gfx->setCursor(10, 190);
    gfx->setTextColor(RGB565(0, 255, 0));  // Bright green
    gfx->println(">>> ADVANCED THREAT DETECTION <<<");
    
    // Back button
    drawButton(20, 210, 100, 25, "< Back", false);
}

void displaySystemStats() {
    gfx->fillScreen(BLACK);
    gfx->setTextColor(GREEN);
    gfx->setTextSize(2);
    gfx->setCursor(10, 10);
    gfx->println("System Stats");
    
    gfx->setTextColor(CYAN);
    gfx->setTextSize(1);
    
    // Memory stats
    uint32_t freeHeap = ESP.getFreeHeap();
    uint32_t heapSize = ESP.getHeapSize();
    uint32_t minFreeHeap = ESP.getMinFreeHeap();
    
    gfx->setCursor(10, 40);
    gfx->setTextColor(WHITE);
    gfx->println("Memory:");
    gfx->setCursor(20, 55);
    gfx->setTextColor(CYAN);
    gfx->printf("Free: %u bytes\n", freeHeap);
    gfx->setCursor(20, 70);
    gfx->printf("Total: %u bytes\n", heapSize);
    gfx->setCursor(20, 85);
    gfx->printf("Min Free: %u bytes\n", minFreeHeap);
    
    // CPU stats
    gfx->setCursor(10, 105);
    gfx->setTextColor(WHITE);
    gfx->println("CPU:");
    gfx->setCursor(20, 120);
    gfx->setTextColor(CYAN);
    gfx->printf("Freq: %u MHz\n", ESP.getCpuFreqMHz());
    gfx->setCursor(20, 135);
    gfx->printf("Cores: %u\n", ESP.getChipCores());
    
    // Flash stats
    uint32_t flashSize = ESP.getFlashChipSize();
    gfx->setCursor(10, 155);
    gfx->setTextColor(WHITE);
    gfx->println("Flash:");
    gfx->setCursor(20, 170);
    gfx->setTextColor(CYAN);
    gfx->printf("Size: %u MB\n", flashSize / 1024 / 1024);
    
    // Uptime
    unsigned long uptime = millis();
    unsigned long seconds = uptime / 1000;
    unsigned long minutes = seconds / 60;
    unsigned long hours = minutes / 60;
    
    gfx->setCursor(10, 190);
    gfx->setTextColor(WHITE);
    gfx->println("Uptime:");
    gfx->setCursor(20, 205);
    gfx->setTextColor(CYAN);
    gfx->printf("%luh %lum %lus\n", hours, minutes % 60, seconds % 60);
    
    // Back button
    drawButton(20, 210, 100, 25, "< Back", false);
}

void exportLogsToSD() {
    gfx->fillScreen(BLACK);
    gfx->setTextColor(GREEN);
    gfx->setTextSize(2);
    gfx->setCursor(10, 10);
    gfx->println("Export Logs");
    
    gfx->setTextColor(WHITE);
    gfx->setTextSize(1);
    gfx->setCursor(10, 40);
    
    if (!sdCardAvailable) {
        gfx->setTextColor(RED);
        gfx->println("ERROR: SD Card not found");
        gfx->setTextColor(WHITE);
        gfx->setCursor(10, 60);
        gfx->println("Insert SD card and restart");
        drawButton(20, 210, 100, 25, "< Back", false);
        return;
    }
    
    // Create filename with timestamp
    unsigned long uptime = millis();
    unsigned long minutes = (uptime / 1000) / 60;
    String filename = "/logs/threats_" + String(minutes) + ".txt";
    
    gfx->println("Exporting threat data...");
    
    File logFile = SD.open(filename.c_str(), FILE_WRITE);
    if (!logFile) {
        gfx->setTextColor(RED);
        gfx->setCursor(10, 60);
        gfx->println("ERROR: Cannot create log file");
        drawButton(20, 210, 100, 25, "< Back", false);
        return;
    }
    
    // Write header
    logFile.println("=== AntiPred CYD Security Log ===");
    logFile.printf("Export Time: %lu minutes uptime\n", minutes);
    logFile.println("Device: ESP32-2432S028 (CYD)");
    logFile.println("");
    
    // Export real-time logged threats from SD card
    gfx->setCursor(10, 60);
    gfx->setTextColor(CYAN);
    gfx->println("Reading logged threats from SD...");
    
    logFile.println("=== LOGGED THREATS ===");
    
    int threatCount = 0;
    // Read from the current log file that was created during scanning
    if (SD.exists(currentLogFile)) {
        File readLogFile = SD.open(currentLogFile, FILE_READ);
        if (readLogFile) {
            while (readLogFile.available()) {
                String line = readLogFile.readStringUntil('\n');
                if (line.startsWith("#")) continue; // Skip header comments
                if (line.length() > 0) {
                    logFile.println(line);
                    threatCount++;
                }
            }
            readLogFile.close();
        }
    }
    
    gfx->setCursor(10, 80);
    gfx->printf("Exported %d threat entries", threatCount);
    
    // Export credential harvest alerts if any
    if (cred_harvest_stats.risk_score > 0) {
        gfx->setCursor(10, 80);
        gfx->printf("Writing %lu credential alerts...", cred_harvest_stats.risk_score);
        
        logFile.println("\n=== CREDENTIAL HARVEST ATTEMPTS ===");
        logFile.printf("Risk Score: %lu\n", cred_harvest_stats.risk_score);
        logFile.printf("Deauth Count: %lu\n", cred_harvest_stats.deauth_count);
        logFile.printf("EAPOL Count: %lu\n", cred_harvest_stats.eapol_count);
        logFile.printf("Targeted APs: %lu\n", cred_harvest_stats.targeted_aps);
        logFile.println("Note: Higher risk score indicates active credential harvesting");
        logFile.println("---");
    }
    
    // Export BLE threats if any - count suspicious devices
    int suspicious_count = 0;
    for (const auto& device : seen_ble_devices) {
        if (device.is_suspicious) suspicious_count++;
    }
    
    gfx->setCursor(10, 100);
    gfx->printf("Writing BLE threat data...");
    
    logFile.println("\n=== BLE THREAT SUMMARY ===");
    logFile.printf("BLE Devices Found: %d\n", ble_stats.unique_devices);
    logFile.printf("Suspicious Devices: %d\n", suspicious_count);
    logFile.println("Note: Device details logged during scan");
    logFile.println("---");
    
    // Footer
    logFile.println("\n=== END OF LOG ===");
    logFile.printf("Log generated by AntiPred CYD v1.3.0\n");
    
    logFile.close();
    
    // Success message
    gfx->setCursor(10, 130);
    gfx->setTextColor(GREEN);
    gfx->println("Export successful!");
    gfx->setCursor(10, 150);
    gfx->setTextColor(WHITE);
    gfx->printf("Saved to: %s", filename.c_str());
    
    gfx->setCursor(10, 170);
    gfx->setTextColor(CYAN);
    gfx->printf("File size: %d bytes", logFile.size());
    
    drawButton(20, 210, 100, 25, "< Back", false);
}

void handleTouch() {
    if (ts.tirqTouched() && ts.touched()) {
        if (millis() - lastTouchTime > TOUCH_DEBOUNCE) {
            TS_Point p = ts.getPoint();
            
            // Convert touch coordinates to screen coordinates
            int x = map(p.x, 200, 3700, 0, SCREEN_WIDTH);
            int y = map(p.y, 240, 3800, 0, SCREEN_HEIGHT);
            
            flashLED(0, 255, 0, 100); // Green flash on touch
            
            if (currentMenu == MAIN_MENU) {
                // Check which menu item was touched - updated for new button positions
                for (int i = 0; i < mainMenuCount; i++) {
                    int itemY = 70 + (i * MENU_ITEM_HEIGHT);  // Match new Y position
                    // New X range: buttons are now 50-270 (50 + 220 width)
                    if (y >= itemY && y <= itemY + 25 && x >= 50 && x <= 270) {
                        selectedMenuItem = i;
                        
                        // Switch to selected module
                        switch (i) {
                            case 0: currentMenu = DEAUTH_HUNTER; break;
                            case 1: currentMenu = NETWORK_SCANNER; break;
                            case 2: currentMenu = BLE_SKIMMER_HUNTER; break;
                            case 3: currentMenu = WIFI_SCANNER; break;
                            case 4: currentMenu = HANDSHAKE_HUNTER; break;
                            case 5: currentMenu = MORE_OPTIONS; break;
                        }
                        
                        // Display status screen for security modules, or more options menu
                        if (currentMenu == MORE_OPTIONS) {
                            displayMoreOptionsMenu();
                        } else {
                            displayStatusScreen(mainMenuItems[i], "Ready");
                        }
                        break;
                    }
                }
            } else if (currentMenu == MORE_OPTIONS) {
                // Handle touches in MORE OPTIONS menu - updated for new button positions
                for (int i = 0; i < moreOptionsCount; i++) {
                    int itemY = 60 + (i * MENU_ITEM_HEIGHT);
                    // New X range: buttons are now 50-270 (50 + 220 width)
                    if (y >= itemY && y <= itemY + 25 && x >= 50 && x <= 270) {
                        selectedMoreOption = i;
                        
                        // Switch to selected option - MORE_OPTIONS removed
                        switch (i) {
                            case 0: // Export Logs
                                exportLogsToSD();
                                break;
                            case 1: // System Stats
                                currentMenu = SYSTEM_STATS;
                                displaySystemStats();
                                break;
                            case 2: // Matrix Screensaver
                                currentMenu = MATRIX_SCREENSAVER;
                                initMatrixScreensaver();
                                break;
                            case 3: // Countermeasures
                                currentMenu = COUNTERMEASURES;
                                displayStatusScreen("Countermeasures", "Ready");
                                break;
                            case 4: // About/Info
                                currentMenu = ABOUT_INFO;
                                displayAboutInfo();
                                break;
                        }
                        
                        // Display appropriate screen - MORE_OPTIONS removed
                        if (currentMenu == SETTINGS) {
                            // TODO: Display settings menu
                        }
                        break;
                    }
                }
                
                // Check for back button
                if (y >= 200 && y <= 230 && x >= 20 && x <= 120) {
                    currentMenu = MAIN_MENU;
                    displayMainMenu();
                }
            } else if (currentMenu == ABOUT_INFO) {
                // Handle About/Info screen touches
                if (y >= 210 && y <= 235 && x >= 20 && x <= 120) {
                    // Back button
                    currentMenu = MORE_OPTIONS;
                    displayMoreOptionsMenu();
                }
            } else if (currentMenu == SYSTEM_STATS) {
                // Handle System Stats screen touches
                if (y >= 210 && y <= 235 && x >= 20 && x <= 120) {
                    // Back button
                    currentMenu = MORE_OPTIONS;
                    displayMoreOptionsMenu();
                }
            } else if (currentMenu == MATRIX_SCREENSAVER) {
                // Handle Matrix Screensaver touches - touch anywhere to exit
                currentMenu = MORE_OPTIONS;
                displayMoreOptionsMenu();
            } else {
                // Handle touches in status screens
                
                // Handle Up/Down navigation buttons for Network Scanner
                if (currentMenu == NETWORK_SCANNER && isScanning && !all_networks.empty()) {
                    // Up button (250, 25, 60, 25)
                    if (y >= 25 && y <= 50 && x >= 250 && x <= 310) {
                        // Scroll up (decrease offset)
                        if (network_scroll_offset > 0) {
                            network_scroll_offset -= NETWORKS_PER_PAGE;
                            if (network_scroll_offset < 0) {
                                network_scroll_offset = 0;
                            }
                        }
                        // Don't process other buttons when navigation is pressed
                        lastTouchTime = millis();
                        return;
                    }
                    
                    // Down button (250, 55, 60, 25)
                    if (y >= 55 && y <= 80 && x >= 250 && x <= 310) {
                        // Scroll down (increase offset)
                        int max_offset = ((int)all_networks.size() - 1) / NETWORKS_PER_PAGE * NETWORKS_PER_PAGE;
                        if (network_scroll_offset < max_offset) {
                            network_scroll_offset += NETWORKS_PER_PAGE;
                            if (network_scroll_offset > max_offset) {
                                network_scroll_offset = max_offset;
                            }
                        }
                        // Don't process other buttons when navigation is pressed
                        lastTouchTime = millis();
                        return;
                    }
                }
                
                // Handle Up/Down navigation buttons for Shady WiFi Scanner
                if (currentMenu == WIFI_SCANNER && isScanning && !detected_shady_networks.empty()) {
                    // Up button (250, 25, 60, 25)
                    if (y >= 25 && y <= 50 && x >= 250 && x <= 310) {
                        // Scroll up (decrease offset)
                        if (shady_scroll_offset > 0) {
                            shady_scroll_offset -= SHADY_NETWORKS_PER_PAGE;
                            if (shady_scroll_offset < 0) {
                                shady_scroll_offset = 0;
                            }
                        }
                        // Don't process other buttons when navigation is pressed
                        lastTouchTime = millis();
                        return;
                    }
                    
                    // Down button (250, 55, 60, 25)
                    if (y >= 55 && y <= 80 && x >= 250 && x <= 310) {
                        // Scroll down (increase offset)
                        int max_offset = ((int)detected_shady_networks.size() - 1) / SHADY_NETWORKS_PER_PAGE * SHADY_NETWORKS_PER_PAGE;
                        if (shady_scroll_offset < max_offset) {
                            shady_scroll_offset += SHADY_NETWORKS_PER_PAGE;
                            if (shady_scroll_offset > max_offset) {
                                shady_scroll_offset = max_offset;
                            }
                        }
                        // Don't process other buttons when navigation is pressed
                        lastTouchTime = millis();
                        return;
                    }
                }
                
                if (y >= 200 && y <= 230) {
                    if (x >= 20 && x <= 120) {
                        // Back button
                        currentMenu = MAIN_MENU;
                        isScanning = false;
                        
                        // Stop any active monitoring
                        if (deauth_hunter_active) {
                            stop_deauth_monitoring();
                        }
                        if (pineap_hunter_active) {
                            stop_pineap_monitoring();
                        }
                        if (ble_hunter_active) {
                            stop_ble_monitoring();
                        }
                        if (shady_wifi_scanner_active) {
                            stop_shady_wifi_monitoring();
                        }
                        if (countermeasures_active) {
                            stop_countermeasures();
                        }
                        
                        displayMainMenu();
                    } else if (x >= 200 && x <= 300) {
                        // Start/Stop button
                        isScanning = !isScanning;
                        
                        // Handle module-specific start/stop logic
                        if (currentMenu == DEAUTH_HUNTER) {
                            if (isScanning) {
                                start_deauth_monitoring();
                                displayStatusScreen("Deauth Hunter", "Monitoring...");
                            } else {
                                stop_deauth_monitoring();
                                displayStatusScreen("Deauth Hunter", "Stopped");
                            }
                        } else if (currentMenu == NETWORK_SCANNER) {
                            if (isScanning) {
                                network_scroll_offset = 0; // Reset scroll position
                                start_pineap_monitoring();
                                displayStatusScreen("All Available Networks", "Scanning...");
                            } else {
                                network_scroll_offset = 0; // Reset scroll position
                                stop_pineap_monitoring();
                                displayStatusScreen("All Available Networks", "Stopped");
                            }
                        } else if (currentMenu == BLE_SKIMMER_HUNTER) {
                            if (isScanning) {
                                start_ble_monitoring();
                                displayStatusScreen("BLE/Card Skimmer Hunter", "Scanning...");
                            } else {
                                stop_ble_monitoring();
                                displayStatusScreen("BLE/Card Skimmer Hunter", "Stopped");
                            }
                        } else if (currentMenu == WIFI_SCANNER) {
                            if (isScanning) {
                                shady_scroll_offset = 0; // Reset scroll position
                                start_shady_wifi_monitoring();
                                displayStatusScreen("Shady WiFi Scanner", "Scanning...");
                            } else {
                                shady_scroll_offset = 0; // Reset scroll position
                                stop_shady_wifi_monitoring();
                                displayStatusScreen("Shady WiFi Scanner", "Stopped");
                            }
                        } else if (currentMenu == HANDSHAKE_HUNTER) {
                            if (isScanning) {
                                start_cred_harvest_monitoring();
                                displayStatusScreen("Credential Alert", "Monitoring...");
                            } else {
                                stop_cred_harvest_monitoring();
                                displayStatusScreen("Credential Alert", "Stopped");
                            }
                        } else if (currentMenu == COUNTERMEASURES) {
                            if (isScanning) {
                                start_countermeasures();
                                displayStatusScreen("Countermeasures", "Active");
                            } else {
                                stop_countermeasures();
                                displayStatusScreen("Countermeasures", "Stopped");
                            }
                        } else {
                            const char* status = isScanning ? "Scanning..." : "Ready";
                            displayStatusScreen(mainMenuItems[selectedMenuItem], status);
                        }
                    }
                }
            }
            
            lastTouchTime = millis();
        }
    }
}

void setLED(uint8_t r, uint8_t g, uint8_t b) {
    digitalWrite(LED_RED_PIN, r == 0 ? HIGH : LOW);
    digitalWrite(LED_GREEN_PIN, g == 0 ? HIGH : LOW);
    digitalWrite(LED_BLUE_PIN, b == 0 ? HIGH : LOW);
}

void flashLED(uint8_t r, uint8_t g, uint8_t b, int duration) {
    setLED(r, g, b);
    delay(duration);
    setLED(0, 0, 0);
}

void drawButton(int x, int y, int w, int h, const char* text, bool selected) {
    // NEON BUTTON COLORS - bright and confident!
    uint16_t bgColor = selected ? RGB565(255, 0, 128) : RGB565(40, 40, 80);  // Hot pink selection, dark blue background
    uint16_t textColor = selected ? WHITE : RGB565(0, 255, 255);  // White selected, bright cyan unselected  
    uint16_t borderColor = selected ? RGB565(255, 255, 0) : RGB565(0, 200, 255);  // Yellow border selected, bright blue unselected
    
    gfx->fillRect(x, y, w, h, bgColor);
    gfx->drawRect(x, y, w, h, borderColor);
    
    // Make selected buttons slightly bigger/bolder
    int textSize = selected ? 1 : 1;
    gfx->setTextSize(textSize);
    
    int charWidth = 6 * textSize;
    int textX = x + (w - strlen(text) * charWidth) / 2;
    int textY = y + (h - 8 * textSize) / 2;
    
    gfx->setCursor(textX, textY);
    gfx->setTextColor(textColor);
    gfx->print(text);
}

void drawCenteredText(const char* text, int y, uint16_t color) {
    // Get current text size to calculate proper centering
    int textSize = 1; // Default size
    int charWidth = 6 * textSize; 
    
    // For size 2 text, character width is doubled
    if (y <= 15) { // Main titles are usually at top
        textSize = 2;
        charWidth = 12;
    }
    
    int textWidth = strlen(text) * charWidth;
    int x = (SCREEN_WIDTH - textWidth) / 2;
    
    gfx->setCursor(x, y);
    gfx->setTextColor(color);
    gfx->print(text);
}

void drawGridBackground() {
    // Subtle grid pattern - dark blue/purple lines
    uint16_t gridColor = RGB565(20, 20, 60);  // Dark blue-purple, subtle but visible
    
    // Draw vertical lines every 30 pixels
    for (int x = 30; x < SCREEN_WIDTH; x += 30) {
        gfx->drawFastVLine(x, 0, SCREEN_HEIGHT, gridColor);
    }
    
    // Draw horizontal lines every 25 pixels  
    for (int y = 25; y < SCREEN_HEIGHT; y += 25) {
        gfx->drawFastHLine(0, y, SCREEN_WIDTH, gridColor);
    }
}

// Deauth Hunter Implementation
void extract_mac(char *addr, uint8_t* data, uint16_t offset) {
    sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", 
            data[offset], data[offset+1], data[offset+2], 
            data[offset+3], data[offset+4], data[offset+5]);
}

void add_unique_ap(const char* mac) {
    String mac_str = String(mac);
    for (const String& seen_mac : seen_ap_macs) {
        if (seen_mac == mac_str) {
            return; // Already seen
        }
    }
    seen_ap_macs.push_back(mac_str);
    deauth_stats.unique_aps = seen_ap_macs.size();
}

void hop_channel() {
    uint32_t now = millis();
    if (now - last_channel_change > 1000) { // Change channel every second
        current_channel_idx = (current_channel_idx + 1) % NUM_CHANNELS;
        esp_wifi_set_channel(WIFI_CHANNELS[current_channel_idx], WIFI_SECOND_CHAN_NONE);
        last_channel_change = now;
    }
}

void reset_stats_if_needed() {
    uint32_t now = millis();
    if (now - deauth_stats.last_reset_time > 10000) { // Reset every 10 seconds
        deauth_stats.total_deauths = 0;
        deauth_stats.rssi_sum = 0;
        deauth_stats.rssi_count = 0;
        deauth_stats.avg_rssi = -90;
        seen_ap_macs.clear();
        deauth_stats.unique_aps = 0;
        deauth_stats.last_reset_time = now;
        scan_cycle_start = now;
    }
}

static void deauth_sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!deauth_hunter_active) return;
    
    wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
    
    if (type == WIFI_PKT_MGMT) {
        uint8_t frame_type = snifferPacket->payload[0];
        
        // Check for deauth (0xC0) or disassoc (0xA0) frames
        if (frame_type == 0xC0 || frame_type == 0xA0) {
            deauth_stats.total_deauths++;
            
            // Extract source MAC (AP sending deauth)
            char source_mac[18];
            extract_mac(source_mac, snifferPacket->payload, 10);
            add_unique_ap(source_mac);
            
            // Log deauth attack
            String frameTypeName = (frame_type == 0xC0) ? "Deauth" : "Disassoc";
            logThreat("Deauth_Attack", frameTypeName + " from " + String(source_mac), 
                      snifferPacket->rx_ctrl.rssi, snifferPacket->rx_ctrl.channel);
            
            // Track RSSI
            int32_t rssi = snifferPacket->rx_ctrl.rssi;
            if (deauth_stats.rssi_count == 0) {
                deauth_stats.avg_rssi = rssi;
                deauth_stats.rssi_count = 1;
                deauth_stats.rssi_sum = rssi;
            } else {
                deauth_stats.rssi_count++;
                deauth_stats.rssi_sum += rssi;
                deauth_stats.avg_rssi = deauth_stats.rssi_sum / deauth_stats.rssi_count;
                
                // Prevent overflow
                if (deauth_stats.rssi_count > 1000) {
                    deauth_stats.rssi_sum = deauth_stats.avg_rssi;
                    deauth_stats.rssi_count = 1;
                }
            }
        }
    }
}

void start_deauth_monitoring() {
    // Stop existing WiFi operations
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(100);
    
    // Initialize WiFi in promiscuous mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    // Set up promiscuous mode
    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&deauth_sniffer_callback);
    
    // Set initial channel
    esp_wifi_set_channel(WIFI_CHANNELS[current_channel_idx], WIFI_SECOND_CHAN_NONE);
    
    // Initialize stats
    memset(&deauth_stats, 0, sizeof(DeauthStats));
    deauth_stats.avg_rssi = -90;
    seen_ap_macs.clear();
    current_channel_idx = 0;
    
    deauth_hunter_active = true;
    scan_cycle_start = millis();
    deauth_stats.last_reset_time = scan_cycle_start;
    last_channel_change = millis();
}

void stop_deauth_monitoring() {
    esp_wifi_set_promiscuous(false);
    deauth_hunter_active = false;
    WiFi.mode(WIFI_STA);
}

// PineAP Hunter Implementation
String bssid_to_string(const uint8_t* bssid) {
    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return String(mac_str);
}

void string_to_bssid(const String& bssid_str, uint8_t* bssid) {
    unsigned int temp[6];
    sscanf(bssid_str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
           &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]);
    for (int i = 0; i < 6; i++) {
        bssid[i] = (uint8_t)temp[i];
    }
}

void add_scan_result(const String& bssid_str, const String& essid, int32_t rssi) {
    // Add to scan buffer
    if (pineap_hunter_stats.scan_buffer.find(bssid_str) == pineap_hunter_stats.scan_buffer.end()) {
        pineap_hunter_stats.scan_buffer[bssid_str] = std::vector<SSIDRecord>();
    }

    // Check if this ESSID is already recorded for this BSSID
    auto& essid_list = pineap_hunter_stats.scan_buffer[bssid_str];
    bool found = false;
    for (auto& existing_record : essid_list) {
        if (existing_record.essid == essid) {
            // Update RSSI and timestamp when this SSID is seen again
            existing_record.rssi = rssi;
            existing_record.last_seen = millis();
            found = true;
            break;
        }
    }

    if (!found) {
        essid_list.push_back(SSIDRecord(essid, rssi));
    }
}

void process_pineap_scan_results() {
    std::vector<PineRecord> new_pineaps;

    // Check each BSSID in scan buffer for pineapple behavior
    for (const auto& entry : pineap_hunter_stats.scan_buffer) {
        const String& bssid_str = entry.first;
        const std::vector<SSIDRecord>& ssid_records = entry.second;

        if (ssid_records.size() >= ph_alert_ssids) {
            PineRecord pine;
            string_to_bssid(bssid_str, pine.bssid);
            pine.essids = ssid_records;
            pine.last_seen = millis();

            // Sort SSIDs by most recent seen first
            std::sort(pine.essids.begin(), pine.essids.end(),
                [](const SSIDRecord& a, const SSIDRecord& b) {
                    return a.last_seen > b.last_seen;
                });

            new_pineaps.push_back(pine);
        }
    }

    // Update detected pineaps list if changed
    if (new_pineaps.size() != pineap_hunter_stats.detected_pineaps.size()) {
        pineap_hunter_stats.list_changed = true;
    }

    pineap_hunter_stats.detected_pineaps = new_pineaps;
}

void maintain_buffer_size() {
    // Keep only the most recent 50 BSSID entries
    if (pineap_hunter_stats.scan_buffer.size() > 50) {
        // Remove oldest entries (simple approach)
        auto it = pineap_hunter_stats.scan_buffer.begin();
        for (int i = 0; i < 10 && it != pineap_hunter_stats.scan_buffer.end(); i++) {
            it = pineap_hunter_stats.scan_buffer.erase(it);
        }
    }
}

void scan_and_analyze_pineap() {
    static uint32_t last_wifi_scan = 0;

    // Scan every 3 seconds for PineAP detection
    if (millis() - last_wifi_scan > 3000) {
        int n = WiFi.scanNetworks();
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                String bssid_str = WiFi.BSSIDstr(i);
                String essid = WiFi.SSID(i);
                int32_t rssi = WiFi.RSSI(i);

                // Only process networks with valid ESSIDs
                if (essid.length() > 0 && bssid_str.length() > 0) {
                    add_scan_result(bssid_str, essid, rssi);
                }
            }

            pineap_hunter_stats.total_scans++;
            process_pineap_scan_results();
            maintain_buffer_size();
        }

        WiFi.scanDelete(); // Free memory
        last_wifi_scan = millis();
    }
}

// Simple Network Scanner Implementation
void scan_all_networks() {
    static uint32_t last_scan_time = 0;
    
    // Scan every 30 seconds or on first call
    if (millis() - last_scan_time > NETWORK_SCAN_INTERVAL || last_scan_time == 0) {
        int n = WiFi.scanNetworks();
        
        // Clear previous results
        all_networks.clear();
        
        if (n > 0) {
            // Create vector with all networks
            for (int i = 0; i < n; i++) {
                String ssid = WiFi.SSID(i);
                String bssid = WiFi.BSSIDstr(i);
                int32_t rssi = WiFi.RSSI(i);
                wifi_auth_mode_t encryption = WiFi.encryptionType(i);
                uint8_t channel = WiFi.channel(i);
                
                all_networks.emplace_back(ssid, bssid, rssi, encryption, channel);
            }
            
            // Sort by signal strength (strongest first)
            std::sort(all_networks.begin(), all_networks.end(),
                [](const SimpleNetworkInfo& a, const SimpleNetworkInfo& b) {
                    return a.rssi > b.rssi;
                });
        }
        
        WiFi.scanDelete(); // Free memory
        last_scan_time = millis();
    }
}

void start_pineap_monitoring() {
    // Ensure WiFi is in station mode for scanning
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    // Initialize stats
    pineap_hunter_stats = PineAPHunterStats();
    pineap_hunter_stats.scan_cycle_start = millis();
    
    pineap_hunter_active = true;
}

void stop_pineap_monitoring() {
    pineap_hunter_active = false;
    WiFi.mode(WIFI_STA);
    
    // Clear stats
    pineap_hunter_stats.detected_pineaps.clear();
    pineap_hunter_stats.scan_buffer.clear();
}

// BLE Hunter Implementation
bool is_suspicious_ble_device(const String& name, const String& mac) {
    // Check for suspicious device names
    String upperName = name;
    upperName.toUpperCase();
    
    for (int i = 0; i < suspicious_names_count; i++) {
        if (upperName.indexOf(suspicious_names[i]) != -1) {
            return true;
        }
    }
    
    // Check for RN modules with the prefix 00:06:66 (from CardSkimmer project)
    if (mac.startsWith("00:06:66")) {
        return true;
    }
    
    // Check for suspicious MAC prefixes (known skimmer manufacturers)
    if (mac.startsWith("00:12:") || // Common Chinese BLE modules
        mac.startsWith("20:16:") || // ESP32 common ranges
        mac.startsWith("24:0a:") || // ESP32 common ranges
        mac.startsWith("98:d3:") || // ESP32 common ranges
        mac.startsWith("30:ae:") || // ESP32 common ranges
        mac.startsWith("24:62:")) { // ESP32 common ranges
        return true;
    }
    
    // Check for RNBT pattern (RNBT-xxxx)
    if (name.indexOf("RNBT-") != -1) {
        return true;
    }
    
    // Check for unnamed devices (often suspicious)
    if (name.length() == 0) {
        return true;
    }
    
    return false;
}

void add_unique_ble_device(const String& mac, const String& name, int32_t rssi) {
    // Check if device already exists
    for (auto& device : seen_ble_devices) {
        if (device.mac == mac) {
            device.rssi = rssi; // Update RSSI
            device.last_seen = millis();
            return;
        }
    }
    
    // Add new device if we haven't reached the limit
    if (seen_ble_devices.size() < MAX_BLE_DEVICES) {
        BLEDeviceInfo newDevice;
        newDevice.mac = mac;
        newDevice.name = name;
        newDevice.rssi = rssi;
        newDevice.last_seen = millis();
        newDevice.device_type = "BLE";
        newDevice.is_suspicious = is_suspicious_ble_device(name, mac);
        
        // Log suspicious BLE devices
        if (newDevice.is_suspicious) {
            logThreat("BLE_Threat", name + " (" + mac + ")", rssi, 0);
        }
        
        seen_ble_devices.push_back(newDevice);
        ble_stats.unique_devices = seen_ble_devices.size();
    }
}

void reset_ble_stats_if_needed() {
    uint32_t now = millis();
    if (now - ble_stats.last_reset_time > 10000) { // Reset every 10 seconds
        ble_stats.total_devices = 0;
        ble_stats.rssi_sum = 0;
        ble_stats.rssi_count = 0;
        ble_stats.avg_rssi = -70;
        ble_stats.last_reset_time = now;
        
        // Clean up old devices (older than 15 seconds)
        seen_ble_devices.erase(
            std::remove_if(seen_ble_devices.begin(), seen_ble_devices.end(),
                [now](const BLEDeviceInfo& device) {
                    return (now - device.last_seen) > 15000;
                }),
            seen_ble_devices.end()
        );
        
        ble_stats.unique_devices = seen_ble_devices.size();
    }
}

void BLEHunterCallback::onResult(BLEAdvertisedDevice advertisedDevice) {
    if (!ble_hunter_active) {
        Serial.println("BLE callback triggered but hunter not active");
        return;
    }
    
    // Rate limiting to prevent memory overflow
    static uint32_t last_process = 0;
    uint32_t now = millis();
    if (now - last_process < 100) { // Limit to 10 devices per second
        return;
    }
    last_process = now;
    
    String mac = advertisedDevice.getAddress().toString().c_str();
    String name = advertisedDevice.getName().c_str();
    int32_t rssi = advertisedDevice.getRSSI();
    
    // Always print to serial for debugging
    Serial.printf("*** BLE Device: '%s' [%s] RSSI:%d ***\n", 
                  name.length() > 0 ? name.c_str() : "<no name>", 
                  mac.c_str(), rssi);
    
    // Update statistics
    ble_stats.total_devices++;
    ble_stats.rssi_sum += rssi;
    ble_stats.rssi_count++;
    if (ble_stats.rssi_count > 0) {
        ble_stats.avg_rssi = ble_stats.rssi_sum / ble_stats.rssi_count;
    }
    
    // Add unique device
    add_unique_ble_device(mac, name, rssi);
}

void scan_and_analyze_ble() {
    static uint32_t last_scan = 0;
    uint32_t now = millis();
    
    if (ble_scanner && (now - last_scan > 6000)) { // Start new scan every 6 seconds
        Serial.println("Starting BLE scan...");
        ble_scanner->clearResults();
        ble_scanner->start(BLE_SCAN_TIME, false); // Scan for 5 seconds, don't loop
        last_scan = now;
    }
    
    // Reset stats periodically
    reset_ble_stats_if_needed();
}

void start_ble_monitoring() {
    if (ble_hunter_active) return;
    
    Serial.println("Starting BLE monitoring...");
    
    // Stop WiFi to free up resources for BLE
    if (deauth_hunter_active) {
        stop_deauth_monitoring();
    }
    if (pineap_hunter_active) {
        stop_pineap_monitoring();
    }
    
    // Initialize BLE with proper settings for ESP32-2432S028R
    Serial.println("Initializing BLE Device...");
    BLEDevice::init("AntiPredCYD-Scanner");
    
    // Get BLE scan object
    Serial.println("Getting BLE Scanner...");
    ble_scanner = BLEDevice::getScan();
    
    if (!ble_scanner) {
        Serial.println("ERROR: Failed to get BLE scanner!");
        return;
    }
    
    // Set callback
    Serial.println("Setting BLE callback...");
    ble_scanner->setAdvertisedDeviceCallbacks(new BLEHunterCallback());
    
    // Configure scan settings
    Serial.println("Configuring BLE scan settings...");
    ble_scanner->setActiveScan(true);  // Active scan uses more power but gets more data
    ble_scanner->setInterval(100);     // How often to scan (in 0.625ms units)
    ble_scanner->setWindow(99);        // How long to scan (in 0.625ms units)
    
    // Initialize stats
    ble_stats = BLEStats();
    seen_ble_devices.clear();
    ble_stats.last_reset_time = millis();
    
    ble_hunter_active = true;
    
    // Start first scan immediately
    Serial.println("Starting initial BLE scan...");
    ble_scanner->start(BLE_SCAN_TIME, false);
    Serial.println("BLE Hunter started successfully!");
}

void stop_ble_monitoring() {
    if (!ble_hunter_active) return;
    
    if (ble_scanner) {
        ble_scanner->stop();
        ble_scanner->clearResults();
    }
    BLEDevice::deinit();
    
    ble_hunter_active = false;
    seen_ble_devices.clear();
}

// Shady WiFi Scanner Implementation (Based on ESP32Marauder)

bool is_suspicious_network(const String& ssid, int32_t rssi, wifi_auth_mode_t auth_mode) {
    // Beacon spam often has random/suspicious SSIDs and appears suddenly
    if (rssi > -50) return true; // Much more reasonable threshold for beacon spam
    
    String suspicious_patterns[] = {
        "xfinitywifi", "FREE", "Open", "WiFi", "Internet", "Guest", 
        "Public", "Hotel", "Airport", "Starbucks", "McDonald", 
        "iPhone", "Samsung", "Android", "NETGEAR", "Linksys",
        "Free", "free", "WIFI", "wifi", "Guest", "guest"  // More beacon spam patterns
    };
    
    for (const auto& pattern : suspicious_patterns) {
        if (ssid.indexOf(pattern) != -1) return true;
    }
    
    if (auth_mode == WIFI_AUTH_OPEN) return true; // Open networks
    if (ssid.length() == 0) return true; // Hidden networks
    
    // Detect networks with suspicious names (random chars, numbers only, etc)
    if (ssid.length() > 0) {
        // If SSID is all random-looking (many numbers/special chars)
        int special_chars = 0;
        for (char c : ssid) {
            if (!isalnum(c) && c != '-' && c != '_') special_chars++;
        }
        if (special_chars > 2) return true; // Likely beacon spam with random chars
    }
    
    return false;
}

String get_encryption_type(wifi_auth_mode_t auth_mode) {
    switch (auth_mode) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        default: return "Unknown";
    }
}

String get_suspicion_reason(const String& ssid, int32_t rssi, wifi_auth_mode_t auth_mode) {
    if (rssi > -30) return "Very Strong Signal";
    if (auth_mode == WIFI_AUTH_OPEN) return "Open Network";
    if (ssid.length() == 0) return "Hidden SSID";
    if (ssid.indexOf("FREE") != -1) return "Suspicious Name";
    return "General Suspicion";
}

void scan_and_analyze_shady_wifi() {
    static uint32_t last_wifi_scan = 0;
    uint32_t now = millis();
    
    if (now - last_wifi_scan > 5000) { // Scan every 5 seconds
        Serial.println("Starting synchronous WiFi scan...");
        
        // Use synchronous scan (more reliable like the simple scanner)
        int n = WiFi.scanNetworks(false, true); // sync=false, show_hidden=true
        Serial.printf("WiFi scan finished: %d networks found\n", n);
        
        if (n > 0) {
            detected_shady_networks.clear();
            shady_wifi_stats.total_networks = n;
            shady_wifi_stats.hidden_networks = 0;
            shady_wifi_stats.open_networks = 0;
            shady_wifi_stats.suspicious_networks = 0;
            shady_wifi_stats.strongest_rssi = -100;
            
            for (int i = 0; i < n; i++) {
                String bssid_str = WiFi.BSSIDstr(i);
                String ssid = WiFi.SSID(i);
                int32_t rssi = WiFi.RSSI(i);
                uint8_t channel = WiFi.channel(i);
                wifi_auth_mode_t auth_mode = WiFi.encryptionType(i);
                
                // Debug output
                Serial.printf("%d: '%s' [%s] Ch:%d RSSI:%d Auth:%s\n", 
                             i, ssid.c_str(), bssid_str.c_str(), channel, rssi, 
                             get_encryption_type(auth_mode).c_str());
                
                if (ssid.length() == 0) {
                    shady_wifi_stats.hidden_networks++;
                    Serial.println("  -> Hidden network detected!");
                }
                if (auth_mode == WIFI_AUTH_OPEN) {
                    shady_wifi_stats.open_networks++;
                    Serial.println("  -> Open network detected!");
                }
                
                if (rssi > shady_wifi_stats.strongest_rssi) {
                    shady_wifi_stats.strongest_rssi = rssi;
                    shady_wifi_stats.strongest_network = (ssid.length() > 0) ? ssid : "[Hidden]";
                }
                
                if (is_suspicious_network(ssid, rssi, auth_mode)) {
                    shady_wifi_stats.suspicious_networks++;
                    
                    ShadyNetwork network = {
                        .ssid = (ssid.length() > 0) ? ssid : "[Hidden]",
                        .bssid = bssid_str,
                        .rssi = rssi,
                        .channel = channel,
                        .encryption = get_encryption_type(auth_mode),
                        .is_suspicious = true,
                        .suspicion_reason = get_suspicion_reason(ssid, rssi, auth_mode),
                        .first_seen = now,
                        .last_seen = now
                    };
                    
                    detected_shady_networks.push_back(network);
                    Serial.printf("  -> SUSPICIOUS: %s (Reason: %s)\n", 
                                 network.ssid.c_str(), network.suspicion_reason.c_str());
                    
                    // Log the threat
                    logThreat("WiFi_Threat", network.ssid + " - " + network.suspicion_reason, rssi, channel);
                }
            }
            
            Serial.printf("Scan complete: %d total, %d hidden, %d open, %d suspicious\n", 
                         shady_wifi_stats.total_networks, shady_wifi_stats.hidden_networks,
                         shady_wifi_stats.open_networks, shady_wifi_stats.suspicious_networks);
        } else {
            Serial.println("No WiFi networks found in scan");
        }
        
        WiFi.scanDelete(); // Free memory
        last_wifi_scan = now;
    }
}

void start_shady_wifi_monitoring() {
    // Ensure WiFi is in station mode for scanning (like simple scanner)
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100); // Allow mode to settle
    
    // Initialize stats
    shady_wifi_stats = ShadyWiFiStats();
    shady_wifi_stats.scan_start_time = millis();
    detected_shady_networks.clear();
    
    shady_wifi_scanner_active = true;
    Serial.println("Shady WiFi Scanner started with improved sync scanning");
}

void stop_shady_wifi_monitoring() {
    shady_wifi_scanner_active = false;
    WiFi.mode(WIFI_STA);
    detected_shady_networks.clear();
}

// Credential Harvesting Alert Implementation
static void cred_harvest_sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!cred_harvest_active) return;
    
    wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
    
    // Extract BSSID for tracking
    char bssid_str[18];
    
    if (type == WIFI_PKT_MGMT) {
        uint8_t frame_type = snifferPacket->payload[0];
        
        // Check for deauth (0xC0) or disassoc (0xA0) frames
        if (frame_type == 0xC0 || frame_type == 0xA0) {
            cred_harvest_stats.deauth_count++;
            
            // Extract BSSID (AP address)
            extract_mac(bssid_str, snifferPacket->payload, 16);
            
            // Find or create targeted AP entry
            bool found = false;
            for (auto& ap : targeted_aps) {
                if (ap.bssid == String(bssid_str)) {
                    ap.deauth_count++;
                    ap.last_activity = millis();
                    ap.rssi = snifferPacket->rx_ctrl.rssi;
                    ap.risk_score = calculate_risk_score(ap);
                    found = true;
                    break;
                }
            }
            
            if (!found && targeted_aps.size() < MAX_TRACKED_APS) {
                TargetedAP new_ap(String(bssid_str), "", snifferPacket->rx_ctrl.rssi);
                new_ap.deauth_count = 1;
                new_ap.risk_score = calculate_risk_score(new_ap);
                
                // Log high-risk credential harvesting attempts
                if (new_ap.risk_score >= 7) {
                    logThreat("Credential_Harvesting", "HIGH RISK: " + String(bssid_str), 
                             snifferPacket->rx_ctrl.rssi, snifferPacket->rx_ctrl.channel);
                } else if (new_ap.risk_score >= 4) {
                    logThreat("Credential_Harvesting", "MEDIUM RISK: " + String(bssid_str), 
                             snifferPacket->rx_ctrl.rssi, snifferPacket->rx_ctrl.channel);
                }
                
                targeted_aps.push_back(new_ap);
            }
        }
    } else if (type == WIFI_PKT_DATA) {
        // Check for EAPOL frames (4-way handshake) - simplified detection
        if (snifferPacket->rx_ctrl.sig_len > 50) { // Basic length check
            // Look for EAPOL ethernet type (0x888E) in the data
            for (int i = 0; i < 30 && i < snifferPacket->rx_ctrl.sig_len - 1; i++) {
                if (snifferPacket->payload[i] == 0x88 && snifferPacket->payload[i+1] == 0x8E) {
                    cred_harvest_stats.eapol_count++;
                    
                    // Extract BSSID from data frame
                    extract_mac(bssid_str, snifferPacket->payload, 4);
                    
                    // Update targeted AP with EAPOL activity
                    for (auto& ap : targeted_aps) {
                        if (ap.bssid == String(bssid_str)) {
                            ap.eapol_count++;
                            ap.last_activity = millis();
                            ap.risk_score = calculate_risk_score(ap);
                            break;
                        }
                    }
                    break; // Found EAPOL, stop searching
                }
            }
        }
    }
}

uint32_t calculate_risk_score(const TargetedAP& ap) {
    uint32_t score = 0;
    
    // 🚩 Signal 1: Deauth → Reconnect → EAPOL (CORE DETECTION)
    // This is the strongest indicator of credential harvesting
    if (ap.eapol_count > 0 && ap.deauth_count > 0) {
        score += 5; // Primary harvesting signal
    }
    
    // 🚩 Signal 2: Repeated Handshake Attempts (Multiple EAPOL without reason)
    // Normal: 1 handshake when connecting, Suspicious: 3+ handshakes rapidly
    if (ap.eapol_count > 6) score += 4;      // Very suspicious
    else if (ap.eapol_count > 3) score += 3; // Suspicious
    else if (ap.eapol_count > 1) score += 1; // Slightly suspicious
    
    // 🚩 Signal 3: Deauth Flood (Attack preparation)
    if (ap.deauth_count > 15) score += 3;    // Aggressive flooding
    else if (ap.deauth_count > 8) score += 2; // Moderate flooding  
    else if (ap.deauth_count > 3) score += 1; // Light flooding
    
    // Bonus: Rapid activity (machine-like behavior)
    uint32_t time_window = millis() - ap.last_activity;
    if (time_window < 5000 && (ap.deauth_count > 2 || ap.eapol_count > 1)) {
        score += 1; // Fast attack pattern
    }
    
    return score;
}

void reset_cred_harvest_stats() {
    uint32_t now = millis();
    
    // Remove old entries
    targeted_aps.erase(
        std::remove_if(targeted_aps.begin(), targeted_aps.end(),
            [now](const TargetedAP& ap) {
                return (now - ap.last_activity) > 30000; // Remove entries older than 30 seconds
            }),
        targeted_aps.end()
    );
    
    // Reset global stats
    cred_harvest_stats.deauth_count = 0;
    cred_harvest_stats.eapol_count = 0;
    cred_harvest_stats.targeted_aps = targeted_aps.size();
    cred_harvest_stats.last_reset_time = now;
    
    // Calculate total risk score
    cred_harvest_stats.risk_score = 0;
    for (const auto& ap : targeted_aps) {
        cred_harvest_stats.risk_score += ap.risk_score;
    }
}

void process_cred_harvest_detection() {
    uint32_t now = millis();
    
    // Reset stats periodically
    if (now - cred_harvest_stats.last_reset_time > CRED_HARVEST_RESET_INTERVAL) {
        reset_cred_harvest_stats();
    }
    
    // Update targeted AP count
    cred_harvest_stats.targeted_aps = targeted_aps.size();
}

void start_cred_harvest_monitoring() {
    // Initialize WiFi in promiscuous mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // Set up promiscuous mode
    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&cred_harvest_sniffer_callback);
    
    // Initialize stats
    cred_harvest_stats = CredentialHarvestingStats();
    cred_harvest_stats.scan_start_time = millis();
    cred_harvest_stats.last_reset_time = millis();
    targeted_aps.clear();
    
    cred_harvest_active = true;
    Serial.println("Credential Harvesting Alert started - monitoring for handshake capture attempts");
}

void stop_cred_harvest_monitoring() {
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_STA);
    cred_harvest_active = false;
    targeted_aps.clear();
    Serial.println("Credential Harvesting Alert stopped");
}

// SD Card logging functions
void logThreat(const String& threatType, const String& details, int rssi, int channel) {
    if (!sdCardAvailable) {
        Serial.println("SD Card not available for logging");
        return;
    }
    
    // Create a unique key for this threat
    String threatKey = threatType + ":" + details;
    
    // Only log if this is a new threat
    if (isNewThreat(threatType, details)) {
        File logFile = SD.open(currentLogFile, FILE_APPEND);
        if (logFile) {
            // Format: timestamp,threatType,details,rssi,channel
            logFile.printf("%lu,%s,%s,%d,%d\n", 
                          millis(), 
                          threatType.c_str(), 
                          details.c_str(), 
                          rssi, 
                          channel);
            logFile.close();
            loggedThreats.insert(threatKey);
            Serial.printf("Successfully logged threat: %s - %s\n", threatType.c_str(), details.c_str());
        } else {
            Serial.printf("Failed to open log file: %s\n", currentLogFile.c_str());
        }
    } else {
        Serial.printf("Duplicate threat not logged: %s - %s\n", threatType.c_str(), details.c_str());
    }
}

bool isNewThreat(const String& threatType, const String& details) {
    String threatKey = threatType + ":" + details;
    return loggedThreats.find(threatKey) == loggedThreats.end();
}

// Matrix Screensaver functions
void initMatrixScreensaver() {
    gfx->fillScreen(BLACK);
    matrix_columns.clear();
    
    // Create columns across the screen (every 10 pixels)
    for (int x = 0; x < 320; x += 10) {
        MatrixColumn col;
        col.x = x;
        col.y = random(0, 240);  // Start at random Y position
        col.speed = random(1, 4);  // Different speeds
        
        // Initialize with random characters
        for (int i = 0; i < 12; i++) {
            col.chars[i] = matrix_chars[random(0, strlen(matrix_chars))];
            col.brightness[i] = 255 - (i * 20);  // Fade from bright to dim
        }
        matrix_columns.push_back(col);
    }
    last_matrix_update = millis();
}

void updateMatrixScreensaver() {
    if (millis() - last_matrix_update < MATRIX_UPDATE_INTERVAL) {
        return;
    }
    
    // Clear screen with slight trail effect
    gfx->fillScreen(BLACK);
    
    // Update each column
    for (auto& col : matrix_columns) {
        // Move column down
        col.y += col.speed;
        
        // If column goes off screen, reset at top
        if (col.y > 240 + 120) {  // Add some buffer for trail
            col.y = -120;
            col.speed = random(1, 4);
        }
        
        // Occasionally change characters
        if (random(0, 10) == 0) {
            int pos = random(0, 12);
            col.chars[pos] = matrix_chars[random(0, strlen(matrix_chars))];
        }
        
        // Draw the character trail
        gfx->setTextSize(1);
        for (int i = 0; i < 12; i++) {
            int char_y = col.y - (i * 12);  // 12 pixels between chars
            if (char_y >= 0 && char_y < 240) {
                // Calculate green color intensity
                uint8_t intensity = col.brightness[i];
                if (i == 0) {
                    // Brightest character at the front (white)
                    gfx->setTextColor(RGB565(255, 255, 255));
                } else {
                    // Green trail with fading intensity
                    gfx->setTextColor(RGB565(0, intensity, 0));
                }
                
                gfx->setCursor(col.x, char_y);
                gfx->print(col.chars[i]);
            }
        }
    }
    
    last_matrix_update = millis();
}

// Attack functions for different portal types
void attack_bruce_portal(const String& gateway) {
    WiFiClient client;
    
    // Bruce-style endpoints (192.168.4.1 portals)
    String bruce_endpoints[] = {"/login", "/auth", "/signin", "/portal", "/admin", "/index", "/", "/captive"};
    int num_bruce_endpoints = 8;
    
    for (int attack = 0; attack < 3; attack++) { // 3 attack rounds
        for (int e = 0; e < num_bruce_endpoints; e++) {
            String endpoint = bruce_endpoints[e];
            
            Serial.printf("💥 Bruce attack %d: POST %s%s\n", attack + 1, gateway.c_str(), endpoint.c_str());
            
            if (client.connect(gateway.c_str(), 80)) {
                // Try multiple credential formats for Bruce
                String formats[] = {
                    "username=Caught%20Ya%20Slippin&password=Ya%20Damn%20Fool",
                    "user=Caught%20Ya%20Slippin&pass=Ya%20Damn%20Fool",
                    "email=Caught%20Ya%20Slippin&password=Ya%20Damn%20Fool"
                };
                
                String postData = formats[attack % 3]; // Rotate through formats
                
                client.print("POST " + endpoint + " HTTP/1.1\r\n");
                client.print("Host: " + gateway + "\r\n");
                client.print("Content-Type: application/x-www-form-urlencoded\r\n");
                client.print("Content-Length: " + String(postData.length()) + "\r\n");
                client.print("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n");
                client.print("Accept: text/html,application/xhtml+xml,application/xml\r\n");
                client.print("Referer: http://" + gateway + endpoint + "\r\n");
                client.print("Connection: close\r\n\r\n");
                client.print(postData);
                
                // Brief wait for response
                delay(150);
                client.stop();
                
                Serial.println("   ✅ Bruce attack sent");
            } else {
                Serial.println("   ❌ Connection failed");
            }
            
            delay(100); // Brief delay between endpoints
        }
    }
    
    Serial.printf("🔥 Bruce portal attack complete: %d attacks sent to %s\n", 3 * num_bruce_endpoints, gateway.c_str());
}

void attack_nemo_portal(const String& gateway) {
    WiFiClient client;
    
    // Nemo-style attack (172.0.0.1 portals) - targets /post with email/password
    for (int attack = 0; attack < 10; attack++) { // 10 attack rounds for Nemo
        Serial.printf("💥 Nemo attack %d: POST %s/post with email/password params\n", attack + 1, gateway.c_str());
        
        if (client.connect(gateway.c_str(), 80)) {
            // Use both formats to ensure compatibility
            String postData1 = "email=Caught%20Ya%20Slippin&password=Ya%20Damn%20Fool";
            String postData2 = "username=Caught%20Ya%20Slippin&password=Ya%20Damn%20Fool";
            
            // Send first attack with email/password (Nemo standard)
            client.print("POST /post HTTP/1.1\r\n");
            client.print("Host: " + gateway + "\r\n");
            client.print("Content-Type: application/x-www-form-urlencoded\r\n");
            client.print("Content-Length: " + String(postData1.length()) + "\r\n");
            client.print("User-Agent: Mozilla/5.0\r\n");
            client.print("Accept: text/html,application/xhtml+xml\r\n");
            client.print("Connection: close\r\n\r\n");
            client.print(postData1);
            
            delay(100);
            client.stop();
            
            // Send second attack with username/password (backup)
            if (client.connect(gateway.c_str(), 80)) {
                client.print("POST /post HTTP/1.1\r\n");
                client.print("Host: " + gateway + "\r\n");
                client.print("Content-Type: application/x-www-form-urlencoded\r\n");
                client.print("Content-Length: " + String(postData2.length()) + "\r\n");
                client.print("User-Agent: Mozilla/5.0\r\n");
                client.print("Accept: text/html,application/xhtml+xml\r\n");
                client.print("Connection: close\r\n\r\n");
                client.print(postData2);
                
                delay(100);
                client.stop();
            }
            
            Serial.println("   ✅ Dual Nemo attacks sent (email + username variants)");
        } else {
            Serial.println("   ❌ Connection failed");
        }
        
        delay(500); // Longer delay for Nemo attacks to avoid overwhelming
    }
    
    Serial.printf("🔥 Nemo portal attack complete: 20 attacks sent to %s/post\n", gateway.c_str());
}

// Portal Killer (Countermeasures) Implementation
void start_countermeasures() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // Initialize stats
    portals_found = 0;
    counter_messages_sent = 0;
    last_portal_scan = 0;
    last_counter_message = 0;
    detected_portals.clear();
    
    countermeasures_active = true;
    Serial.println("Countermeasures activated - hunting portals and sending counter-messages");
}

void stop_countermeasures() {
    countermeasures_active = false;
    WiFi.mode(WIFI_STA);
    detected_portals.clear();
    Serial.println("Countermeasures deactivated");
}

void scan_for_portals() {
    uint32_t now = millis();
    
    if (now - last_portal_scan > PORTAL_SCAN_INTERVAL) {
        Serial.println("🔍 Scanning for BOTH Bruce (192.168.4.1) and Nemo (172.0.0.1) portals...");
        
        int n = WiFi.scanNetworks();
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                String ssid = WiFi.SSID(i);
                String bssid = WiFi.BSSIDstr(i);
                int32_t rssi = WiFi.RSSI(i);
                uint8_t channel = WiFi.channel(i);
                wifi_auth_mode_t encType = WiFi.encryptionType(i);
                
                Serial.printf("🔍 Network %d: '%s' [%s] Ch:%d RSSI:%d %s\n", 
                             i+1, ssid.c_str(), bssid.c_str(), channel, rssi,
                             (encType == WIFI_AUTH_OPEN) ? "OPEN" : "ENCRYPTED");
                
                // TARGET ALL OPEN NETWORKS (like EvilBotDef1 aggressive mode)
                if (encType == WIFI_AUTH_OPEN) {
                    // Skip our own networks and known safe ones
                    if (ssid.indexOf("AntiPred") != -1 || ssid.indexOf("defender") != -1) {
                        Serial.println("   SKIPPED (our network)");
                        continue;
                    }
                    
                    // Check if this portal is already detected
                    bool found = false;
                    for (auto& portal : detected_portals) {
                        if (portal.bssid == bssid) {
                            portal.last_seen = now;
                            portal.rssi = rssi;
                            found = true;
                            break;
                        }
                    }
                    
                    if (!found) {
                        PortalInfo portal(ssid, bssid, rssi, channel);
                        portal.is_portal = true;
                        detected_portals.push_back(portal);
                        portals_found++;
                        
                        Serial.printf("🎯 OPEN NETWORK DETECTED: '%s' (%s) Ch:%d - TARGETING!\n", 
                                    ssid.c_str(), bssid.c_str(), channel);
                        
                        // Log the portal detection
                        logThreat("Portal_Detected", ssid + " (" + bssid + ")", rssi, channel);
                    }
                } else {
                    Serial.println("   ENCRYPTED - Safe");
                }
            }
        } else {
            Serial.println("❌ No networks found");
        }
        
        WiFi.scanDelete();
        last_portal_scan = now;
    }
}

void send_counter_messages() {
    uint32_t now = millis();
    
    if (now - last_counter_message > COUNTER_MESSAGE_INTERVAL && !detected_portals.empty()) {
        Serial.println("💥 COUNTER-ATTACKING DETECTED PORTALS!");
        
        // Attack each detected portal with both Bruce and Nemo methods
        for (const auto& portal : detected_portals) {
            Serial.printf("🎯 Attacking portal: '%s' at %s\n", portal.ssid.c_str(), portal.bssid.c_str());
            
            // Connect to the portal to get gateway IP (like EvilBotDef1)
            WiFi.disconnect();
            delay(500);
            
            Serial.printf("🔄 Connecting to '%s'...\n", portal.ssid.c_str());
            WiFi.begin(portal.ssid.c_str(), "");
            
            int attempts = 0;
            while (WiFi.status() != WL_CONNECTED && attempts < 15) {
                delay(1000);
                attempts++;
                Serial.printf("   Connection attempt %d/15\n", attempts);
            }
            
            if (WiFi.status() == WL_CONNECTED) {
                String gateway = WiFi.gatewayIP().toString();
                Serial.printf("✅ Connected! Gateway IP: %s\n", gateway.c_str());
                
                // Attack with BOTH methods based on gateway IP
                if (gateway.startsWith("192.168.4.")) {
                    Serial.println("🎯 Bruce-style portal detected (192.168.4.x) - attacking common endpoints");
                    attack_bruce_portal(gateway);
                } else if (gateway.startsWith("172.0.0.")) {
                    Serial.println("🎯 Nemo-style portal detected (172.0.0.x) - attacking /post endpoint");
                    attack_nemo_portal(gateway);
                } else {
                    Serial.printf("🎯 Unknown portal type (%s) - attacking with BOTH methods\n", gateway.c_str());
                    attack_bruce_portal(gateway);
                    attack_nemo_portal(gateway);
                }
                
                counter_messages_sent += 10; // Count all attack attempts
                
            } else {
                Serial.printf("❌ Failed to connect to '%s'\n", portal.ssid.c_str());
            }
        }
        
        last_counter_message = now;
    }
}

bool is_portal_network(const String& ssid) {
    if (ssid.length() == 0) return false;
    
    String upperSSID = ssid;
    upperSSID.toUpperCase();
    
    for (int i = 0; i < portal_patterns_count; i++) {
        String pattern = String(portal_patterns[i]);
        pattern.toUpperCase();
        
        if (upperSSID.indexOf(pattern) != -1) {
            return true;
        }
    }
    
    return false;
}

void send_counter_beacon(const String& ssid, uint8_t channel) {
    // Set WiFi channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    
    // Create beacon packet
    uint8_t beacon[128];
    memcpy(beacon, counter_beacon_packet, sizeof(counter_beacon_packet));
    
    // Generate random MAC addresses
    for (int i = 10; i < 16; i++) {
        beacon[i] = random(256);        // Source MAC
        beacon[i + 6] = beacon[i];      // Copy to BSSID
    }
    
    // Make MAC locally administered
    beacon[10] = (beacon[10] & 0xFC) | 0x02;
    beacon[16] = (beacon[16] & 0xFC) | 0x02;
    
    // Set SSID
    int ssidLen = min(32, (int)ssid.length());
    beacon[37] = (uint8_t)ssidLen;
    
    // Clear SSID area and set new SSID
    memset(&beacon[38], 0x20, 32);
    for (int i = 0; i < ssidLen; i++) {
        beacon[38 + i] = ssid.c_str()[i];
    }
    
    // Update timestamp
    uint64_t timestamp = micros();
    memcpy(&beacon[24], &timestamp, 8);
    
    // Update channel parameter
    beacon[sizeof(counter_beacon_packet) - 1] = channel;
    
    // Send beacon multiple times for better visibility
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, beacon, sizeof(counter_beacon_packet), false);
        delayMicroseconds(1000);
    }
}

void displayCountermeasures() {
    // Update live display with current stats
    gfx->setTextSize(1);
    gfx->setCursor(20, 120);
    gfx->setTextColor(WHITE, BLACK);
    gfx->printf("Open APs Found: %-3d      ", portals_found);
    
    gfx->setCursor(20, 140);
    gfx->printf("Attacks Sent: %-5d      ", counter_messages_sent);
    
    gfx->setCursor(20, 160);
    gfx->printf("Active Targets: %-2d       ", detected_portals.size());
    
    // Show detected portals with their likely type
    if (!detected_portals.empty()) {
        gfx->setCursor(20, 180);
        gfx->setTextColor(RED, BLACK);
        
        // Show up to 2 most recent portals
        int displayed = 0;
        for (int i = detected_portals.size() - 1; i >= 0 && displayed < 2; i--) {
            const auto& portal = detected_portals[i];
            
            // Truncate SSID if too long
            String displaySSID = portal.ssid;
            if (displaySSID.length() > 15) {
                displaySSID = displaySSID.substring(0, 12) + "...";
            }
            
            gfx->setCursor(20, 180 + displayed * 15);
            gfx->printf("• %s [ATTACKING]", displaySSID.c_str());
            displayed++;
        }
    }
}