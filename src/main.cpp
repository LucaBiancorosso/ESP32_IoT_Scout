
#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>

#include <FS.h>
#include <LittleFS.h>
#include <memory>

//  Build options 


#define USE_OLED   1
#define USE_BLOOM  1   // set 0 to disable Bloom filter


//  Buttons 

#define PIN_BTN_MODE   27   
#define PIN_BTN_ACT    26  

//  OLED (SSD1306 over I2C) 
#if USE_OLED
  #include <Wire.h>
  #include <Adafruit_GFX.h>
  #include <Adafruit_SSD1306.h>
  Adafruit_SSD1306 oled(128, 64, &Wire, -1);
  static bool oled_ok = false;
#endif

//  ESP AP (web dashboard) 
const char* AP_SSID = "ESP-IoT-Scout";
const char* AP_PSK  = "esp32pass";

//  Channels 
#define CHAN_MIN 1
#define CHAN_MAX 13
#define CHAN_DWELL_MS 600
static uint8_t cur_ch = 6;
static bool pin_channel = false;
static uint32_t last_hop_ms = 0;

//  Data limits 
#define SSID_MAX_LEN 32
#define AP_MAX 120
#define EVT_MAX 64
#define EV_RING 128

//  Helpers 
static inline uint32_t nowms(){ return millis(); }
static inline void mac_copy(uint8_t* d, const uint8_t* s){ memcpy(d,s,6); }
static inline bool mac_eq(const uint8_t* a, const uint8_t* b){ for(int i=0;i<6;i++) if(a[i]!=b[i]) return false; return true; }
static inline void mac_str(const uint8_t m[6], char out[18]){ sprintf(out,"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]); }
static bool parse_bssid_str(const String& s, uint8_t out[6]){
  int v[6]; char c;
  if(sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x%c", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5], &c) == 6){
    for(int i=0;i<6;i++) out[i] = (uint8_t)v[i];
    return true;
  }
  return false;
}


//   COMPACT OUI/VENDOR DB

struct VendorMeta { const char* name; const char* cat; uint8_t risk; };
static const VendorMeta VENDORS[] PROGMEM = {
  {"Espressif","MCU/DIY", 5},     // id 0
  {"Tuya",     "SmartPlug",10},   // id 1
  {"TP-Link",  "IoT/Router",7},   // id 2
  {"Shelly",   "Relay",6},        // id 3
  {"Sonoff",   "Relay",6},        // id 4
  {"HP",       "Printer",6},      // id 5
  {"Xiaomi",   "IoT",7},          // id 6
  {"Wyze",     "Camera",8},       // id 7
  {"Ring",     "Camera",8},       // id 8
  {"Broadlink","IR/IoT",7},       // id 9
};
static const uint16_t VENDOR_COUNT = sizeof(VENDORS)/sizeof(VENDORS[0]);

struct OUIEntry { uint32_t oui24; uint16_t vendor_id; };
static const OUIEntry OUI_TABLE[] PROGMEM = {
  // Espressif (examples)
  {0x1869D8, 0}, {0x24A160, 0}, {0x246F28, 0}, {0x30AEA4, 0}, {0x7CDFA1, 0}, {0xBCDDC2, 0},
  // TP-Link
  {0x50C7BF, 2}, {0xF4F26D, 2},
  // HP
  {0x186024, 5}, {0x3CD92B, 5},
  // Shelly (Allterco)
  {0x84CCA8, 3},
  // Xiaomi (examples)
  {0x28E31F, 6}, {0x640980, 6},
  // Broadlink
  {0xB4430D, 9},
};
static const size_t OUI_N = sizeof(OUI_TABLE)/sizeof(OUI_TABLE[0]);

static inline uint32_t pack_oui24(const uint8_t mac[6]){
  return ( (uint32_t)mac[0]<<16 ) | ( (uint32_t)mac[1]<<8 ) | mac[2];
}
static int find_vendor_id_by_oui24(uint32_t k){
  int lo=0, hi=(int)OUI_N-1;
  while(lo<=hi){
    int mid=(lo+hi)>>1;
    OUIEntry e; memcpy_P(&e, &OUI_TABLE[mid], sizeof(e));
    if(k<e.oui24) hi=mid-1;
    else if(k>e.oui24) lo=mid+1;
    else return (int)e.vendor_id;
  }
  return -1;
}

// SSID pattern DB

struct SsidPat { const char* pat; uint16_t vendor_id; bool is_default; };
static const SsidPat SSID_PATS[] PROGMEM = {
  {"SmartLife_*", 1, true},  // Tuya
  {"TuyaSmart_*", 1, true},
  {"ESP_*",       0, false}, // Espressif (DIY)
  {"ESP32_*",     0, false},
  {"DIRECT-*-HP*",5, true},  // HP printers
  {"Tapo_*",      2, true},  // TP-Link Tapo
  {"Shelly*",     3, true},
  {"SONOFF_*",    4, true},
};
static const size_t SSID_PAT_N = sizeof(SSID_PATS)/sizeof(SSID_PATS[0]);

static bool match_pat(const char* s, const char* pat){
  if(!pat) return false;
  const char* star = strchr(pat,'*');
  if(!star) return strcmp(s,pat)==0;
  size_t n = (size_t)(star - pat);
  return strncasecmp(s, pat, n) == 0;
}


//   OVERLAY DB (LittleFS)

struct OverlayEntry {
  uint32_t oui24;
  char     name[16];
  char     cat[16];
  uint8_t  risk;
};
static OverlayEntry overlay[256];
static size_t overlay_n = 0;

static int overlay_find(uint32_t k){
  for(size_t i=0;i<overlay_n;i++) if(overlay[i].oui24==k) return (int)i;
  return -1;
}
static uint8_t hexval(char c){
  if(c>='0'&&c<='9') return c-'0';
  if(c>='A'&&c<='F') return c-'A'+10;
  if(c>='a'&&c<='f') return c-'a'+10;
  return 0xFF;
}
static bool parse_oui24(const String& raw, uint32_t& out){
  String s; s.reserve(8);
  for(size_t i=0;i<raw.length();i++){ char c=raw[i]; if(c==':'||c=='-'||c==' ') continue; s += c; }
  if(s.length()!=6) return false;
  uint8_t b[3];
  for(int i=0;i<3;i++){
    uint8_t h=hexval(s[i*2]), l=hexval(s[i*2+1]);
    if(h==0xFF||l==0xFF) return false;
    b[i]=(h<<4)|l;
  }
  out = ((uint32_t)b[0]<<16)|((uint32_t)b[1]<<8)|b[2];
  return true;
}
static bool load_overlay_from_fs(){
  overlay_n = 0;
  File f = LittleFS.open("/oui.csv", FILE_READ);
  if(!f) return false;
  while(f.available()){
    String line = f.readStringUntil('\n');
    line.trim(); if(line.length()==0 || line[0]=='#') continue;
    int p1=line.indexOf(','), p2=line.indexOf(',', p1+1), p3=line.indexOf(',', p2+1);
    if(p1<0||p2<0) continue;
    String s_oui = line.substring(0,p1);
    String s_name = line.substring(p1+1,p2); s_name.trim();
    String s_cat = (p3>0? line.substring(p2+1,p3) : line.substring(p2+1)); s_cat.trim();
    String s_risk = (p3>0? line.substring(p3+1) : "7"); s_risk.trim();

    uint32_t k; if(!parse_oui24(s_oui, k)) continue;
    if(overlay_n>=sizeof(overlay)/sizeof(overlay[0])) break;
    OverlayEntry &e = overlay[overlay_n++];
    e.oui24 = k;
    s_name.toCharArray(e.name, sizeof(e.name));
    s_cat.toCharArray(e.cat, sizeof(e.cat));
    int r = s_risk.toInt(); if(r<0) r=0; if(r>10) r=10; e.risk = (uint8_t)r;
  }
  f.close();
  return true;
}
static bool save_upload_to_fs(const uint8_t* buf, size_t len){
  File f = LittleFS.open("/oui.csv", FILE_WRITE);
  if(!f) return false;
  size_t w = f.write(buf, len);
  f.close();
  return (w==len);
}


//   BLOOM FILTER (optional)

#if USE_BLOOM
static uint8_t bloom_bits[256]; // 2048 bits
static inline void bloom_clear(){ memset(bloom_bits, 0, sizeof(bloom_bits)); }
static uint32_t h1(uint32_t x){ uint32_t h=2166136261u; for(int i=0;i<3;i++){ uint8_t b=(x>>(16-8*i))&0xFF; h^=b; h*=16777619u; } return h; }
static uint32_t h2(uint32_t x){ x += (x<<12); x ^= (x>>22); x += (x<<4); x ^= (x>>9); x += (x<<10); x ^= (x>>2); x += (x<<7); x ^= (x>>12); return x; }
static void bloom_add(uint32_t v){ uint32_t a=h1(v)%2048, b=h2(v)%2048; bloom_bits[a>>3] |= (1<<(a&7)); bloom_bits[b>>3] |= (1<<(b&7)); }
static bool bloom_maybe(uint32_t v){ uint32_t a=h1(v)%2048, b=h2(v)%2048; return (bloom_bits[a>>3]&(1<<(a&7))) && (bloom_bits[b>>3]&(1<<(b&7))); }
#else
static inline void bloom_clear(){}
static inline void bloom_add(uint32_t){ }
static inline bool bloom_maybe(uint32_t){ return false; }
#endif
static void bloom_seed_base(){
#if USE_BLOOM
  bloom_clear();
  for(size_t i=0;i<OUI_N;i++){ OUIEntry e; memcpy_P(&e, &OUI_TABLE[i], sizeof(e)); bloom_add(e.oui24); }
  for(size_t i=0;i<overlay_n;i++) bloom_add(overlay[i].oui24);
#endif
}


//   SSID patterns → vendor id

static bool ssid_to_vendor(const char* ssid, uint16_t &vendor_id, bool &is_default){
  for(size_t i=0;i<SSID_PAT_N;i++){
    SsidPat p; memcpy_P(&p, &SSID_PATS[i], sizeof(p));
    if(match_pat(ssid, p.pat)){ vendor_id = p.vendor_id; is_default = p.is_default; return true; }
  }
  return false;
}


//   EXCLUDE LIST (SSID / BSSID)

struct ExSsid { char pat[SSID_MAX_LEN+1]; };   // supports '*' wildcard
struct ExBssid{ uint8_t mac[6]; };

static ExSsid  ex_ssid[64];
static size_t  ex_ssid_n = 0;
static ExBssid ex_bssid[64];
static size_t  ex_bssid_n = 0;

static bool wildmatch_ci(const char* s, const char* pat){ // '*' any, case-insensitive
  const char *sp=nullptr, *pp=nullptr;
  while(*s){
    if(*pat=='*'){ pp=++pat; sp=s; continue; }
    if(tolower((unsigned char)*pat)==tolower((unsigned char)*s)){ pat++; s++; continue; }
    if(pp){ pat=pp; s=++sp; continue; }
    return false;
  }
  while(*pat=='*') pat++;
  return *pat==0;
}
static void ex_clear(){ ex_ssid_n=0; ex_bssid_n=0; }
static bool ex_add_ssid(const String& pat){
  if(ex_ssid_n>=sizeof(ex_ssid)/sizeof(ex_ssid[0])) return false;
  String t = pat; t.trim();
  t.toCharArray(ex_ssid[ex_ssid_n].pat, sizeof(ex_ssid[0].pat));
  ex_ssid_n++; return true;
}
static bool ex_add_bssid_str(const String& s){
  if(ex_bssid_n>=sizeof(ex_bssid)/sizeof(ex_bssid[0])) return false;
  uint8_t m[6]; if(!parse_bssid_str(s, m)) return false;
  memcpy(ex_bssid[ex_bssid_n].mac, m, 6); ex_bssid_n++; return true;
}
static bool ex_load_file(){
  ex_clear();
  File f = LittleFS.open("/exclude.txt", FILE_READ);
  if(!f) return false;
  while(f.available()){
    String line = f.readStringUntil('\n'); line.trim();
    if(line.length()==0 || line[0]=='#') continue;
    if(line.startsWith("SSID:")){
      ex_add_ssid(line.substring(5));
    } else if(line.startsWith("BSSID:")){
      ex_add_bssid_str(line.substring(6));
    }
  }
  f.close();
  return true;
}
static bool ex_save_all(){ // rewrite file from RAM
  File f = LittleFS.open("/exclude.txt", FILE_WRITE);
  if(!f) return false;
  for(size_t i=0;i<ex_ssid_n;i++){
    f.print("SSID:"); f.println(ex_ssid[i].pat);
  }
  for(size_t i=0;i<ex_bssid_n;i++){
    char b[18]; mac_str(ex_bssid[i].mac,b);
    f.print("BSSID:"); f.println(b);
  }
  f.close();
  return true;
}
static bool ex_remove_ssid(const String& pat){
  for(size_t i=0;i<ex_ssid_n;i++){
    if(strcasecmp(ex_ssid[i].pat, pat.c_str())==0){
      for(size_t j=i+1;j<ex_ssid_n;j++) ex_ssid[j-1]=ex_ssid[j];
      ex_ssid_n--; return true;
    }
  }
  return false;
}
static bool ex_remove_bssid(const String& s){
  uint8_t m[6]; if(!parse_bssid_str(s,m)) return false;
  for(size_t i=0;i<ex_bssid_n;i++){
    if(mac_eq(ex_bssid[i].mac,m)){
      for(size_t j=i+1;j<ex_bssid_n;j++) ex_bssid[j-1]=ex_bssid[j];
      ex_bssid_n--; return true;
    }
  }
  return false;
}
static bool ex_match_ap(const char* ssid, const uint8_t bssid[6]){
  for(size_t i=0;i<ex_bssid_n;i++){
    if(mac_eq(ex_bssid[i].mac, bssid)) return true;
  }
  if(ssid && *ssid){
    for(size_t i=0;i<ex_ssid_n;i++){
      if(wildmatch_ci(ssid, ex_ssid[i].pat)) return true;
    }
  }
  return false;
}


//   Live AP model + scoring + anomalies

struct AP {
  uint8_t  bssid[6];
  char     ssid[SSID_MAX_LEN+1];
  uint8_t  ch;
  int8_t   rssi_ewma;
  uint32_t last_ms;

  bool open=false, wep=false, wpa=false, wpa2=false, wpa3=false;

  // derived
  char vendor[16];
  char category[16];
  bool default_ssid=false;
  uint8_t risk_vendor=0;
  bool likely_iot=false;

  uint8_t risk_score=0;
  bool excluded=false;

  // baselines / anomaly tracking
  bool     base_set=false;
  bool     base_open=false, base_wep=false, base_wpa=false, base_wpa2=false, base_wpa3=false;
  uint8_t  base_ch=0;
  uint16_t base_bi=0; // beacon interval TU

  // anomalies flags
  bool an_down=false;
  bool an_chan=false;
  bool an_evil=false;
  uint32_t last_an_down_ms=0;
  uint32_t last_an_chan_ms=0;
  uint32_t last_an_evil_ms=0;
};

static AP aps[AP_MAX];
static size_t n_aps = 0;

struct EventItem { uint32_t ts; char msg[64]; };
static EventItem evts[EVT_MAX];
static size_t evt_n=0;

static void push_evt(const char* fmt, ...){
  char buf[64];
  va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
  if(evt_n < EVT_MAX){
    evts[evt_n].ts = nowms();
    strncpy(evts[evt_n].msg, buf, sizeof(evts[evt_n].msg)-1);
    evts[evt_n].msg[sizeof(evts[evt_n].msg)-1]=0;
    evt_n++;
  } else {
    for(size_t i=1;i<EVT_MAX;i++) evts[i-1]=evts[i];
    evts[EVT_MAX-1].ts = nowms();
    strncpy(evts[EVT_MAX-1].msg, buf, sizeof(evts[EVT_MAX-1].msg)-1);
    evts[EVT_MAX-1].msg[sizeof(evts[EVT_MAX-1].msg)-1]=0;
  }
}

static AP* ap_find(const uint8_t bssid[6]){
  for(size_t i=0;i<n_aps;i++) if(mac_eq(aps[i].bssid,bssid)) return &aps[i];
  return nullptr;
}
static AP* ap_touch(const uint8_t bssid[6]){
  if(AP* a = ap_find(bssid)) return a;
  if(n_aps >= AP_MAX) return nullptr;
  AP &a = aps[n_aps++];
  mac_copy(a.bssid,bssid);
  a.ssid[0]=0;
  a.ch=0; a.rssi_ewma=-127; a.last_ms=nowms();
  a.vendor[0]=0; a.category[0]=0; a.default_ssid=false; a.risk_vendor=0; a.likely_iot=false;
  a.risk_score=0; a.excluded=false;
  a.base_set=false; a.an_down=false; a.an_chan=false; a.an_evil=false;
  return &a;
}
static void set_security(AP& a, bool privacy, bool has_wpa, bool has_rsn, bool has_sae){
  a.open = (!privacy && !has_wpa && !has_rsn);
  a.wep  = (privacy && !has_wpa && !has_rsn);
  a.wpa  = has_wpa;
  a.wpa2 = (has_rsn && !has_sae);
  a.wpa3 = (has_rsn && has_sae);
}
static void derive_vendor(AP& a){
  uint32_t k = pack_oui24(a.bssid);
  int vid = find_vendor_id_by_oui24(k);
  if(vid >= 0){
    VendorMeta m; memcpy_P(&m, &VENDORS[vid], sizeof(m));
    strncpy(a.vendor, m.name, sizeof(a.vendor)-1);
    strncpy(a.category, m.cat, sizeof(a.category)-1);
    a.risk_vendor = m.risk;
  }
  int ox = overlay_find(k);
  if(ox >= 0){
    strncpy(a.vendor, overlay[ox].name, sizeof(a.vendor)-1);
    strncpy(a.category, overlay[ox].cat, sizeof(a.category)-1);
    a.risk_vendor = overlay[ox].risk;
  }
  uint16_t ssid_vid=0; bool is_def=false;
  if(a.ssid[0] && ssid_to_vendor(a.ssid, ssid_vid, is_def)){
    VendorMeta m; memcpy_P(&m, &VENDORS[ssid_vid], sizeof(m));
    if(a.vendor[0]==0){
      strncpy(a.vendor, m.name, sizeof(a.vendor)-1);
      strncpy(a.category, m.cat, sizeof(a.category)-1);
      a.risk_vendor = m.risk;
    }
    if(is_def) a.default_ssid = true;
  }
  a.likely_iot = bloom_maybe(k);
}
static uint8_t score_ap(const AP& a){
  int s=0;
  if(a.open) s+=40;
  else if(a.wep) s+=30;
  else if(a.wpa) s+=15;
  else if(a.wpa3) s-=5;

  if(a.default_ssid) s+=20;
  s += a.risk_vendor;
  if(!a.ssid[0]) s+=5; // hidden

  if(a.vendor[0]==0 && a.likely_iot) s+=5;

  // anomaly bumps (small)
  if(a.an_down) s+=10;
  if(a.an_evil) s+=10;
  if(a.an_chan) s+=5;

  if(s<0) s=0; if(s>100) s=100;
  return (uint8_t)s;
}


//   Sniffer (mgmt frames)

struct Ev {
  uint8_t subtype, ch; int8_t rssi;
  uint8_t sa[6], bssid[6];
  char ssid[SSID_MAX_LEN+1];
  bool privacy, has_wpa, has_rsn, has_sae;
  uint16_t bi; // beacon interval TU
};
static Ev evring[EV_RING];
static volatile uint8_t widx=0;
static uint8_t ridx=0;
static volatile uint32_t g_mgmt=0, g_beacon=0, g_probersp=0;

static void parse_mgmt(const wifi_promiscuous_pkt_t* ppkt){
  const uint8_t* f = ppkt->payload;
  int len = ppkt->rx_ctrl.sig_len;
  if(len < 36) return;

  uint8_t fc0 = f[0];
  if(((fc0>>2)&0x3)!=0) return; // only mgmt
  uint8_t subtype = (fc0>>4)&0x0F;
  if(!(subtype==8 || subtype==5)) return; // Beacon=8, ProbeResp=5

  g_mgmt++; if(subtype==8) g_beacon++; else g_probersp++;

  const uint8_t* addr3 = f+16; // BSSID
  uint8_t bssid[6]; mac_copy(bssid, addr3);

  // fixed params: timestamp(8), beacon interval(2), capability(2)
  if(len < 24+12) return;
  uint16_t bi = f[24+8] | (f[24+9]<<8);
  uint16_t cap = f[24+10] | (f[24+11]<<8);
  bool privacy = (cap & 0x0010);

  int pos=24+12;
  uint8_t ch = ppkt->rx_ctrl.channel;
  int8_t  rssi = ppkt->rx_ctrl.rssi;

  bool has_wpa=false, has_rsn=false, has_sae=false;
  char ssid[SSID_MAX_LEN+1]; ssid[0]=0;

  while(pos+2<=len){
    uint8_t id=f[pos++]; if(pos>=len) break;
    uint8_t ilen=f[pos++]; if(pos+ilen>len) break;
    if(id==0){ int c = (ilen>SSID_MAX_LEN?SSID_MAX_LEN:ilen); memcpy(ssid,&f[pos],c); ssid[c]=0; }
    else if(id==3){ if(ilen>=1) ch = f[pos]; }
    else if(id==48){ // RSN
      has_rsn = true;
      for(int i=0;i+3<ilen;i++){
        if(f[pos+i]==0x00 && f[pos+i+1]==0x0F && f[pos+i+2]==0xAC && f[pos+i+3]==0x08){ has_sae=true; break; }
      }
    } else if(id==221 && ilen>=4){
      if(f[pos]==0x00 && f[pos+1]==0x50 && f[pos+2]==0xF2 && f[pos+3]==0x01) has_wpa=true;
    }
    pos += ilen;
  }

  uint8_t w = widx;
  Ev &e = evring[w];
  e.subtype=subtype; e.ch=ch; e.rssi=rssi; e.bi=bi;
  memset(e.sa,0,6); mac_copy(e.bssid,bssid);
  if(ssid[0]){ strncpy(e.ssid, ssid, SSID_MAX_LEN); e.ssid[SSID_MAX_LEN]=0; } else e.ssid[0]=0;
  e.privacy=privacy; e.has_wpa=has_wpa; e.has_rsn=has_rsn; e.has_sae=has_sae;
  widx = (uint8_t)((w+1)%EV_RING);
}
extern "C" void sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type){
  if(type==WIFI_PKT_MGMT) parse_mgmt((wifi_promiscuous_pkt_t*)buf);
}


//   Locate mode (state + helpers)

static bool     locate_mode = false;
static uint8_t  locate_bssid[6] = {0};
static uint8_t  locate_ch = 0;
static int8_t   locate_rssi_fast = -127;
static uint32_t locate_last_ms = 0;

static AP* pick_top_ap(){
  if(n_aps==0) return nullptr;
  AP* best = nullptr;
  for(size_t i=0;i<n_aps;i++){
    AP* x=&aps[i];
    if(x->excluded) continue;
    if(!best || x->risk_score > best->risk_score ||
       (x->risk_score == best->risk_score && x->rssi_ewma > best->rssi_ewma)){
      best = x;
    }
  }
  return best;
}
static void start_locate_for(const AP* a){
  if(!a) return;
  memcpy(locate_bssid, a->bssid, 6);
  locate_ch = a->ch ? a->ch : cur_ch;
  locate_rssi_fast = -127;
  locate_mode = true;
  pin_channel = true; cur_ch = locate_ch;
  esp_wifi_set_channel(cur_ch, WIFI_SECOND_CHAN_NONE);
  char b[18]; mac_str(locate_bssid,b);
  push_evt("Locate ON %s ch%u (btn)", b, locate_ch);
}


//   Buttons + channel hop

static bool rdBtn(uint8_t pin){ return digitalRead(pin)==LOW; }
static bool prev_mode=false, prev_act=false;
static uint32_t act_down_ms=0;

static void handle_buttons(){
  bool m = rdBtn(PIN_BTN_MODE);
  bool a = rdBtn(PIN_BTN_ACT);
  uint32_t t = nowms();

  if(m && !prev_mode){
    pin_channel = !pin_channel;
    push_evt(pin_channel ? "Pinned channel" : "Sweeping channels");
  }

  if(!prev_act && a){ act_down_ms = t; }
  if(prev_act && !a){
    uint32_t dur = t - act_down_ms;
    if(dur >= 1200){
      static uint8_t pinned = 1;
      pinned = (pinned==1?6:(pinned==6?11:1));
      cur_ch = pinned; pin_channel = true;
      esp_wifi_set_channel(cur_ch, WIFI_SECOND_CHAN_NONE);
      push_evt("Pinned ch -> %u", cur_ch);
    } else {
      if(locate_mode){
        locate_mode = false;
        push_evt("Locate OFF (button)");
      } else {
        AP* top = pick_top_ap();
        if(top) start_locate_for(top);
        else { n_aps=0; evt_n=0; push_evt("Tables cleared"); }
      }
    }
  }

  prev_mode = m; prev_act = a;
}

static void hop_channel(){
  if(pin_channel) return;
  uint32_t t=nowms();
  if(t - last_hop_ms >= CHAN_DWELL_MS){
    cur_ch++; if(cur_ch>CHAN_MAX) cur_ch=CHAN_MIN;
    esp_wifi_set_channel(cur_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms=t;
  }
}


//   Web server + dashboard

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

static const char INDEX_HTML[] PROGMEM = R"html(
<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>ESP IoT Scout</title>
<style>
body{margin:0;background:#0e0f10;color:#e6e6e6;font:14px system-ui,Arial}
header{position:sticky;top:0;background:#15171a;padding:8px 12px;display:flex;gap:12px;align-items:center}
h3{margin:8px 0}
.btn{background:#272b30;color:#fff;border:0;border-radius:6px;padding:6px 10px;cursor:pointer}
.card{background:#16181b;border-radius:10px;padding:12px;margin:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:4px 6px;border-bottom:1px solid #262a2e}
th{position:sticky;top:0;background:#16181b}
.bad{color:#ff6b6b}.warn{color:#f5c85a}.ok{color:#7bdc86}
.small{opacity:.7}
.tag{padding:2px 6px;border:1px solid #444;border-radius:6px;margin-right:4px;font-size:11px}
</style>
<header>
  <b>ESP IoT Scout</b>
  <span id=stat class=small>connecting…</span>
  <span style="margin-left:auto">
    <button class=btn onclick="fetch('/api/pin',{method:'POST'})">Pin/Sweep</button>
    <button class=btn onclick="fetch('/api/reset',{method:'POST'})">Reset</button>
    <button class=btn onclick="fetch('/api/locate',{method:'POST'})">Stop Locate</button>
    <a class=btn href="/db">DB</a>
  </span>
</header>
<div class="grid">
  <div class=card>
    <h3>Status</h3>
    <div id=info class=small></div>
  </div>
  <div class=card>
    <h3>Top Risk Devices</h3>
    <table id=tbl><thead><tr><th>Score<th>SSID<th>BSSID<th>Ch<th>RSSI<th>Sec<th>Vendor<th>Anom<th>Tools</thead><tbody></tbody></table>
  </div>
  <div class=card>
    <h3>Events</h3>
    <ul id=ev style="margin:0;padding-left:16px"></ul>
  </div>
</div>
<script>
let ws; function age(ts){return Math.floor((Date.now()-ts)/1000)+'s';}
function badge(n){return n>=60?'<span class=bad>'+n+'</span>':n>=30?'<span class=warn>'+n+'</span>':'<span class=ok>'+n+'</span>'}
function sec(o){return o.wpa3?'WPA3':o.wpa2?'WPA2':o.wpa?'WPA':o.wep?'WEP':'OPEN'}
function anom(o){
  const tags=[];
  if(o.an && o.an.length){
    for(const t of o.an){ tags.push('<span class=tag>'+t+'</span>'); }
  }
  return tags.join('');
}
function connect(){
  ws=new WebSocket('ws://'+location.host+'/ws');
  ws.onopen=()=>document.getElementById('stat').textContent='connected';
  ws.onclose=()=>{document.getElementById('stat').textContent='reconnecting…'; setTimeout(connect,1000);}
  ws.onmessage=(e)=>{
    const d=JSON.parse(e.data);
    const db = d.stat.db ? (' | DB: overlay '+d.stat.db.overlay+' | base '+d.stat.db.base_ouis) : '';
    const loc = d.stat.locate ? (' | LOC '+d.stat.loc_bssid+' ch'+d.stat.loc_ch+' RSSI '+d.stat.loc_rssi) : '';
    const exc = d.stat.exclude ? (' | EXC '+d.stat.exclude) : '';
    document.getElementById('info').innerHTML = 'CH '+d.stat.ch+' | mgmt '+d.stat.mgmt+' | aps '+d.stat.aps+' | '+(d.stat.pinned?'PINNED':'SWEEPING')+db+loc+exc;
    const tb=document.querySelector('#tbl tbody'); tb.innerHTML='';
    d.devices.sort((a,b)=>b.score-a.score).slice(0,60).forEach(x=>{
      const tr=document.createElement('tr');
      tr.innerHTML=
        '<td>'+badge(x.score)+
        '<td>'+x.ssid+
        '<td class=small>'+x.bssid+
        '<td>'+x.ch+
        '<td>'+x.rssi+
        '<td>'+sec(x)+
        '<td>'+x.vendor+
        '<td>'+anom(x)+
        '<td><button class=btn onclick="fetch(\'/api/locate?bssid='+x.bssid+'&ch='+x.ch+'\',{method:\'POST\'})">Locate</button>';
      tb.appendChild(tr);
    });
    const ev=document.getElementById('ev'); ev.innerHTML='';
    d.events.slice(-30).forEach(evx=>{
      const li=document.createElement('li'); li.textContent=evx.msg+' - '+age(evx.ts); ev.appendChild(li);
    });
  };
}
connect();
</script>
)html";

static const char DB_HTML[] PROGMEM = R"html(
<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>IoT DB</title>
<style>body{font:14px system-ui;margin:20px}input,button{font:14px}</style>
<h2>Upload OUI CSV</h2>
<p>Format: <code>OUI,name,category,risk</code> e.g. <code>24:6F:28,Espressif,MCU/DIY,5</code></p>
<form id=f enctype="multipart/form-data" method="post" action="/api/oui-upload">
  <input type="file" name="file" accept=".csv,text/csv" required>
  <button type="submit">Upload</button>
</form>
<p><button onclick="fetch('/api/oui-clear',{method:'POST'}).then(()=>location.reload())">Clear overlay</button>
   <button onclick="fetch('/api/db-info').then(r=>r.json()).then(j=>alert(JSON.stringify(j,null,2)))">DB info</button></p>
)html";

void on_ws_event(AsyncWebSocket*, AsyncWebSocketClient*, AwsEventType, void*, uint8_t*, size_t){}

// ---------- SNAPSHOT ----------
static void append_anoms(const struct AP& a, JsonArray& arr){
  if(a.an_down) arr.add("DOWN");
  if(a.an_chan) arr.add("CHAN");
  if(a.an_evil) arr.add("EVIL");
}

static void send_snapshot(){
  JsonDocument doc;

  JsonObject stat = doc["stat"].to<JsonObject>();
  stat["ch"] = cur_ch;
  stat["mgmt"] = (uint32_t)g_mgmt;
  stat["aps"] = (uint32_t)n_aps;
  stat["pinned"] = pin_channel;
  stat["exclude"] = (uint32_t)(ex_ssid_n + ex_bssid_n);

  if(locate_mode){
    char b[18]; mac_str(locate_bssid,b);
    stat["locate"] = true;
    stat["loc_bssid"] = b;
    stat["loc_ch"] = locate_ch;
    stat["loc_rssi"] = locate_rssi_fast;
  } else {
    stat["locate"] = false;
  }

  JsonObject db = stat["db"].to<JsonObject>();
  db["overlay"]   = (uint32_t)overlay_n;
  db["bloom"]     = (uint32_t)(USE_BLOOM ? 2048 : 0);
  db["base_ouis"] = (uint32_t)OUI_N;

  JsonArray arr = doc["devices"].to<JsonArray>();
  for(size_t i=0;i<n_aps;i++){
    const AP& a = aps[i];
    if(a.excluded) continue; // hide excluded
    JsonObject o = arr.add<JsonObject>();
    char b[18]; mac_str(a.bssid,b);
    o["bssid"]=b; o["ssid"]= (a.ssid[0] ? a.ssid : "<hidden>"); o["ch"]=a.ch; o["rssi"]=a.rssi_ewma;
    o["open"]=a.open; o["wep"]=a.wep; o["wpa"]=a.wpa; o["wpa2"]=a.wpa2; o["wpa3"]=a.wpa3;
    o["vendor"]=a.vendor; o["cat"]=a.category; o["default"]=a.default_ssid;
    o["likely"]=a.likely_iot;
    o["score"]=a.risk_score;
    o["ts"]=a.last_ms;
    JsonArray an = o["an"].to<JsonArray>(); append_anoms(a, an);
  }

  JsonArray ev = doc["events"].to<JsonArray>();
  for(size_t i=0;i<evt_n;i++){
    JsonObject e = ev.add<JsonObject>();
    e["ts"]=evts[i].ts; e["msg"]=evts[i].msg;
  }

  String out; serializeJson(doc, out);
  ws.textAll(out);
}

//  HTTP 
static void setup_http(){
  ws.onEvent(on_ws_event);
  server.addHandler(&ws);

  server.on("/", HTTP_GET, [](AsyncWebServerRequest* req){
    req->send_P(200, "text/html", INDEX_HTML);
  });
  server.on("/db", HTTP_GET, [](AsyncWebServerRequest* req){
    req->send_P(200, "text/html", DB_HTML);
  });

  server.on("/api/reset", HTTP_POST, [](AsyncWebServerRequest* req){
    n_aps=0; evt_n=0; req->send(200, "text/plain", "OK"); push_evt("Tables cleared (HTTP)");
  });
  server.on("/api/pin", HTTP_POST, [](AsyncWebServerRequest* req){
    pin_channel = !pin_channel;
    req->send(200, "text/plain", pin_channel ? "PIN" : "SWEEP");
    push_evt(pin_channel ? "Pinned (HTTP)" : "Sweeping (HTTP)");
  });

  // DB info
  server.on("/api/db-info", HTTP_GET, [](AsyncWebServerRequest* req){
    JsonDocument d;
    d["overlay"]   = (uint32_t)overlay_n;
    d["base_ouis"] = (uint32_t)OUI_N;
    d["bloom_bits"]= (uint32_t)(USE_BLOOM? 2048:0);
    d["exclude"]   = (uint32_t)(ex_ssid_n + ex_bssid_n);
    String out; serializeJson(d,out);
    req->send(200,"application/json",out);
  });

  // Locate via API
  server.on("/api/locate", HTTP_POST, [](AsyncWebServerRequest* req){
    auto getP=[&](const char* k)->String{
      if(req->hasParam(k,true)) return req->getParam(k,true)->value();
      if(req->hasParam(k,false)) return req->getParam(k,false)->value();
      return String();
    };
    String sb = getP("bssid");
    String sc = getP("ch");
    if(sb.length() && sc.length()){
      uint8_t bb[6]; if(!parse_bssid_str(sb, bb)){ req->send(400,"text/plain","bad bssid"); return; }
      int ch = sc.toInt(); if(ch<1||ch>13){ req->send(400,"text/plain","bad channel"); return; }
      memcpy(locate_bssid, bb, 6);
      locate_ch = (uint8_t)ch;
      locate_rssi_fast = -127;
      locate_mode = true;
      pin_channel = true; cur_ch = locate_ch;
      esp_wifi_set_channel(cur_ch, WIFI_SECOND_CHAN_NONE);
      push_evt("Locate ON %s ch%u", sb.c_str(), locate_ch);
      req->send(200, "text/plain", "LOCATE ON");
    } else {
      locate_mode = false;
      push_evt("Locate OFF");
      req->send(200, "text/plain", "LOCATE OFF");
    }
  });

  // OUI upload
  server.on(
    "/api/oui-upload", HTTP_POST,
    [](AsyncWebServerRequest* req){ /* onRequest */ },
    [](AsyncWebServerRequest* req, String, size_t index, uint8_t *data, size_t len, bool final){
      static std::unique_ptr<uint8_t[]> buf;
      static size_t total=0;
      if(index==0){ buf.reset(); total=0; }
      if(!buf) buf.reset(new uint8_t[64*1024]);
      if(total+len <= 64*1024){ memcpy(buf.get()+total, data, len); total += len; }
      if(final){
        bool ok=false;
        if(total>0) ok = save_upload_to_fs(buf.get(), total);
        if(ok){
          load_overlay_from_fs();
          bloom_seed_base();
          push_evt("Overlay loaded: %u entries", (unsigned)overlay_n);
          req->send(200, "text/plain", "OK");
        } else req->send(500, "text/plain", "Save failed");
        buf.reset(); total=0;
      }
    }
  );

  server.on("/api/oui-clear", HTTP_POST, [](AsyncWebServerRequest* req){
    LittleFS.remove("/oui.csv");
    overlay_n=0;
    bloom_seed_base();
    req->send(200,"text/plain","Cleared");
    push_evt("Overlay cleared");
  });

  //  EXCLUDE endpoints (accept body or query) 
  server.on("/api/exclude", HTTP_GET, [](AsyncWebServerRequest* req){
    JsonDocument d;
    JsonArray ss = d["ssid"].to<JsonArray>();
    for(size_t i=0;i<ex_ssid_n;i++) ss.add(ex_ssid[i].pat);
    JsonArray bs = d["bssid"].to<JsonArray>();
    for(size_t i=0;i<ex_bssid_n;i++){ char b[18]; mac_str(ex_bssid[i].mac,b); bs.add(b); }
    String out; serializeJson(d,out);
    req->send(200,"application/json",out);
  });

  server.on("/api/exclude-add", HTTP_POST, [](AsyncWebServerRequest* req){
    auto getParamAny = [&](const char* key)->String{
      if (req->hasParam(key, true))  return req->getParam(key, true)->value();
      if (req->hasParam(key, false)) return req->getParam(key, false)->value();
      return String();
    };
    String ssid = getParamAny("ssid");
    String bssi = getParamAny("bssid");
    bool ok=false; String what;
    if (ssid.length()){ ok = ex_add_ssid(ssid); what = "SSID:" + ssid; }
    else if (bssi.length()){ ok = ex_add_bssid_str(bssi); what = "BSSID:" + bssi; }
    else { req->send(400,"text/plain","need ssid or bssid"); return; }
    if (ok && ex_save_all()){ push_evt("Exclude add %s", what.c_str()); req->send(200,"text/plain","OK"); }
    else req->send(500,"text/plain","ERR");
  });

  server.on("/api/exclude-del", HTTP_POST, [](AsyncWebServerRequest* req){
    auto getParamAny = [&](const char* key)->String{
      if (req->hasParam(key, true))  return req->getParam(key, true)->value();
      if (req->hasParam(key, false)) return req->getParam(key, false)->value();
      return String();
    };
    String ssid = getParamAny("ssid");
    String bssi = getParamAny("bssid");
    bool ok=false; String what;
    if (ssid.length()){ ok = ex_remove_ssid(ssid); what = "SSID:" + ssid; }
    else if (bssi.length()){ ok = ex_remove_bssid(bssi); what = "BSSID:" + bssi; }
    else { req->send(400,"text/plain","need ssid or bssid"); return; }
    if (ok && ex_save_all()){ push_evt("Exclude del %s", what.c_str()); req->send(200,"text/plain","OK"); }
    else req->send(404,"text/plain","Not found");
  });

  server.on("/api/exclude-clear", HTTP_POST, [](AsyncWebServerRequest* req){
    ex_clear(); LittleFS.remove("/exclude.txt"); ex_save_all();
    push_evt("Exclude list cleared");
    req->send(200,"text/plain","Cleared");
  });

  server.begin();
}


//   OLED status

static void oled_status(){
#if USE_OLED
  if(!oled_ok) return;

  oled.clearDisplay();
  oled.setTextSize(1); oled.setTextColor(SSD1306_WHITE);

  if(locate_mode){
    oled.setCursor(0,0);
    char b[18]; mac_str(locate_bssid,b);
    oled.printf("LOC ch:%u  %s\n", locate_ch, b);

    int r = locate_rssi_fast;
    int pct = (r + 90) * 100 / 60;
    if(pct<0) pct=0; if(pct>100) pct=100;

    oled.setCursor(0,16); oled.printf("RSSI: %d dBm\n", r);
    int w = (pct * 120) / 100;
    oled.drawRect(0, 32, 120, 12, SSD1306_WHITE);
    if(w>0) oled.fillRect(1, 33, (w>118?118:w), 10, SSD1306_WHITE);

    oled.setCursor(0,48);
    uint32_t age = nowms() - locate_last_ms;
    oled.printf("age:%lums", (unsigned long)age);
    oled.display();
    return;
  }

  // Pick top non-excluded AP for OLED preview
  uint8_t top_score = 0; int top_idx=-1;
  for(size_t i=0;i<n_aps;i++){
    if(aps[i].excluded) continue;
    if(aps[i].risk_score>top_score){ top_score=aps[i].risk_score; top_idx=(int)i; }
  }

  oled.setCursor(0,0);
  oled.printf("CH:%u %s  AP:%u\n", cur_ch, pin_channel?"PIN":"SWP", (unsigned)n_aps);

  oled.setCursor(0,16);
  if(top_idx>=0){
    const char* name = aps[top_idx].ssid[0] ? aps[top_idx].ssid : "<hidden>";
    char ss[17]; strncpy(ss, name, 16); ss[16]=0;
    oled.printf("Top:%3u\n", aps[top_idx].risk_score);
    oled.printf("%.16s\n", ss);
  } else {
    oled.println("Top: ---");
    oled.println("(no APs yet)");
  }

  oled.setCursor(0,48);
  oled.printf("mgmt:%lu DB:%u EXC:%u\n", (unsigned long)g_mgmt, (unsigned)overlay_n, (unsigned)(ex_ssid_n+ex_bssid_n));
  oled.display();
#endif
}


//   Anomaly detection helpers

static void update_baseline_and_anoms(AP& a, const Ev& e){
  uint32_t t = nowms();

  // baseline set on first solid sight (has channel & security known)
  if(!a.base_set && e.ch){
    a.base_set = true;
    a.base_ch = e.ch;
    a.base_bi = e.bi;
    a.base_open = a.open; a.base_wep=a.wep; a.base_wpa=a.wpa; a.base_wpa2=a.wpa2; a.base_wpa3=a.wpa3;
  }

  // Security downgrade: baseline stronger than current (e.g., WPA2/3 -> OPEN/WEP/WPA)
  bool base_stronger =
      (a.base_wpa3 && !a.wpa3) ||
      (a.base_wpa2 && !(a.wpa2 || a.wpa3)) ||
      (a.base_wpa  && !(a.wpa  || a.wpa2 || a.wpa3)) ||
      (a.base_wep  && a.open); // weird but count
  if(base_stronger && (t - a.last_an_down_ms > 30000)){
    a.an_down = true;
    a.last_an_down_ms = t;
    const char* name = a.ssid[0] ? a.ssid : "<hidden>";
    push_evt("Anom DOWN: %s (%02X:%02X:%02X..)", name, a.bssid[0],a.bssid[1],a.bssid[2]);
  }

  // Channel switch: differs from baseline
  if(a.base_set && e.ch && e.ch != a.base_ch && (t - a.last_an_chan_ms > 30000)){
    a.an_chan = true;
    a.last_an_chan_ms = t;
    const char* name = a.ssid[0] ? a.ssid : "<hidden>";
    push_evt("Anom CHAN: %s %u->%u", name, a.base_ch, e.ch);
  }
}

// Check for evil twin for this AP: same SSID, different BSSID, different security
static void check_evil_twin(AP& target){
  if(!target.ssid[0]) return; // unknown name
  uint32_t t = nowms();
  for(size_t i=0;i<n_aps;i++){
    AP& other = aps[i];
    if(&other == &target) continue;
    if(other.excluded) continue;
    if(!other.ssid[0]) continue;
    if(strcasecmp(other.ssid, target.ssid)!=0) continue;
    if(mac_eq(other.bssid, target.bssid)) continue;

    // different security profile?
    bool diff_sec = (other.open!=target.open) || (other.wep!=target.wep) ||
                    (other.wpa!=target.wpa) || (other.wpa2!=target.wpa2) || (other.wpa3!=target.wpa3);
    if(diff_sec && (t - target.last_an_evil_ms > 45000)){
      target.an_evil = true;
      target.last_an_evil_ms = t;
      char b1[18], b2[18]; mac_str(target.bssid,b1); mac_str(other.bssid,b2);
      push_evt("Anom EVIL: '%s' %s vs %s", target.ssid, b1, b2);
      break;
    }
  }
}


//   Setup / Loop

void setup(){
  pinMode(PIN_BTN_MODE, INPUT_PULLUP);
  pinMode(PIN_BTN_ACT,  INPUT_PULLUP);

  Serial.begin(115200);
  delay(150);

#if USE_OLED
  Wire.begin(21,22); Wire.setClock(100000);
  oled_ok = oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  if(oled_ok){
    oled.clearDisplay(); oled.setTextSize(1); oled.setTextColor(SSD1306_WHITE);
    oled.setCursor(0,0); oled.println("ESP IoT Scout");
    oled.setCursor(0,10); oled.println("Starting...");
    oled.display();
  } else {
    Serial.println("[OLED] init failed");
  }
#endif

  if(!LittleFS.begin(true)){ Serial.println("LittleFS mount failed"); }
  ex_load_file();
  if(load_overlay_from_fs()){ Serial.printf("[DB] overlay entries: %u\n", (unsigned)overlay_n); }
  bloom_seed_base();

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PSK);
  IPAddress ip = WiFi.softAPIP();
  Serial.print("AP up at http://"); Serial.println(ip);

  esp_wifi_set_promiscuous_rx_cb(sniffer_cb);
  if(esp_wifi_set_promiscuous(true)!=ESP_OK) Serial.println("promisc failed");
  esp_wifi_set_channel(cur_ch, WIFI_SECOND_CHAN_NONE);
  last_hop_ms = nowms();

  setup_http();

#if USE_OLED
  if(oled_ok){
    oled.clearDisplay(); oled.setCursor(0,0);
    oled.printf("AP @ %d.%d.%d.%d\n", ip[0],ip[1],ip[2],ip[3]);
    oled.setCursor(0,16); oled.println("Open web page");
    oled.display();
    delay(800);
  }
#endif
}

void loop(){
  // drain captured events
  while(ridx != widx){
    Ev e = evring[ridx];
    ridx = (uint8_t)((ridx+1)%EV_RING);

    if(e.bssid[0]|e.bssid[1]|e.bssid[2]|e.bssid[3]|e.bssid[4]|e.bssid[5]){
      // locate RSSI update
      if(locate_mode && mac_eq(e.bssid, locate_bssid)){
        if(locate_rssi_fast == -127) locate_rssi_fast = e.rssi;
        else locate_rssi_fast = (int8_t)((locate_rssi_fast + e.rssi) / 2);
        locate_last_ms = nowms();
      }

      AP* a = ap_touch(e.bssid);
      if(!a) continue;

      // Only set SSID if non-empty; don't overwrite learned name with "<hidden>"
      if(e.ssid[0]){
        strncpy(a->ssid, e.ssid, SSID_MAX_LEN);
        a->ssid[SSID_MAX_LEN]=0;
      }
      a->ch = e.ch;
      a->last_ms = nowms();
      if(a->rssi_ewma==-127) a->rssi_ewma = e.rssi;
      else a->rssi_ewma = (int8_t)((a->rssi_ewma*7 + e.rssi)/8);

      set_security(*a, e.privacy, e.has_wpa, e.has_rsn, e.has_sae);
      a->default_ssid = false;
      derive_vendor(*a);

      // Exclude check BEFORE scoring visibility
      a->excluded = ex_match_ap(a->ssid[0] ? a->ssid : "<hidden>", a->bssid);

      // Anomalies
      update_baseline_and_anoms(*a, e);
      check_evil_twin(*a);

      // Risk
      a->risk_score = a->excluded ? 0 : score_ap(*a);
    }
  }

  handle_buttons();
  hop_channel();

  static uint32_t last_ws=0, last_oled=0;
  if(nowms() - last_ws >= 600){
    ws.cleanupClients();
    send_snapshot();
    last_ws = nowms();
  }
  if(nowms() - last_oled >= 350){
    oled_status();
    last_oled = nowms();
  }
}
