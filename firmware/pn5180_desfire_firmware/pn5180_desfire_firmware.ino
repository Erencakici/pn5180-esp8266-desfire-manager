/*
 * DESFire EV3 kart firmware - PN5180 + NodeMCU v3 (ESP8266)
 * Serial 115200 8N1, satir bazli JSON: istek {"cmd":...} -> tek yanit {"ok":...};
 * ayrica istenmeden gelen {"event":...} mesajlari.
 * EN: line-based JSON over serial; one reply per request, plus events.
 */

#ifndef ARDUINO_H_INCLUDED
#include <Arduino.h>
#endif

/* PN5180 kutuphanesinin yamali kopyasi (src/pn5180lib): BUSY/IRQ beklemeleri
   sinirli + watchdog besler. Tirnakli include yerel kopyayi derler.
   EN: vendored patched PN5180 lib with bounded waits. */
#include "src/pn5180lib/PN5180.h"
#include "src/pn5180lib/PN5180ISO14443.h"
#include "desfire_crypto.h"

struct FileInfo;

#define PN5180_NSS  15   // D8
#define PN5180_BUSY 5    // D1
#define PN5180_RST  4    // D2
#define LED_PIN     2    // D4 / GPIO2 NodeMCU blue LED (active LOW)

#define FW_VERSION  "1.0.0"
#define PROTO_VER   1

PN5180ISO14443 nfc(PN5180_NSS, PN5180_BUSY, PN5180_RST);

static inline void ledOn() { digitalWrite(LED_PIN, LOW); }
static inline void ledOff() { digitalWrite(LED_PIN, HIGH); }
static inline void ledActivity() {
  digitalWrite(LED_PIN, HIGH);
  delayMicroseconds(1500);
  digitalWrite(LED_PIN, LOW);
}

#define REG_SYSTEM_CONFIG 0x00
#define REG_IRQ_STATUS    0x02
#define REG_RX_STATUS     0x13

#define IRQ_RX_STAT    0x00000001UL
#define RX_ST_LEN_MASK 0x000001FFUL
#define RX_ST_CRC_ERROR 0x00010000UL
#define RX_ST_PROTOCOL_ERROR 0x00020000UL

#define PCB_I_BASE     0x02
#define PCB_I_BLKNO    0x01
#define PCB_I_CHAINING 0x10
#define PCB_I_CID_FLAG 0x08
#define PCB_I_NAD_FLAG 0x04
#define PCB_R_ACK      0xA2

#define CMD_AUTHENTICATE_LEGACY 0x0A
#define CMD_AUTHENTICATE_ISO    0x1A
#define CMD_AUTHENTICATE_AES    0xAA
#define CMD_GET_VERSION         0x60
#define CMD_GET_APP_IDS         0x6A
#define CMD_SELECT_APP          0x5A
#define CMD_CREATE_APP          0xCA
#define CMD_DELETE_APP          0xDA
#define CMD_GET_KEY_SETTINGS    0x45
#define CMD_GET_KEY_VERSION     0x64
#define CMD_CHANGE_KEY          0xC4
#define CMD_GET_FILE_IDS        0x6F
#define CMD_GET_FILE_SETTINGS   0xF5
#define CMD_CREATE_STD_FILE     0xCD
#define CMD_DELETE_FILE         0xDF
#define CMD_CHANGE_FILE_SETTINGS 0x5F
#define CMD_GET_FREE_MEMORY     0x6E
#define CMD_READ_DATA           0xBD
#define CMD_WRITE_DATA          0x3D
#define CMD_FORMAT_PICC         0xFC

#define STATUS_OK           0x00
#define STATUS_MORE_FRAMES  0xAF
#define EXCHANGE_TIMEOUT_MS 800

/* Katman bazli hata kodlari, araliklar cakismaz: rawTransceive -1..-9,
   isoDepExchange -20..-29, desfireNative -30..-39. rc<0 host'a hep transport
   hatasi olur. EN: layered return-code ranges, rc<0 = transport fail. */
#define RF_RET_WEDGED      (-6)  /* reader BUSY stuck: hardware reset needed   */
#define RF_RET_TIMEOUT     (-1)  /* no RX interrupt within EXCHANGE_TIMEOUT_MS */
#define RF_RET_BADARG      (-2)  /* impossible tx length / sendData refused    */
#define RF_RET_REGFAIL     (-3)  /* IRQ/RX-status register read failed         */
#define RF_RET_PROTO       (-4)  /* RX protocol error flag                     */
#define RF_RET_CRC         (-5)  /* RX CRC error flag                          */
#define RF_RET_RX_OVERFLOW (-7)  /* card answer larger than the caller buffer  */

#define ISO_RET_BAD_BLOCK  (-20) /* I-block with an impossible header          */
#define ISO_RET_BAD_SBLK   (-21) /* unexpected S-block                         */
#define ISO_RET_BAD_PCB    (-22) /* unknown block type                         */
#define ISO_RET_CHAIN_LIM  (-23) /* more chained blocks than the loop allows   */
#define ISO_RET_OVERFLOW   (-24) /* concatenated INF exceeded the caller buffer */

#define NFC_RET_FRAMES     (-30) /* more continuation frames than the loop allows */
#define NFC_RET_OVERFLOW   (-31) /* assembled response exceeded the caller buffer */

/* ------------------------------------------------------------------ */
/*  Session / reader state                                             */
/* ------------------------------------------------------------------ */
static uint8_t  gPcdBlock = 0;
static uint8_t  gRxRaw[320];
static uint8_t  gInf[320];
static uint8_t  gResp[320];
static uint8_t  gRead[320];
static uint8_t  gVer[64];

static uint8_t  gCurrentUID[7];
static uint8_t  gCurrentUIDLen = 0;
static uint8_t  gCurrentSAK = 0;
static uint32_t gCurrentAID = 0x000000;

static bool     gCardConnected = false;
static bool     gIsAuthenticated = false;
static uint8_t  gAuthKeyNo = 0;
static char     gAuthAlgo[8] = "";          // "des" | "2k3des" | "iso" | "aes"
static char     gAuthRoleName[16] = "Yok";
static uint8_t  gSessionKey[16];

/* EV1 guvenli mesajlasma durumu. ISO/AES auth sonrasi kart yanitlari MAC'ler
   ve bir IV zincirler; host aynalamazsa sifreli komutlar patlar.
   gSmBlk 0=yok, 8=3DES, 16=AES. EN: mirror the running IV or cmds fail. */
static uint8_t  gSmIv[16];
static uint8_t  gSmBlk = 0;

static uint8_t  gAts[32];
static uint8_t  gAtsLen = 0;

static uint32_t gLastPoll = 0;      // last activation attempt while scanning
static uint32_t gLastProbe = 0;     // last presence probe while a card is connected
static uint8_t  gProbeFails = 0;
static bool     gRfFault = false;        // reader was wedged -> report RF_ERROR
static bool     gRfNeedsReset = false;   // RF field is stale -> re-init before the next activation

/* Kart varlik yoklamasi kendi zamanlayicisinda; seri trafige bagli degil
   (host her saniye status sorar). EN: probe on its own timer. */
#define PROBE_INTERVAL_MS 300
#define PROBE_TIMEOUT_MS  400   /* a probe must fail fast; a real card answers in ms */
#define PROBE_RETRY_PAUSE_MS 20 /* pause before the in-round probe retry */

/* rawTransceive zaman asimi. Yoklama gecici dusurur ki gitmis kart dongu'yu
   bloklamasin. EN: probe lowers it so a gone card can't stall. */
static uint32_t gExchangeTimeoutMs = EXCHANGE_TIMEOUT_MS;

/* Format onay token'i: kartin UID'sine bagli, tek kullanimlik, her kart
   degisiminde silinir. EN: format token bound to UID, single-use. */
#define FORMAT_CONFIRM_TTL_MS 30000UL
static char     gFormatToken[17];        /* 8 random bytes as hex */
static uint32_t gFormatTokenAt = 0;
static uint8_t  gFormatTokenUid[7];
static uint8_t  gFormatTokenUidLen = 0;

static void clearFormatToken(void) {
  gFormatToken[0] = 0;
  gFormatTokenAt = 0;
  gFormatTokenUidLen = 0;
  memset(gFormatTokenUid, 0, sizeof(gFormatTokenUid));
}

/* Serial line assembly */
#define LINE_MAX 512
static char     gLineBuf[LINE_MAX + 1];
static uint16_t gLineLen = 0;
static bool     gLineOverflow = false;

/* ------------------------------------------------------------------ */
/*  Small byte / hex helpers                                           */
/* ------------------------------------------------------------------ */
static uint32_t read3LE(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static void write3LE(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
}

static int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void toHex2(uint8_t b, char *out) {
  static const char *H = "0123456789ABCDEF";
  out[0] = H[b >> 4];
  out[1] = H[b & 0x0F];
  out[2] = 0;
}

static void appendBinHex(String &r, const uint8_t *p, uint16_t n) {
  static const char *H = "0123456789ABCDEF";
  for (uint16_t i = 0; i < n; i++) {
    r += H[p[i] >> 4];
    r += H[p[i] & 0x0F];
  }
}

static bool hexToBin(const char *s, uint8_t *out, int maxBytes, int *outLen) {
  size_t n = strlen(s);
  if (n == 0 || (n % 2) != 0) return false;
  int cnt = (int)(n / 2);
  if (cnt > maxBytes) return false;
  for (int i = 0; i < cnt; i++) {
    int hi = hexVal(s[2 * i]);
    int lo = hexVal(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  *outLen = cnt;
  return true;
}

static bool parseAid6(const char *s, uint32_t *out) {
  if (strlen(s) != 6) return false;
  uint32_t v = 0;
  for (int i = 0; i < 6; i++) {
    int h = hexVal(s[i]);
    if (h < 0) return false;
    v = (v << 4) | (uint32_t)h;
  }
  *out = v;
  return true;
}

static void aidToHex(uint32_t aid, char *out) {
  static const char *H = "0123456789ABCDEF";
  out[0] = H[(aid >> 20) & 0xF];
  out[1] = H[(aid >> 16) & 0xF];
  out[2] = H[(aid >> 12) & 0xF];
  out[3] = H[(aid >> 8) & 0xF];
  out[4] = H[(aid >> 4) & 0xF];
  out[5] = H[aid & 0xF];
  out[6] = 0;
}

static void asciiLower(char *s) {
  for (; *s; s++) {
    if (*s >= 'A' && *s <= 'Z') *s = (char)(*s - 'A' + 'a');
  }
}

/* ------------------------------------------------------------------ */
/*  JSON parser — bounded recursive descent (no ArduinoJson needed)    */
/*                                                                     */
/*  A real grammar driven parser, not a byte scanner:                  */
/*   - every value is matched against the JSON grammar, so a member    */
/*     that has to hold a string but holds 1 / true / null is         */
/*     rejected instead of being silently ignored,                     */
/*   - braces and brackets must match in kind: "{]" and "[}" are      */
/*     invalid documents,                                              */
/*   - numbers must be complete JSON numbers: "12abc", "1.5" and     */
/*     "1e3" are NOT integers and are rejected,                       */
/*   - strings are unescaped properly: "\n", "\t", "\uXXXX" become    */
/*     real characters / UTF-8 bytes,                                  */
/*   - a value that does not fit the caller's buffer is an ERROR,      */
/*     never a silent truncation (a shortened key or hex string would */
/*     silently reach the card).                                       */
/*                                                                     */
/*  Nesting depth is bounded so a hostile document cannot blow up     */
/*  the small ESP8266 stack.                                           */
/* ------------------------------------------------------------------ */
#define JSON_MAX_DEPTH 8

static const char *skipWs(const char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  return p;
}


static int jsonHex4(const char *p) {
  int v = 0;
  for (uint8_t i = 0; i < 4; i++) {
    int h = hexVal(p[i]);
    if (h < 0) return -1;
    v = (v << 4) | h;
  }
  return v;
}


static const char *jsonParseString(const char *p, char *out, size_t maxOut) {
  if (*p != '"') return NULL;
  p++;
  size_t o = 0;
  const bool keep = (out != NULL && maxOut > 0);

  for (;;) {
    unsigned char c = (unsigned char)*p;
    if (c == 0) return NULL;               
    if (c == '"') { p++; break; }
    if (c < 0x20) return NULL;              

    char decoded[4];
    uint8_t decLen = 1;

    if (c == '\\') {
      p++;
      switch (*p) {
        case '"':  decoded[0] = '"';  p++; break;
        case '\\': decoded[0] = '\\'; p++; break;
        case '/':  decoded[0] = '/';  p++; break;
        case 'b':  decoded[0] = '\b'; p++; break;
        case 'f':  decoded[0] = '\f'; p++; break;
        case 'n':  decoded[0] = '\n'; p++; break;
        case 'r':  decoded[0] = '\r'; p++; break;
        case 't':  decoded[0] = '\t'; p++; break;
        case 'u': {
          p++;
          int cp = jsonHex4(p);
          if (cp < 0) return NULL;       
          p += 4;
          if (cp < 0x80) {
            decoded[0] = (char)cp;
            decLen = 1;
          } else if (cp < 0x800) {
            decoded[0] = (char)(0xC0 | (cp >> 6));
            decoded[1] = (char)(0x80 | (cp & 0x3F));
            decLen = 2;
          } else {
            decoded[0] = (char)(0xE0 | (cp >> 12));
            decoded[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
            decoded[2] = (char)(0x80 | (cp & 0x3F));
            decLen = 3;
          }
          break;
        }
        default:
          return NULL;                      
      }
    } else {
      decoded[0] = (char)c;
      p++;
    }

    if (keep) {
      if (o + decLen + 1 > maxOut) return NULL;  
      memcpy(out + o, decoded, decLen);
    }
    o += decLen;
  }

  if (keep) out[o] = 0;
  return p;
}

static const char *jsonParseNumber(const char *p) {
  const char *start = p;
  if (*p == '-') p++;
  if (*p == '0') {
    p++;
  } else if (*p >= '1' && *p <= '9') {
    while (*p >= '0' && *p <= '9') p++;
  } else {
    return NULL;
  }
  if (*p == '.') {
    p++;
    if (!(*p >= '0' && *p <= '9')) return NULL;
    while (*p >= '0' && *p <= '9') p++;
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') p++;
    if (!(*p >= '0' && *p <= '9')) return NULL;
    while (*p >= '0' && *p <= '9') p++;
  }
  return (p == start) ? NULL : p;
}

static const char *jsonParseValue(const char *p, int depth) {
  if (depth > JSON_MAX_DEPTH) return NULL;
  p = skipWs(p);
  switch (*p) {
    case '"':
      return jsonParseString(p, NULL, 0);
    case '{': {
      p = skipWs(p + 1);
      if (*p == '}') return p + 1;
      for (;;) {
        p = skipWs(p);
        if (*p != '"') return NULL;        
        p = jsonParseString(p, NULL, 0);
        if (!p) return NULL;
        p = skipWs(p);
        if (*p != ':') return NULL;         
        p = jsonParseValue(p + 1, depth + 1);
        if (!p) return NULL;
        p = skipWs(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') return p + 1;
        return NULL;                     
      }
    }
    case '[': {
      p = skipWs(p + 1);
      if (*p == ']') return p + 1;
      for (;;) {
        p = jsonParseValue(p, depth + 1);
        if (!p) return NULL;
        p = skipWs(p);
        if (*p == ',') { p++; continue; }
        if (*p == ']') return p + 1;
        return NULL;
      }
    }
    case 't': return strncmp(p, "true", 4) == 0 ? p + 4 : NULL;
    case 'f': return strncmp(p, "false", 5) == 0 ? p + 5 : NULL;
    case 'n': return strncmp(p, "null", 4) == 0 ? p + 4 : NULL;
    default:
      return jsonParseNumber(p);
  }
}

static bool jsonValidate(const char *p) {
  p = skipWs(p);
  if (*p != '{') return false;    
  const char *end = jsonParseValue(p, 0);
  if (!end) return false;
  return *skipWs(end) == 0;        
}

/* Kok nesnede "key": degerini bul; yoksa/bozuksa NULL.
   EN: find top-level "key" value. */
static const char *jsonFindKey(const char *json, const char *key) {
  const size_t klen = strlen(key);
  const char *p = skipWs(json);
  if (*p != '{') return NULL;
  p = skipWs(p + 1);

  while (*p && *p != '}') {
    if (*p != '"') return NULL;             

    const char *keyStart = p + 1;
    const char *keyEnd = jsonParseString(p, NULL, 0);  
    if (!keyEnd) return NULL;
    size_t thisLen = (size_t)(keyEnd - 1 - keyStart);

    const char *after = skipWs(keyEnd);
    if (*after != ':') return NULL;           

    const char *val = skipWs(after + 1);
    if (thisLen == klen && strncmp(keyStart, key, klen) == 0)
      return val;

    const char *next = jsonParseValue(val, 1);
    if (!next) return NULL;
    p = skipWs(next);
    if (*p != ',') return NULL;              
    p = skipWs(p + 1);
  }
  return NULL;
}

/* String uye oku; deger JSON string olmali. Escape cozulur, sigmayan deger
   HATA (sessiz kirpma yok). EN: read string member, oversize is an error. */
static bool jsonGetString(const char *json, const char *key, char *out, size_t maxOut) {
  if (maxOut == 0) return false;
  const char *v = jsonFindKey(json, key);
  if (!v || *v != '"') return false;
  if (!jsonParseString(v, out, maxOut)) {
    out[0] = 0;
    return false;
  }
  return true;
}

/* Integer uye oku; "12abc"/"12.5"/"1e3" reddedilir (kirpilmaz).
   EN: read integer member, malformed rejected. */
static bool jsonGetInt(const char *json, const char *key, long *out) {
  const char *v = jsonFindKey(json, key);
  if (!v) return false;
  const char *p = v;
  bool neg = false;
  if (*p == '-') { neg = true; p++; }
  if (*p < '0' || *p > '9') return false;    
  if (*p == '0' && p[1] >= '0' && p[1] <= '9')
    return false;                              

  long acc = 0;
  while (*p >= '0' && *p <= '9') {
    if (acc > 99999999L) return false;  
    acc = acc * 10 + (*p - '0');
    p++;
  }

  const char c = *p;
  if (c == '.' || c == 'e' || c == 'E') return false;  
  if (c != 0 && c != ',' && c != '}' && c != ' ' && c != '\t' &&
      c != '\r' && c != '\n')
    return false;                          

  *out = neg ? -acc : acc;
  return true;
}

static bool jsonGetBool(const char *json, const char *key, bool *out) {
  const char *v = jsonFindKey(json, key);
  if (!v) return false;
  if (strncmp(v, "true", 4) == 0 && (v[4] == 0 || v[4] == ',' || v[4] == '}' || v[4] == ' ' || v[4] == '\t' || v[4] == '\r' || v[4] == '\n')) {
    *out = true; return true;
  }
  if (strncmp(v, "false", 5) == 0 && (v[5] == 0 || v[5] == ',' || v[5] == '}' || v[5] == ' ' || v[5] == '\t' || v[5] == '\r' || v[5] == '\n')) {
    *out = false; return true;
  }
  return false;
}

/* ------------------------------------------------------------------ */
/*  JSON response / event builders                                     */
/* ------------------------------------------------------------------ */
static void appendEscaped(String &r, const String &s) {
  for (unsigned int i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') { r += '\\'; r += c; }
    else if ((uint8_t)c < 0x20) { r += ' '; }
    else r += c;
  }
}

static void appendEscapedC(String &r, const char *s) {
  for (; *s; s++) {
    char c = *s;
    if (c == '"' || c == '\\') { r += '\\'; r += c; }
    else if ((uint8_t)c < 0x20) { r += ' '; }
    else r += c;
  }
}

static void sendLine(const String &r) { Serial.println(r); }

static void sendErr(const char *cmd, const char *code, const char *stHex /*NULL ok*/, const char *msg) {
  String r;
  r.reserve(140);
  r = F("{\"ok\":false,\"cmd\":\"");
  appendEscapedC(r, cmd);
  r += F("\",\"error\":\"");
  r += code;
  if (stHex) {
    r += F("\",\"status\":\"");
    r += stHex;
  }
  r += F("\",\"message\":\"");
  appendEscapedC(r, msg);
  r += F("\"}");
  sendLine(r);
}

static void emitLog(const char *level, const char *msg) {
  String r;
  r.reserve(112);
  r = F("{\"event\":\"log\",\"level\":\"");
  r += level;
  r += F("\",\"msg\":\"");
  appendEscapedC(r, msg);
  r += F("\"}");
  sendLine(r);
}

static void emitCardLost() {
  sendLine(F("{\"event\":\"card_lost\"}"));
}

static void emitCardEvent() {
  String r;
  r.reserve(96);
  r = F("{\"event\":\"card\",\"uid\":\"");
  appendBinHex(r, gCurrentUID, gCurrentUIDLen);
  r += F("\",\"sak\":\"");
  char h[3];
  toHex2(gCurrentSAK, h);
  r += h;
  r += '"';
  if (gAtsLen > 0) {
    r += F(",\"ats\":\"");
    appendBinHex(r, gAts, gAtsLen);
    r += '"';
  }
  r += '}';
  sendLine(r);
}

static void emitProgress(const char *task, int pct, const char *msg) {
  String r;
  r.reserve(112);
  r = F("{\"event\":\"progress\",\"task\":\"");
  r += task;
  r += F("\",\"pct\":");
  r += pct;
  r += F(",\"msg\":\"");
  appendEscapedC(r, msg);
  r += F("\"}");
  sendLine(r);
}

/* ------------------------------------------------------------------ */
/*  Bounded response writer                                            */
/*                                                                     */
/*  A deep dump response is up to ~6 kB of JSON.  Filling an Arduino  */
/*  String with it means a multi-kilobyte heap block that is grown    */
/*  and reallocated while it is filled: the classic cause of heap     */
/*  fragmentation on the ESP8266 and of OOM resets in the middle of   */
/*  a card transaction.  This writer fills a fixed static buffer      */
/*  instead - no heap traffic at all - and every write is bounds      */
/*  checked, so an oversized response is detected while it is built   */
/*  and never reaches the host.                                        */
/* ------------------------------------------------------------------ */
#define TX_BUF_MAX 6400

static char gTxBuf[TX_BUF_MAX];
static uint32_t gTxLen = 0;
static bool gTxOverflow = false;

static char txHexDigit(uint8_t n) {
  return (char)(n < 10 ? ('0' + n) : ('A' + (n - 10)));
}

static void txReset() {
  gTxLen = 0;
  gTxOverflow = false;
  gTxBuf[0] = 0;
}


static uint32_t txRoom() {
  return (uint32_t)(TX_BUF_MAX - 1) - gTxLen;
}

static void txPutRaw(const char *s, uint32_t n) {
  if (n > txRoom()) { gTxOverflow = true; return; }
  memcpy(gTxBuf + gTxLen, s, n);
  gTxLen += n;
  gTxBuf[gTxLen] = 0;
}


static void txPut(const char *s) {
  if (!s) return;
  txPutRaw(s, (uint32_t)strlen(s));
}


static void txPut(const __FlashStringHelper *s) {
  if (!s) return;
  uint32_t n = (uint32_t)strlen_P((const char *)s);
  if (n > txRoom()) { gTxOverflow = true; return; }
  memcpy_P(gTxBuf + gTxLen, (const char *)s, n);
  gTxLen += n;
  gTxBuf[gTxLen] = 0;
}

static void txPutChar(char c) {
  if (txRoom() < 1) { gTxOverflow = true; return; }
  gTxBuf[gTxLen++] = c;
  gTxBuf[gTxLen] = 0;
}

static void txPutNum(unsigned long v) {
  char tmp[12];
  uint8_t i = 0;
  if (v == 0) { txPutChar('0'); return; }
  while (v > 0 && i < sizeof(tmp)) {
    tmp[i++] = txHexDigit((uint8_t)(v % 10UL));
    v /= 10UL;
  }
  while (i > 0) txPutChar(tmp[--i]);
}

static void txPutSigned(long v) {
  if (v < 0) { txPutChar('-'); txPutNum((unsigned long)(-(v + 1)) + 1UL); }
  else txPutNum((unsigned long)v);
}

static void txPutHex2(uint8_t b) {
  txPutChar(txHexDigit((uint8_t)(b >> 4)));
  txPutChar(txHexDigit((uint8_t)(b & 0x0F)));
}

static void txPutBinHex(const uint8_t *p, uint16_t n) {
  for (uint16_t i = 0; i < n; i++) txPutHex2(p[i]);
}

static bool txOverflowed() { return gTxOverflow; }

static void sendTxLine() { Serial.println(gTxBuf); }

/* ------------------------------------------------------------------ */
/*  PN5180 watchdog guard                                               */
/*                                                                     */
/*  The vendored PN5180 library waits for IRQ/BUSY flags inside        */
/*  unbounded loops and never feeds the ESP8266 watchdog.  When the    */
/*  RF state machine is left in an indeterminate state (card pulled in */
/*  the middle of a transaction) the awaited flag never arrives, the   */
/*  library spins forever and the soft WDT resets the board.           */
/*                                                                     */
/*  The library must not be modified, so the reader is kept out of    */
/*  that state from the sketch: every risky library call is preceded  */
/*  by a bounded BUSY pre-check, and a wedged reader is recovered with */
/*  its own hardware reset line (plain GPIO, can never block).         */
/* ------------------------------------------------------------------ */
#define PN5180_BUSY_GUARD_MS 20   /* max time we wait for BUSY to drop */
#define PN5180_RST_LOW_MS   10   /* PN5180 reset pulse length          */
#define PN5180_RST_HIGH_MS  20   /* PN5180 start-up time after reset    */

/* Okuyucu donanim reset'i: sadece RST, SPI yok, bloklanmaz. Cipi bosa alir,
   RF alanini kapatir, IRQ temizler (kart oturumu da biter).
   EN: HW reset via RST; field off, session dies. */
static void pn5180HardReset(void) {
  digitalWrite(PN5180_RST, LOW);
  delay(PN5180_RST_LOW_MS);
  digitalWrite(PN5180_RST, HIGH);
  delay(PN5180_RST_HIGH_MS);
  ESP.wdtFeed();
}


static bool pn5180WaitIdle(void) {
  uint32_t t0 = millis();
  while (digitalRead(PN5180_BUSY) != LOW) {
    if ((uint32_t)(millis() - t0) >= PN5180_BUSY_GUARD_MS) return false;
    delay(1);
    ESP.wdtFeed();
  }
  return true;
}

/* ------------------------------------------------------------------ */
/*  RF transport layer (guards every library call against a wedged    */
/*  reader, otherwise identical to the working original)               */
/* ------------------------------------------------------------------ */
static int rawTransceive(const uint8_t *tx, uint8_t txLen, uint8_t *rx, uint16_t maxRx) {
  if (txLen == 0 || txLen > 64) return RF_RET_BADARG;


  if (!pn5180WaitIdle()) {
    gRfFault = true;
    return RF_RET_WEDGED;
  }

  nfc.clearIRQStatus(0xFFFFFFFFUL);
  if (!nfc.sendData((uint8_t *)tx, (int)txLen)) return RF_RET_BADARG;

  uint32_t start = millis();
  for (;;) {
    uint32_t irq = 0;
    if (!pn5180WaitIdle()) {
      gRfFault = true;
      return RF_RET_WEDGED;
    }
    if (!nfc.readRegister(REG_IRQ_STATUS, &irq)) {

      if (!pn5180WaitIdle()) { gRfFault = true; return RF_RET_WEDGED; }
      return RF_RET_REGFAIL;
    }
    if (irq & IRQ_RX_STAT) break;
    if (millis() - start > gExchangeTimeoutMs) return RF_RET_TIMEOUT;
    delay(1);
    yield();
    ESP.wdtFeed();
  }

  uint32_t rxStatus = 0;
  if (!nfc.readRegister(REG_RX_STATUS, &rxStatus)) {
    if (!pn5180WaitIdle()) { gRfFault = true; return RF_RET_WEDGED; }
    return RF_RET_REGFAIL;
  }
  if (rxStatus & RX_ST_PROTOCOL_ERROR) return RF_RET_PROTO;

  uint16_t len = (uint16_t)(rxStatus & RX_ST_LEN_MASK);
  if (len == 0) return RF_RET_TIMEOUT;


  if (len > maxRx) return RF_RET_RX_OVERFLOW;

  nfc.readData((int)len, rx);
  if (gCardConnected) ledActivity();

  if (rxStatus & RX_ST_CRC_ERROR) {
    if (len <= 4) return (int)len;
    return RF_RET_CRC;
  }


  gRfFault = false;
  return (int)len;
}

static int isoDepExchange(const uint8_t *cmd, uint8_t cmdLen, uint8_t *inf, uint16_t maxInf) {
  delay(4); // RF Guard Time

  uint8_t frame[70];
  if (cmdLen > 64) return RF_RET_BADARG;

  frame[0] = PCB_I_BASE | (gPcdBlock & PCB_I_BLKNO);
  memcpy(frame + 1, cmd, cmdLen);
  uint8_t frameLen = (uint8_t)(cmdLen + 1);
  uint16_t total = 0;

  for (uint8_t iter = 0; iter < 16; iter++) {
    yield();
    ESP.wdtFeed();

    int n = rawTransceive(frame, frameLen, gRxRaw, sizeof(gRxRaw));
    if (n < 1) return n;

    uint8_t pcb  = gRxRaw[0];
    uint8_t type = pcb & 0xC0;

    if (type == 0x00) { // I-block
      gPcdBlock ^= 1;
      uint16_t off = 1;
      if (pcb & PCB_I_CID_FLAG) off++;
      if (pcb & PCB_I_NAD_FLAG) off++;
      if (off > (uint16_t)n) return ISO_RET_BAD_BLOCK;

    
      uint16_t chunk = (uint16_t)n - off;

      if ((uint32_t)total > (uint32_t)maxInf) return ISO_RET_OVERFLOW;
      if ((uint32_t)chunk > (uint32_t)maxInf - (uint32_t)total) return ISO_RET_OVERFLOW;
      memcpy(inf + total, gRxRaw + off, chunk);
      total += chunk;

      if (pcb & PCB_I_CHAINING) {
        frame[0] = PCB_R_ACK | (gPcdBlock & PCB_I_BLKNO);
        frameLen = 1;
        continue;
      }
      return (int)total;
    }

    if (type == 0xC0) { // S-block
      if ((pcb & 0x30) == 0x30 && n >= 2) {
        frame[0] = 0xF2;
        frame[1] = gRxRaw[1] & 0x3F;
        frameLen = 2;
        continue;
      }
      return ISO_RET_BAD_SBLK;
    }
    return ISO_RET_BAD_PCB;
  }
  return ISO_RET_CHAIN_LIM;
}

/* ------------------------------------------------------------------ */
/*  EV1 secure messaging: running-IV CBC, CMAC, CRC32                  */
/* ------------------------------------------------------------------ */
#define STATUS_INTEGRITY_ERROR 0x1E
#define STATUS_DUPLICATE       0xDE

static void clearAuthState(void);

static void smEncrypt(uint8_t *buf, uint16_t len) {
  if (gSmBlk == 16) aes128_cbc_encrypt(gSessionKey, gSmIv, buf, buf, len);
  else              des3_2key_cbc_encrypt(gSessionKey, gSmIv, buf, buf, len);
}

static void smDecrypt(uint8_t *buf, uint16_t len) {
  if (gSmBlk == 16) aes128_cbc_decrypt(gSessionKey, gSmIv, buf, buf, len);
  else              des3_2key_cbc_decrypt(gSessionKey, gSmIv, buf, buf, len);
}

static void cmacShift(const uint8_t *in, uint8_t *out, uint8_t b, uint8_t rb) {
  uint8_t carry = 0;
  for (int i = b - 1; i >= 0; i--) {
    uint8_t nc = in[i] >> 7;
    out[i] = (uint8_t)((in[i] << 1) | carry);
    carry = nc;
  }
  if (in[0] & 0x80) out[b - 1] ^= rb;
}

static void smCmac(const uint8_t *msg, uint16_t len, uint8_t *mac) {
  static uint8_t buf[336];
  const uint8_t b = gSmBlk;
  uint8_t l[16], zeroIv[16], k[16];
  memset(l, 0, sizeof(l));
  memset(zeroIv, 0, sizeof(zeroIv));
  if (b == 16) aes128_cbc_encrypt(gSessionKey, zeroIv, l, l, 16);
  else         des3_2key_cbc_encrypt(gSessionKey, zeroIv, l, l, 8);
  const uint8_t rb = (b == 16) ? 0x87 : 0x1B;
  cmacShift(l, k, b, rb);                         

  bool complete = (len != 0) && (len % b == 0);
  uint16_t padded = complete ? len : (uint16_t)((len / b + 1) * b);
  memcpy(buf, msg, len);
  if (!complete) {
    buf[len] = 0x80;
    memset(buf + len + 1, 0, padded - len - 1);
    uint8_t k1[16];
    memcpy(k1, k, b);
    cmacShift(k1, k, b, rb);                  
  }
  for (uint8_t i = 0; i < b; i++) buf[padded - b + i] ^= k[i];
  smEncrypt(buf, padded);
  memcpy(mac, gSmIv, b);
}

static uint32_t desfireCrc32(const uint8_t *p, uint16_t n, uint32_t crc) {
  for (uint16_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (uint8_t bit = 0; bit < 8; bit++)
      crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320UL : 0);
  }
  return crc;
}

static void put32LE(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}


static bool smVerifyResponse(uint8_t *data, uint16_t len, const uint8_t *rxMac) {
  data[len] = STATUS_OK;       
  uint8_t mac[16];
  smCmac(data, (uint16_t)(len + 1), mac);
  return memcmp(mac, rxMac, 8) == 0;
}

static uint8_t gNat[336];

static int desfireNative(const uint8_t *cmd, uint8_t cmdLen, uint8_t *out, uint16_t maxOut,
                         uint16_t *outLen, uint8_t *status) {
  uint8_t tx[70];
  if (cmdLen == 0 || cmdLen > 64) return RF_RET_BADARG;

  const bool sm = gIsAuthenticated && gSmBlk != 0 && cmd[0] != CMD_SELECT_APP;
  if (sm) {
    uint8_t mac[16];
    smCmac(cmd, cmdLen, mac);
  }

  memcpy(tx, cmd, cmdLen);
  uint8_t txLen = cmdLen;
  uint16_t total = 0;

  *outLen = 0;
  *status = 0xFF;

  for (uint8_t f = 0; f < 16; f++) {
    yield();
    ESP.wdtFeed();

    int n = isoDepExchange(tx, txLen, gInf, sizeof(gInf));
    if (n < 1) {
      if (sm) clearAuthState();       
      return n;
    }

    uint8_t stat = gInf[0];


    uint16_t chunk = (uint16_t)n - 1;
    if ((uint32_t)total + chunk > sizeof(gNat) - 1) {
      *status = stat;
      return NFC_RET_OVERFLOW;
    }

    if (stat == STATUS_MORE_FRAMES || stat == STATUS_OK) {
      memcpy(gNat + total, gInf + 1, chunk);
      total += chunk;
    }

    if (stat == STATUS_MORE_FRAMES) {
      tx[0] = STATUS_MORE_FRAMES;
      txLen = 1;
      continue;
    }

    if (sm) {
      if (stat != STATUS_OK) {
        clearAuthState();             
      } else if (total < 8) {
        clearAuthState();
        stat = STATUS_INTEGRITY_ERROR;
        total = 0;
      } else {
        uint8_t rxMac[8];
        total -= 8;
        memcpy(rxMac, gNat + total, 8);
        if (!smVerifyResponse(gNat, total, rxMac)) {
          clearAuthState();
          emitLog("error", "response MAC mismatch - session dropped");
          stat = STATUS_INTEGRITY_ERROR;
          total = 0;
        }
      }
    }


    if (total > maxOut) {
      *status = stat;
      return NFC_RET_OVERFLOW;
    }
    memcpy(out, gNat, total);
    *status = stat;
    *outLen = total;
    return 0;
  }
  if (sm) clearAuthState();
  return NFC_RET_FRAMES;
}

static int desfireGetVersion(uint8_t *out, uint16_t maxOut, uint16_t *outLen, uint8_t *status) {
  uint8_t cmd = CMD_GET_VERSION;
  return desfireNative(&cmd, 1, out, maxOut, outLen, status);
}

static void clearAuthState(void) {
  gIsAuthenticated = false;
  gAuthKeyNo = 0;
  gAuthAlgo[0] = 0;
  strcpy(gAuthRoleName, "Yok");
  memset(gSessionKey, 0, sizeof(gSessionKey));
  memset(gSmIv, 0, sizeof(gSmIv));
  gSmBlk = 0;
}

static bool pn5180Reinit(bool hardReset) {
  if (hardReset) pn5180HardReset();

  if (!pn5180WaitIdle()) return false;    
  nfc.clearIRQStatus(0xFFFFFFFFUL);

  if (!pn5180WaitIdle()) return false;
  if (!nfc.setupRF()) return false;

  if (!pn5180WaitIdle()) return false;
  nfc.clearIRQStatus(0xFFFFFFFFUL);
  return true;
}


static bool fullRFReset(bool emitLostIfConnected) {
  bool hadCard = gCardConnected;

  ledOff();


  bool rfOk = pn5180Reinit(true);

  ESP.wdtFeed();

  clearAuthState();
  gCardConnected = false;
  gPcdBlock = 0;
  gCurrentAID = 0;
  gCurrentUIDLen = 0;
  gCurrentSAK = 0;
  gAtsLen = 0;
  gProbeFails = 0;
  gLastPoll = 0;                 
  gLastProbe = 0;
  clearFormatToken();         


  gRfNeedsReset = true;


  if (!rfOk) {
    gRfFault = true;
    emitLog("error", "PN5180 hardware reset failed (BUSY stuck)");
  }

  if (hadCard && emitLostIfConnected) emitCardLost();
  return rfOk;
}

static void handleTransportLoss(void) {

  if (gCardConnected) emitCardLost();
  fullRFReset(false);
}

/* ------------------------------------------------------------------ */
/*  Card activation (hardened against stale RX data / stuck ACTIVE)    */
/* ------------------------------------------------------------------ */

enum {
  CONNECT_OK = 0,
  CONNECT_REINIT_FAIL,      /* the reader could not be brought back */
  CONNECT_NO_UID,           /* activateTypeA did not find a card */
  CONNECT_UID_LEN,          /* unexpected UID length */
  CONNECT_UID_PLACEHOLDER,  /* all-zero / all-FF UID */
  CONNECT_RATS_TIMEOUT,     /* the card did not answer RATS */
  CONNECT_RATS_WEDGED,      /* the reader is wedged (BUSY stuck) */
  CONNECT_RATS_ERROR        /* any other RATS failure */
};

static const char *connectFailText(uint8_t reason) {
  switch (reason) {
    case CONNECT_REINIT_FAIL:    return "activation: reader re-init failed (BUSY stuck)";
    case CONNECT_NO_UID:         return "activation: no card detected";
    case CONNECT_UID_LEN:        return "activation: unexpected UID length";
    case CONNECT_UID_PLACEHOLDER: return "activation: all-zero/all-FF UID";
    case CONNECT_RATS_TIMEOUT:   return "activation: card did not answer RATS";
    case CONNECT_RATS_WEDGED:    return "activation: reader wedged during RATS";
    case CONNECT_RATS_ERROR:     return "activation: RATS exchange failed";
    default:                     return "activation failed";
  }
}

static bool connectCard() {
  static const uint8_t RATS[2] = { 0xE0, 0x80 };
  static uint8_t lastLogged = CONNECT_OK;
  uint8_t reason = CONNECT_OK;

  for (uint8_t attempt = 0; attempt < 3; attempt++) {
    yield();
    ESP.wdtFeed();

    if (attempt > 0) delay(20);

    /* Kutuphaneye dokunmadan once reader'i bilinen iyi duruma getir. setRF_off
       kullanilmaz (gelmeyen IRQ = soft WDT). Donanim reset alani kapatir ve
       takili state machine'i temizler; hala BUSY ise denemeyi iptal eder.
       EN: HW reset to a known state, no reset loop. */
    if (attempt > 0 || gRfNeedsReset || !pn5180WaitIdle()) {
      if (!pn5180Reinit(true)) { reason = CONNECT_REINIT_FAIL; continue; }
      gRfNeedsReset = false;
      /* Donanim reset alani kapatti; kart WUPA'ya cevap vermeden once enerji
         toplayip boot etmeli. 10 ms antende bekleyen kart icin azdi.
         EN: card needs time to reboot after field power-down. */
      delay(30);           
    } else {
      nfc.clearIRQStatus(0xFFFFFFFFUL);
    }

    uint8_t card[10];
    memset(card, 0, sizeof(card));
    uint8_t uidLen = nfc.activateTypeA(card, 1);

    if (uidLen != 4 && uidLen != 7) {
      reason = (uidLen == 0) ? CONNECT_NO_UID : CONNECT_UID_LEN;
      continue;
    }

    bool all0 = true, allF = true;
    for (uint8_t i = 0; i < uidLen; i++) {
      if (card[3 + i] != 0x00) all0 = false;
      if (card[3 + i] != 0xFF) allF = false;
    }
    if (all0 || allF) { reason = CONNECT_UID_PLACEHOLDER; continue; }

    gPcdBlock = 0;
    int atsLen = rawTransceive(RATS, 2, gRxRaw, sizeof(gRxRaw));
    if (atsLen < 1) {
      if (atsLen == RF_RET_TIMEOUT)     reason = CONNECT_RATS_TIMEOUT;
      else if (atsLen == RF_RET_WEDGED) reason = CONNECT_RATS_WEDGED;
      else                              reason = CONNECT_RATS_ERROR;
      continue;
    }

    memcpy(gCurrentUID, card + 3, uidLen);
    gCurrentUIDLen = uidLen;
    gCurrentSAK = card[2];
    gAtsLen = (atsLen > 32) ? 32 : (uint8_t)atsLen;
    memcpy(gAts, gRxRaw, gAtsLen);

    gCurrentAID = 0;
    clearAuthState();
    clearFormatToken();           
    gPcdBlock = 0;

    gCardConnected = true;
    gProbeFails = 0;
    gLastProbe = millis();
    ledOn();
    emitCardEvent();
    lastLogged = CONNECT_OK;
    return true;
  }

  if (reason != CONNECT_OK && reason != lastLogged) {
    emitLog("warn", connectFailText(reason));
  }
  lastLogged = reason;
  return false;
}

/* Baglantidayken varlik yoklamasi (auth'dayken de guvenli: GET_VERSION
   sifrelenmez/MAC'lenmez). Ikinci RATS yerine serbest GET_VERSION; herhangi
   bir RF cevabi -hata bile- kart orada demek. EN: probe with GET_VERSION. */
static const char *rfFailText(int rc) {
  switch (rc) {
    case RF_RET_TIMEOUT:      return "zaman asimi (yanit yok)";
    case RF_RET_CRC:          return "CRC hatasi";
    case RF_RET_PROTO:        return "protokol hatasi";
    case RF_RET_WEDGED:       return "okuyucu kilitlendi (BUSY)";
    case RF_RET_REGFAIL:      return "register okunamadi";
    case RF_RET_RX_OVERFLOW:  return "yanit tampona sigmadi";
    case RF_RET_BADARG:       return "gonderim hatasi";
    case NFC_RET_FRAMES:      return "cok fazla devam cercevesi";
    case NFC_RET_OVERFLOW:    return "yanit tasma";
    default:
      if (rc <= ISO_RET_CHAIN_LIM && rc >= ISO_RET_BAD_BLOCK) return "I-bloke cerceve hatasi";
      return "bilinmeyen RF hatasi";
  }
}

static int probeGetVersionOnce() {
  uint16_t dlen = 0;
  uint8_t st = 0xFF;

  /* Hizli basarisiz ol: gitmis kart her yoklamada dongu'yu tam
     EXCHANGE_TIMEOUT_MS bloklamasin. Tek is parcacikli, guvenli.
     EN: fail fast; single-threaded so override is safe. */
  uint32_t savedTimeout = gExchangeTimeoutMs;
  gExchangeTimeoutMs = PROBE_TIMEOUT_MS;
  int rc = desfireGetVersion(gVer, sizeof(gVer), &dlen, &st);
  gExchangeTimeoutMs = savedTimeout;
  return rc;
}

/* Baglantidayken varlik yoklamasi. Kararlilik: yoklama bir TUR olarak
   calisir (kisa duraklamayla bir kez yeniden dener); sadece iki denemesi de
   basarisiz tur sayilir. Oturum dusunce sebep bir kez loglanir. Gercekten
   cikan kart ~650 ms'de dusurulur. EN: round-based, only a full fail counts. */
static void presenceProbe() {
  int rc = probeGetVersionOnce();

  if (rc == RF_RET_WEDGED) {
    /* reader hatasi (BUSY takili): hemen toparla; saymak donanim reset'i
       geciktirirdi. EN: on wedged reader recover now. */
    handleTransportLoss();
    return;
  }

  if (rc < 0) {
    /* ilk deneme basarisiz - gecici olabilir; saymadan once tum diziyi bir kez
       yeniden dene. EN: retry once before counting. */
    delay(PROBE_RETRY_PAUSE_MS);
    rc = probeGetVersionOnce();
    if (rc == RF_RET_WEDGED) {
      handleTransportLoss();
      return;
    }
  }

  if (rc < 0) {
    /* bu turun iki denemesi de basarisiz: ust uste iki kotu tur kartin
       gittigini kanitlar; tek kotu tur dusurmesin. EN: two bad rounds = gone. */
    gProbeFails++;
    if (gProbeFails >= 4) {   /* daha toleransli: gecici RF glitch'inde oturumu dusurme */
      char msg[96];
      snprintf(msg, sizeof(msg),
               "presence probe failed twice (%s) - dropping card session",
               rfFailText(rc));
      emitLog("warn", msg);
      handleTransportLoss();
    }
    return;
  }

  gProbeFails = 0;
}

/* ------------------------------------------------------------------ */
/*  Authentication engine (DES / 2K3DES / ISO / AES)                   */
/*  return: 0 = success, 1 = rejected (*outStatus = card status/0xFF), */
/*          -1 = transport failure                                     */
/* ------------------------------------------------------------------ */
static void rotateLeft(const uint8_t *in, uint8_t *out, uint8_t len) {
  uint8_t first = in[0];
  for (uint8_t i = 0; i < len - 1; i++) {
    out[i] = in[i + 1];
  }
  out[len - 1] = first;
}

static void fillRandom(uint8_t *buf, uint8_t len) {
  for (uint8_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)os_random();
  }
}

static int authenticateDES(uint8_t cmdCode, uint8_t keyNo, const uint8_t *keyBytes, uint8_t keyLen, uint8_t *outStatus) {
  *outStatus = 0xFF;

  uint8_t key16[16];
  if (keyLen == 8) {
    memcpy(key16, keyBytes, 8);
    memcpy(key16 + 8, keyBytes, 8);
  } else {
    memcpy(key16, keyBytes, 16);
  }

  uint8_t cmd[2] = { cmdCode, keyNo };
  int n = isoDepExchange(cmd, 2, gInf, sizeof(gInf));
  if (n < 1) return -1;
  if (n < 9 || gInf[0] != STATUS_MORE_FRAMES) {
    *outStatus = gInf[0];
    return 1;
  }

  uint8_t encRndB[8];
  memcpy(encRndB, &gInf[1], 8);

  uint8_t iv[8];
  memset(iv, 0, 8);
  uint8_t rndB[8];
  des3_2key_cbc_decrypt(key16, iv, encRndB, rndB, 8);

  uint8_t rndB_prime[8];
  rotateLeft(rndB, rndB_prime, 8);

  uint8_t rndA[8];
  fillRandom(rndA, 8);

  uint8_t plain[16];
  memcpy(plain, rndA, 8);
  memcpy(plain + 8, rndB_prime, 8);

  uint8_t encToken[16];
  if (cmdCode == CMD_AUTHENTICATE_LEGACY) {

    uint8_t z[8], t[8], b2[8];
    memset(z, 0, 8);
    for (uint8_t i = 0; i < 8; i++) t[i] = rndA[i] ^ encRndB[i];
    des3_2key_cbc_decrypt(key16, z, t, encToken, 8);         /* b1 = D(RndA ^ encRndB) */
    memset(z, 0, 8);
    for (uint8_t i = 0; i < 8; i++) t[i] = rndB_prime[i] ^ encToken[i];
    des3_2key_cbc_decrypt(key16, z, t, b2, 8);               /* b2 = D(RndB' ^ b1)     */
    memcpy(encToken + 8, b2, 8);
  } else {
    memcpy(iv, encRndB, 8);
    des3_2key_cbc_encrypt(key16, iv, plain, encToken, 16);
  }

  uint8_t sendBuf[17];
  sendBuf[0] = STATUS_MORE_FRAMES;
  memcpy(sendBuf + 1, encToken, 16);

  n = isoDepExchange(sendBuf, 17, gInf, sizeof(gInf));
  if (n < 1) return -1;
  if (n < 9 || gInf[0] != STATUS_OK) {
    *outStatus = gInf[0];
    return 1;
  }

  uint8_t encRndA_prime[8];
  memcpy(encRndA_prime, &gInf[1], 8);

  memcpy(iv, encToken + 8, 8);
  uint8_t verifyRndA_prime[8];
  des3_2key_cbc_decrypt(key16, iv, encRndA_prime, verifyRndA_prime, 8);

  uint8_t expectedRndA_prime[8];
  rotateLeft(rndA, expectedRndA_prime, 8);

  if (memcmp(verifyRndA_prime, expectedRndA_prime, 8) != 0) {
    return 1; 
  }


  bool singleDes = (keyLen == 8) || (memcmp(key16, key16 + 8, 8) == 0);
  if (singleDes) {
    memcpy(gSessionKey, rndA, 4);
    memcpy(gSessionKey + 4, rndB, 4);
    memcpy(gSessionKey + 8, rndA, 4);
    memcpy(gSessionKey + 12, rndB, 4);
    strcpy(gAuthAlgo, (cmdCode == CMD_AUTHENTICATE_LEGACY) ? "des" : "iso");
  } else {
    memcpy(gSessionKey, rndA, 4);
    memcpy(gSessionKey + 4, rndB, 4);
    memcpy(gSessionKey + 8, rndA + 4, 4);
    memcpy(gSessionKey + 12, rndB + 4, 4);
    strcpy(gAuthAlgo, (cmdCode == CMD_AUTHENTICATE_ISO) ? "iso" : "2k3des");
  }

  memset(gSmIv, 0, sizeof(gSmIv));
  gSmBlk = (cmdCode == CMD_AUTHENTICATE_ISO) ? 8 : 0;

  gIsAuthenticated = true;
  gAuthKeyNo = keyNo;
  return 0;
}

static int authenticateAES(uint8_t keyNo, const uint8_t *key16, uint8_t *outStatus) {
  *outStatus = 0xFF;

  uint8_t cmd[2] = { CMD_AUTHENTICATE_AES, keyNo };
  int n = isoDepExchange(cmd, 2, gInf, sizeof(gInf));
  if (n < 1) return -1;
  if (n < 17 || gInf[0] != STATUS_MORE_FRAMES) {
    *outStatus = gInf[0];
    return 1;
  }

  uint8_t encRndB[16];
  memcpy(encRndB, &gInf[1], 16);

  uint8_t iv[16];
  memset(iv, 0, 16);
  uint8_t rndB[16];
  aes128_cbc_decrypt(key16, iv, encRndB, rndB, 16);

  uint8_t rndB_prime[16];
  rotateLeft(rndB, rndB_prime, 16);

  uint8_t rndA[16];
  fillRandom(rndA, 16);

  uint8_t plain[32];
  memcpy(plain, rndA, 16);
  memcpy(plain + 16, rndB_prime, 16);

  memcpy(iv, encRndB, 16);
  uint8_t encToken[32];
  aes128_cbc_encrypt(key16, iv, plain, encToken, 32);

  uint8_t sendBuf[33];
  sendBuf[0] = STATUS_MORE_FRAMES;
  memcpy(sendBuf + 1, encToken, 32);

  n = isoDepExchange(sendBuf, 33, gInf, sizeof(gInf));
  if (n < 1) return -1;
  if (n < 17 || gInf[0] != STATUS_OK) {
    *outStatus = gInf[0];
    return 1;
  }

  uint8_t encRndA_prime[16];
  memcpy(encRndA_prime, &gInf[1], 16);

  memcpy(iv, encToken + 16, 16);
  uint8_t verifyRndA_prime[16];
  aes128_cbc_decrypt(key16, iv, encRndA_prime, verifyRndA_prime, 16);

  uint8_t expectedRndA_prime[16];
  rotateLeft(rndA, expectedRndA_prime, 16);

  if (memcmp(verifyRndA_prime, expectedRndA_prime, 16) != 0) {
    return 1;
  }

  memcpy(gSessionKey, rndA, 4);
  memcpy(gSessionKey + 4, rndB, 4);
  memcpy(gSessionKey + 8, rndA + 12, 4);
  memcpy(gSessionKey + 12, rndB + 12, 4);

  memset(gSmIv, 0, sizeof(gSmIv));     /* EV1 session: AES CMAC, 16 byte blocks */
  gSmBlk = 16;

  gIsAuthenticated = true;
  gAuthKeyNo = keyNo;
  strcpy(gAuthAlgo, "aes");
  return 0;
}

/* ------------------------------------------------------------------ */
/*  DESFire application-level helpers                                  */
/*  selectApplicationX: 0 ok, 1 status fail (*outSt), -1 transport     */
/* ------------------------------------------------------------------ */
static int selectApplicationX(uint32_t aid, uint8_t *outSt) {
  uint8_t cmd[4];
  cmd[0] = CMD_SELECT_APP;
  write3LE(cmd + 1, aid);

  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(cmd, 4, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) return -1;
  if (st != STATUS_OK) {
    if (outSt) *outSt = st;
    return 1;
  }

  gCurrentAID = aid;
  clearAuthState();      
  return 0;
}

static bool selectApplication(uint32_t aid) {
  return selectApplicationX(aid, NULL) == 0;
}

/* ------------------------------------------------------------------ */
/*  Command handlers                                                   */
/* ------------------------------------------------------------------ */

/* Common wrapper: requires a connected card. */
#define REQUIRE_CARD(cmdName)                                       \
  do {                                                              \
    if (!gCardConnected) {                                          \
      sendErr(cmdName, "NO_CARD", NULL, "no card present");         \
      return;                                                       \
    }                                                               \
  } while (0)

static void handleTransportFailCmd(const char *cmd) {
  bool rfFault = gRfFault;         
  handleTransportLoss();
  if (rfFault) sendErr(cmd, "RF_ERROR", NULL, "PN5180 not responding");
  else          sendErr(cmd, "NO_CARD", NULL, "card lost");
}

static void sendStatusErr(const char *cmd, uint8_t st, const char *msg) {
  char h[3];
  toHex2(st, h);
  sendErr(cmd, "STATUS", h, msg);
}

static void cmdPing(const char *cmd) {
  String r;
  r.reserve(112);
  r = F("{\"ok\":true,\"cmd\":\"ping\",\"proto\":1,\"fw\":\"" FW_VERSION "\",\"uptime\":");
  r += (unsigned long)millis();
  r += F(",\"card\":");
  r += gCardConnected ? F("true") : F("false");
  r += '}';
  sendLine(r);
}

static void cmdStatus(const char *cmd) {
  String r;
  r.reserve(200);
  r = F("{\"ok\":true,\"cmd\":\"status\",\"card\":");
  r += gCardConnected ? F("true") : F("false");
  r += F(",\"uid\":\"");
  appendBinHex(r, gCurrentUID, gCurrentUIDLen);
  r += F("\",\"sak\":\"");
  char h[3];
  toHex2(gCurrentSAK, h);
  r += h;
  r += F("\",\"aid\":\"");
  char ah[7];
  aidToHex(gCurrentAID, ah);
  r += ah;
  r += F("\",\"authenticated\":");
  r += gIsAuthenticated ? F("true") : F("false");
  if (gIsAuthenticated) {
    r += F(",\"algo\":\"");
    r += gAuthAlgo;
    r += F("\",\"keyNo\":");
    r += (int)gAuthKeyNo;
    r += F(",\"role\":\"");
    appendEscapedC(r, gAuthRoleName);
    r += '"';
  } else {
    r += F(",\"algo\":null,\"keyNo\":null,\"role\":\"Yok\"");
  }
  r += '}';
  sendLine(r);
}

static void cmdResetScan(const char *cmd) {
  fullRFReset(true);
  String r;
  r.reserve(64);
  r = F("{\"ok\":true,\"cmd\":\"");
  r += cmd;
  r += F("\",\"scanning\":true}");
  sendLine(r);
}

/* version info JSON fragment from 28-byte GetVersion payload (7+7+14) */
static void appendVersionObject(const uint8_t *v7) {
  txPut(F("{\"vendor\":"));
  txPutNum(v7[0]);
  txPut(F(",\"type\":"));
  txPutNum(v7[1]);
  txPut(F(",\"major\":"));
  txPutNum(v7[3]);
  txPut(F(",\"minor\":"));
  txPutNum(v7[4]);
  txPut(F(",\"storage\":"));
  txPutNum(v7[5]);
  txPutChar('}');
}

static void cmdVersion(const char *cmd) {
  REQUIRE_CARD(cmd);

  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireGetVersion(gVer, sizeof(gVer), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "get version failed"); return; }
  if (dlen < 28) {
    /* GetVersion 7+7+14 bayt vermeli; kisa yuk alanlari sifirlardi, bu yuzden
       sifir bildirmek yerine hata ver. EN: needs 7+7+14 bytes else fail. */
    sendErr(cmd, "RF_ERROR", NULL, "short version response");
    return;
  }

  uint8_t v[28];
  memcpy(v, gVer, 28);

  txReset();
  txPut(F("{\"ok\":true,\"cmd\":\"version\",\"hw\":"));
  appendVersionObject(v);
  txPut(F(",\"sw\":"));
  appendVersionObject(v + 7);
  txPut(F(",\"batchNo\":\""));
  txPutBinHex(v + 21, 5);
  txPut(F("\",\"prodWeek\":"));
  txPutNum(v[26]);
  txPut(F(",\"prodYear\":"));
  txPutNum(v[27]);
  txPut(F(",\"uid\":\""));
  txPutBinHex(v + 14, 7);
  txPut(F("\"}"));
  sendTxLine();
}

static int getFreeMemoryX(uint32_t *outBytes, uint8_t *outSt) {
  uint8_t cmd[1] = { CMD_GET_FREE_MEMORY };
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(cmd, 1, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) return -1;
  if (st != STATUS_OK || dlen < 3) {
    *outSt = st;
    return 1;
  }
  *outBytes = read3LE(gResp);
  return 0;
}

/* Dump yanit limitleri. Tampon sert limit; bu iki rezerv kart'a dokunmadan
   ONCE kontrol edilir, buyuk dump bastan reddedilir. EN: size reserves. */
#define DUMP_MAX_RESPONSE 6000
#define DUMP_APP_RESERVE   96
#define DUMP_FILE_RESERVE 192

static void cmdDump(const char *cmd) {
  REQUIRE_CARD(cmd);

  bool deep = false;
  bool btmp = false;
  if (jsonGetBool(gLineBuf, "deep", &btmp)) {
    deep = btmp;
  } else if (jsonFindKey(gLineBuf, "deep") != NULL) {
    sendErr(cmd, "INVALID_PARAM", NULL, "deep must be a boolean");
    return;
  }

  bool wasAuth = gIsAuthenticated;

  /* 1. version */
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireGetVersion(gVer, sizeof(gVer), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "get version failed"); return; }
  if (dlen < 28) {
    sendErr(cmd, "RF_ERROR", NULL, "short version response");
    return;
  }
  uint8_t v[28];
  memcpy(v, gVer, 28);
  emitProgress("dump", 5, "version");

  /* 2. PICC level: free memory + app list */
  uint8_t stSel = 0xFF;
  int s = selectApplicationX(0x000000, &stSel);
  if (s < 0) { handleTransportFailCmd(cmd); return; }
  if (s > 0) { sendStatusErr(cmd, stSel, "select PICC failed"); return; }

  uint32_t freeMem = 0;
  rc = getFreeMemoryX(&freeMem, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (rc > 0) { sendStatusErr(cmd, st, "free memory read failed"); return; }
  emitProgress("dump", 15, "free memory");

  uint8_t aids[90];
  uint16_t aidsLen = 0;
  uint8_t cmdA[1] = { CMD_GET_APP_IDS };
  rc = desfireNative(cmdA, 1, aids, sizeof(aids), &aidsLen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "app list failed"); return; }
  uint16_t appCount = aidsLen / 3;
  emitProgress("dump", 20, "app list");

/* Istek basina tek yanit satiri; tum dump tek STATIK tamponda toplanir (heap
   yok, her yazim sinirli), sigmayan yanit insa sirasinda reddedilir. Durum:
   PICC seviyesi, oturum yok. EN: one reply, static bounds-checked buffer. */
  if (deep) {
    uint32_t need = 1024UL + (uint32_t)appCount * 64UL;
    if ((uint32_t)ESP.getFreeHeap() < need) {
      sendErr(cmd, "BUSY", NULL, "not enough memory for deep dump");
      return;
    }
  }

  /* 3. build the response inside the static buffer */
  txReset();
  txPut(F("{\"ok\":true,\"cmd\":\"dump\",\"authLost\":"));
  txPut(wasAuth ? F("true") : F("false"));
  txPut(F(",\"version\":"));
  appendVersionObject(v);
  txPut(F(",\"freeMemory\":"));
  txPutNum((unsigned long)freeMem);
  txPut(F(",\"apps\":["));

  for (uint16_t i = 0; i < appCount; i++) {
    yield();
    ESP.wdtFeed();

    /* boyut limiti kart'a dokunulmadan ONCE kontrol edilir: sigmayan kayit sona
       kadar insa edilip atilmaz. EN: size checked before the round trip. */
    if (gTxLen > DUMP_MAX_RESPONSE || txRoom() < DUMP_APP_RESERVE) {
      gCurrentAID = 0;
      clearAuthState();
      sendErr(cmd, "BUSY", NULL, "dump response too large");
      return;
    }

    uint32_t aid = read3LE(&aids[i * 3]);
    if (i > 0) txPutChar(',');
    txPut(F("{\"aid\":\""));
    char ah[7];
    aidToHex(aid, ah);
    txPut(ah);
    txPutChar('"');

    if (!deep) {
      txPutChar('}');
      emitProgress("dump", 20 + (int)(((i + 1) * 75UL) / appCount), "app");
      continue;
    }

    bool appFailed = false;
    uint8_t appSt = 0xFF;

    s = selectApplicationX(aid, &appSt);
    if (s < 0) { handleTransportFailCmd(cmd); return; }
    if (s > 0) {
      appFailed = true;
      txPut(F(",\"error\":\"STATUS\""));
    }

    if (!appFailed) {
      uint8_t ksCmd[1] = { CMD_GET_KEY_SETTINGS };
      uint16_t ksLen = 0;
      uint8_t ks[4];
      rc = desfireNative(ksCmd, 1, ks, sizeof(ks), &ksLen, &st);
      if (rc < 0) { handleTransportFailCmd(cmd); return; }
      if (st != STATUS_OK || ksLen < 1) {
        appFailed = true;
        txPut(F(",\"error\":\"STATUS\""));
      } else {
        uint8_t keySettings = ks[0];
        uint8_t maxKeys = (ksLen >= 2) ? ks[1] : 1;
        txPut(F(",\"keySettings\":\""));
        txPutHex2(keySettings);
        txPut(F("\",\"maxKeys\":"));
        txPutNum(maxKeys);
        txPut(F(",\"files\":["));

        uint8_t fCmd[1] = { CMD_GET_FILE_IDS };
        uint8_t fIds[96];
        uint16_t fIdsLen = 0;
        rc = desfireNative(fCmd, 1, fIds, sizeof(fIds), &fIdsLen, &st);
        if (rc < 0) { handleTransportFailCmd(cmd); return; }
        if (st != STATUS_OK) {
          txPut(F("],\"error\":\"STATUS\""));
          appFailed = true;
        } else {
          uint16_t fileCount = fIdsLen / 3;
          for (uint16_t fi = 0; fi < fileCount; fi++) {
            yield();
            ESP.wdtFeed();
            uint8_t fileNo = fIds[fi * 3];

   
            if (gTxLen > DUMP_MAX_RESPONSE || txRoom() < DUMP_FILE_RESERVE) {
              gCurrentAID = 0;
              clearAuthState();
              sendErr(cmd, "BUSY", NULL, "dump response too large");
              return;
            }

            uint8_t fsCmd[2] = { CMD_GET_FILE_SETTINGS, fileNo };
            uint8_t fs[32];
            uint16_t fsLen = 0;
            rc = desfireNative(fsCmd, 2, fs, sizeof(fs), &fsLen, &st);
            if (rc < 0) { handleTransportFailCmd(cmd); return; }

            if (fi > 0) txPutChar(',');
            if (st != STATUS_OK || fsLen < 4) {
              txPut(F("{\"file\":"));
              txPutNum(fileNo);
              txPut(F(",\"error\":\"STATUS\"}"));
              continue;
            }
            txPut(F("{\"file\":"));
            txPutNum(fileNo);
            appendFileSettingsFields(fs, fsLen);
            txPutChar('}');
          }
          txPutChar(']');
        }
      }
    }

    txPutChar('}');
    emitProgress("dump", 20 + (int)(((i + 1) * 75UL) / appCount), "app");
  }

  txPut(F("]}"));
  if (txOverflowed()) {
    gCurrentAID = 0;
    clearAuthState();
    sendErr(cmd, "BUSY", NULL, "dump response too large");
    return;
  }
  emitProgress("dump", 100, "done");


  s = selectApplicationX(0x000000, &stSel);
  if (s < 0) {
    handleTransportFailCmd(cmd);
    return;
  }
  if (s > 0) {

    gCurrentAID = 0;
    clearAuthState();
    emitLog("warn", "final PICC select failed; selection cleared");
  }

  sendTxLine();
}

static void cmdAuth(const char *cmd) {
  REQUIRE_CARD(cmd);

  char algo[12];
  if (!jsonGetString(gLineBuf, "algo", algo, sizeof(algo))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "algo missing");
    return;
  }
  asciiLower(algo);

  long keyNoL = -1;
  if (!jsonGetInt(gLineBuf, "keyNo", &keyNoL) || keyNoL < 0 || keyNoL > 13) {
    sendErr(cmd, "INVALID_PARAM", NULL, "keyNo must be 0..13");
    return;
  }
  uint8_t keyNo = (uint8_t)keyNoL;

  char keyHex[40];
  if (!jsonGetString(gLineBuf, "key", keyHex, sizeof(keyHex))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "key missing");
    return;
  }

  uint8_t key[16];
  int keyLen = 0;
  int expected = -1;
  if      (strcmp(algo, "des") == 0)     expected = 8;
  else if (strcmp(algo, "2k3des") == 0)  expected = 16;
  else if (strcmp(algo, "iso") == 0)     expected = 16;
  else if (strcmp(algo, "aes") == 0)     expected = 16;
  else {
    sendErr(cmd, "INVALID_PARAM", NULL, "algo must be des|2k3des|iso|aes");
    return;
  }

  if (!hexToBin(keyHex, key, 16, &keyLen) || keyLen != expected) {
    sendErr(cmd, "INVALID_PARAM", NULL, "wrong key length");
    return;
  }


  clearAuthState();

  uint8_t st = 0xFF;
  int rc;
  if (strcmp(algo, "aes") == 0) {
    rc = authenticateAES(keyNo, key, &st);
  } else if (strcmp(algo, "iso") == 0) {
    rc = authenticateDES(CMD_AUTHENTICATE_ISO, keyNo, key, 16, &st);
  } else if (strcmp(algo, "2k3des") == 0) {
    rc = authenticateDES(CMD_AUTHENTICATE_LEGACY, keyNo, key, 16, &st);
  } else {
    rc = authenticateDES(CMD_AUTHENTICATE_LEGACY, keyNo, key, 8, &st);
  }

  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (rc > 0) {
    clearAuthState();         
    if (st != 0xFF) {
      char h[3];
      toHex2(st, h);
      sendErr(cmd, "AUTH_FAILED", h, "authentication failed");
    } else {
      sendErr(cmd, "AUTH_FAILED", NULL, "session key verification failed");
    }
    return;
  }

  strcpy(gAuthRoleName, "Manuel");

  String r;
  r.reserve(140);
  r = F("{\"ok\":true,\"cmd\":\"auth\",\"authenticated\":true,\"algo\":\"");
  r += algo;
  r += F("\",\"keyNo\":");
  r += (int)keyNo;
  r += F(",\"sessionKey\":\"");
  appendBinHex(r, gSessionKey, 16);
  r += F("\"}");
  sendLine(r);
}

static void cmdZeroScan(const char *cmd) {
  REQUIRE_CARD(cmd);

  uint32_t target = gCurrentAID;
  static const uint8_t Z8[8] = { 0 };
  static const uint8_t Z16[16] = { 0 };
  static const char *const ALGO_NAMES[4] = { "DES", "2K3DES", "ISO", "AES" };
  static const char *const ALGO_IDS[4] = { "des", "2k3des", "iso", "aes" };

  uint8_t st = 0xFF;

  for (uint8_t k = 0; k <= 4; k++) {
    for (uint8_t v = 0; v < 4; v++) {
      yield();
      ESP.wdtFeed();

      int s = selectApplicationX(target, &st);
      if (s < 0) { handleTransportFailCmd(cmd); return; }
      if (s > 0) {
        clearAuthState();
        gCurrentAID = 0;
        sendStatusErr(cmd, st, "re-select app failed");
        return;
      }

      clearAuthState();

      int rc;
      if (v == 0)      rc = authenticateDES(CMD_AUTHENTICATE_LEGACY, k, Z8, 8, &st);
      else if (v == 1) rc = authenticateDES(CMD_AUTHENTICATE_LEGACY, k, Z16, 16, &st);
      else if (v == 2) rc = authenticateDES(CMD_AUTHENTICATE_ISO, k, Z16, 16, &st);
      else             rc = authenticateAES(k, Z16, &st);

      if (rc < 0) { handleTransportFailCmd(cmd); return; }

      if (rc == 0) {
        strcpy(gAuthRoleName, (v == 0) ? "Zero8-DES" :
                              (v == 1) ? "Zero16-2K3DES" :
                              (v == 2) ? "Zero16-ISODES" : "Zero16-AES");
        char msg[24];
        snprintf(msg, sizeof(msg), "Key %u/5 - %s", (unsigned)(k + 1), ALGO_NAMES[v]);
        emitProgress("zero_scan", (int)(((uint16_t)(k * 4 + v) + 1) * 100UL / 20), msg);

        String r;
        r.reserve(120);
        r = F("{\"ok\":true,\"cmd\":\"zero_scan\",\"found\":true,\"keyNo\":");
        r += (int)k;
        r += F(",\"algo\":\"");
        r += ALGO_IDS[v];
        r += F("\",\"authenticated\":true}");
        sendLine(r);
        return;
      }

      char msg[24];
      snprintf(msg, sizeof(msg), "Key %u/5 - %s", (unsigned)(k + 1), ALGO_NAMES[v]);
      emitProgress("zero_scan", (int)(((uint16_t)(k * 4 + v) + 1) * 100UL / 20), msg);
    }
  }

  clearAuthState();
  if (target != 0) {
    uint8_t stSel = 0xFF;
    if (selectApplicationX(target, &stSel) != 0) {
      gCurrentAID = 0;
      emitLog("warn", "app re-select after zero scan failed");
    }
  }

  sendLine(F("{\"ok\":true,\"cmd\":\"zero_scan\",\"found\":false,\"keyNo\":null,\"algo\":null,\"authenticated\":false}"));
}

static void cmdSelectApp(const char *cmd) {
  REQUIRE_CARD(cmd);

  char aidHexStr[8];
  if (!jsonGetString(gLineBuf, "aid", aidHexStr, sizeof(aidHexStr))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "aid missing");
    return;
  }
  uint32_t aid = 0;
  if (!parseAid6(aidHexStr, &aid)) {
    sendErr(cmd, "INVALID_PARAM", NULL, "aid must be 6 hex chars");
    return;
  }

  bool wasAuth = gIsAuthenticated;

  uint8_t st = 0xFF;
  int s = selectApplicationX(aid, &st);
  if (s < 0) { handleTransportFailCmd(cmd); return; }
  if (s > 0) { sendStatusErr(cmd, st, "select application failed"); return; }

  String r;
  r.reserve(96);
  r = F("{\"ok\":true,\"cmd\":\"select_app\",\"aid\":\"");
  char ah[7];
  aidToHex(aid, ah);
  r += ah;
  r += F("\",\"authLost\":");
  r += wasAuth ? F("true") : F("false");
  r += '}';
  sendLine(r);
}

static void cmdListApps(const char *cmd) {
  REQUIRE_CARD(cmd);

  bool wasAuth = gIsAuthenticated;
  uint32_t prevAID = gCurrentAID;
  uint8_t stSel = 0xFF;


  bool authLost = false;

  if (prevAID != 0) {
    int s = selectApplicationX(0x000000, &stSel);
    if (s < 0) { handleTransportFailCmd(cmd); return; }
    if (s > 0) { sendStatusErr(cmd, stSel, "select PICC failed"); return; }
    authLost = wasAuth;
  }

  uint8_t aids[90];
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  uint8_t cmdA[1] = { CMD_GET_APP_IDS };
  int rc = desfireNative(cmdA, 1, aids, sizeof(aids), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "app list failed"); return; }


  if (prevAID != 0 && !wasAuth) {
    if (selectApplication(prevAID) != 0) {
      gCurrentAID = 0;
      emitLog("warn", "app re-select after list failed");
    }
  } else if (wasAuth) {
    gCurrentAID = 0;
  }

  uint16_t count = dlen / 3;
  String r;
  r.reserve(96 + count * 10);
  r = F("{\"ok\":true,\"cmd\":\"list_apps\",\"authLost\":");
  r += authLost ? F("true") : F("false");
  r += F(",\"aid\":\"");
  char ahCur[7];
  aidToHex(gCurrentAID, ahCur);
  r += ahCur;
  r += F("\",\"apps\":[");
  for (uint16_t i = 0; i < count; i++) {
    if (i > 0) r += ',';
    char ah[7];
    aidToHex(read3LE(&aids[i * 3]), ah);
    r += '"';
    r += ah;
    r += '"';
  }
  r += F("]}");
  sendLine(r);
}

static void cmdCreateApp(const char *cmd) {
  REQUIRE_CARD(cmd);

  char aidHexStr[8];
  if (!jsonGetString(gLineBuf, "aid", aidHexStr, sizeof(aidHexStr))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "aid missing");
    return;
  }
  uint32_t aid = 0;
  if (!parseAid6(aidHexStr, &aid)) {
    sendErr(cmd, "INVALID_PARAM", NULL, "aid must be 6 hex chars");
    return;
  }

  char algo[8];
  if (!jsonGetString(gLineBuf, "algo", algo, sizeof(algo))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "algo missing");
    return;
  }
  asciiLower(algo);
  bool useAES;
  if      (strcmp(algo, "des") == 0 || strcmp(algo, "2k3des") == 0) useAES = false;
  else if (strcmp(algo, "aes") == 0) useAES = true;
  else {
    sendErr(cmd, "INVALID_PARAM", NULL, "algo must be des|2k3des|aes");
    return;
  }

  long keys = 0;
  if (!jsonGetInt(gLineBuf, "keys", &keys) || keys < 1 || keys > 14) {
    sendErr(cmd, "INVALID_PARAM", NULL, "keys must be 1..14");
    return;
  }

  uint8_t c[6];
  c[0] = CMD_CREATE_APP;
  write3LE(c + 1, aid);
  c[4] = 0x0F;
  c[5] = (uint8_t)((useAES ? 0x80 : 0x00) | (keys & 0x0F));

  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 6, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }

  bool already = false;
  if (st == STATUS_DUPLICATE) already = true;
  else if (st != STATUS_OK) { sendStatusErr(cmd, st, "create application failed"); return; }

  String r;
  r.reserve(80);
  r = F("{\"ok\":true,\"cmd\":\"create_app\",\"aid\":\"");
  char ah[7];
  aidToHex(aid, ah);
  r += ah;
  r += F("\",\"alreadyExists\":");
  r += already ? F("true") : F("false");
  r += '}';
  sendLine(r);
}

static void cmdDeleteApp(const char *cmd) {
  REQUIRE_CARD(cmd);

  char aidHexStr[8];
  if (!jsonGetString(gLineBuf, "aid", aidHexStr, sizeof(aidHexStr))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "aid missing");
    return;
  }
  uint32_t aid = 0;
  if (!parseAid6(aidHexStr, &aid)) {
    sendErr(cmd, "INVALID_PARAM", NULL, "aid must be 6 hex chars");
    return;
  }

  uint8_t c[4];
  c[0] = CMD_DELETE_APP;
  write3LE(c + 1, aid);

  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 4, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "delete application failed"); return; }

  if (gCurrentAID == aid) {

    gCurrentAID = 0;
    clearAuthState();
  } else {

  }

  sendLine(F("{\"ok\":true,\"cmd\":\"delete_app\"}"));
}

static void cmdFreeMemory(const char *cmd) {
  REQUIRE_CARD(cmd);

  bool wasAuth = gIsAuthenticated;
  uint32_t prevAID = gCurrentAID;
  uint8_t stSel = 0xFF;


  int s = selectApplicationX(0x000000, &stSel);
  if (s < 0) { handleTransportFailCmd(cmd); return; }
  if (s > 0) { sendStatusErr(cmd, stSel, "select PICC failed"); return; }

  uint32_t bytes = 0;
  uint8_t st = 0xFF;
  int rc = getFreeMemoryX(&bytes, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (rc > 0) { sendStatusErr(cmd, st, "free memory read failed"); return; }


  if (!wasAuth && prevAID != 0) {
    if (selectApplication(prevAID) != 0) {
      gCurrentAID = 0;
      emitLog("warn", "app re-select after free_memory failed");
    }
  }


  String r;
  r.reserve(104);
  r = F("{\"ok\":true,\"cmd\":\"free_memory\",\"bytes\":");
  r += (unsigned long)bytes;
  r += F(",\"authLost\":");
  r += wasAuth ? F("true") : F("false");
  r += F(",\"aid\":\"");
  char ah[7];
  aidToHex(gCurrentAID, ah);
  r += ah;
  r += F("\"}");
  sendLine(r);
}

static void cmdGetKeySettings(const char *cmd) {
  REQUIRE_CARD(cmd);

  uint8_t c[1] = { CMD_GET_KEY_SETTINGS };
  uint8_t out[4];
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 1, out, sizeof(out), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "get key settings failed"); return; }
  if (dlen < 1) { sendErr(cmd, "RF_ERROR", NULL, "empty key settings response"); return; }

  uint8_t maxKeys = (dlen >= 2) ? out[1] : 1;
  String r;
  r.reserve(72);
  r = F("{\"ok\":true,\"cmd\":\"get_key_settings\",\"keySettings\":\"");
  char h[3];
  toHex2(out[0], h);
  r += h;
  r += F("\",\"maxKeys\":");
  r += (int)maxKeys;
  r += '}';
  sendLine(r);
}

static void cmdGetKeyVersion(const char *cmd) {
  REQUIRE_CARD(cmd);

  long keyNoL = -1;
  if (!jsonGetInt(gLineBuf, "keyNo", &keyNoL) || keyNoL < 0 || keyNoL > 13) {
    sendErr(cmd, "INVALID_PARAM", NULL, "keyNo must be 0..13");
    return;
  }

  uint8_t c[2] = { CMD_GET_KEY_VERSION, (uint8_t)keyNoL };
  uint8_t out[2];
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 2, out, sizeof(out), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "get key version failed"); return; }
  if (dlen < 1) { sendErr(cmd, "RF_ERROR", NULL, "empty key version response"); return; }

  String r;
  r.reserve(72);
  r = F("{\"ok\":true,\"cmd\":\"get_key_version\",\"keyNo\":");
  r += (long)keyNoL;
  r += F(",\"version\":\"");
  char h[3];
  toHex2(out[0], h);
  r += h;
  r += F("\"}");
  sendLine(r);
}

static void desfire_xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint8_t len) {
  for (uint8_t i = 0; i < len; i++) dst[i] = a[i] ^ b[i];
}

static void cmdChangeKey(const char *cmd) {
  REQUIRE_CARD(cmd);

  if (!gIsAuthenticated) {
    sendErr(cmd, "AUTH_REQUIRED", NULL, "authentication required - auth first with current key");
    return;
  }

  if (gSessionKey[0] == 0 && gSessionKey[1] == 0 && gSessionKey[2] == 0 && gSessionKey[3] == 0 &&
      gSessionKey[4] == 0 && gSessionKey[5] == 0 && gSessionKey[6] == 0 && gSessionKey[7] == 0 &&
      gSessionKey[8] == 0 && gSessionKey[9] == 0 && gSessionKey[10] == 0 && gSessionKey[11] == 0 &&
      gSessionKey[12] == 0 && gSessionKey[13] == 0 && gSessionKey[14] == 0 && gSessionKey[15] == 0) {
    /* allow if session exists but guard */
  }

  char algo[12];
  if (!jsonGetString(gLineBuf, "algo", algo, sizeof(algo))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "algo missing");
    return;
  }
  asciiLower(algo);

  long keyNoL = -1;
  if (!jsonGetInt(gLineBuf, "keyNo", &keyNoL) || keyNoL < 0 || keyNoL > 13) {
    sendErr(cmd, "INVALID_PARAM", NULL, "keyNo must be 0..13");
    return;
  }
  uint8_t keyNo = (uint8_t)keyNoL;

  char keyHex[40];
  if (!jsonGetString(gLineBuf, "newKey", keyHex, sizeof(keyHex))) {
    sendErr(cmd, "INVALID_PARAM", NULL, "newKey missing");
    return;
  }

  uint8_t newKey[16];
  int keyLen = 0;
  int expected = -1;
  if (strcmp(algo, "des") == 0) {
    expected = 8;
  } else if (strcmp(algo, "2k3des") == 0) {
    expected = 16;
  } else if (strcmp(algo, "iso") == 0) {
    expected = 16;
  } else if (strcmp(algo, "aes") == 0) {
    expected = 16;
  } else {
    sendErr(cmd, "INVALID_PARAM", NULL, "algo must be des|2k3des|iso|aes");
    return;
  }

  bool isAes = (strcmp(algo, "aes") == 0);

  /* PICC master degisimi kripto TIPINI de degistirebilir: gonderilen keyNo
     baytinin ust bitleri yeni tipi tasir (0x80=AES, 0x00=DES/2K3DES). Sadece
     host "typeChange":1 derse; normal app anahtar degisimi tip biti tasimaz.
     Isaretli bayt hem tele hem komut CRC'sine girer. EN: type bits in keyNo. */
  long tcL = 0; jsonGetInt(gLineBuf, "typeChange", &tcL);
  bool typeChange = (tcL != 0);
  uint8_t txKeyNo = keyNo;
  if (typeChange && isAes) txKeyNo |= 0x80;

  if (!hexToBin(keyHex, newKey, 16, &keyLen) || keyLen != expected) {
    sendErr(cmd, "INVALID_PARAM", NULL, "wrong newKey length for algo");
    return;
  }


  uint8_t key16[16];
  memset(key16, 0, sizeof(key16));
  if (expected == 8) {
    memcpy(key16, newKey, 8);
    memcpy(key16 + 8, newKey, 8);
  } else {
    memcpy(key16, newKey, 16);
  }

  /* ChangeKey kriptogrami (EV1), iki durum:
     ayni anahtar: newKey || CRC32(C4|keyNo|newKey)
     farkli: (newKey^oldKey) || CRC32(C4|keyNo|(newKey^oldKey)) || CRC32(newKey)
     Calisan oturum IV'si (gSmIv) ile sifrelenir, HAM gonderilir (CMAC yok).
     Farkli anahtarda host mevcut anahtari "oldKey" verir. Sadece EV1 (ISO/AES);
     legacy 0x0A reddedilir. EN: EV1 ChangeKey cryptogram, sent raw. */
  if (gSmBlk == 0) {
    sendErr(cmd, "UNSUPPORTED", NULL,
            "change_key needs an ISO(0x1A) or AES session (legacy DES not supported)");
    return;
  }

  bool sameKey = (keyNo == gAuthKeyNo);
  uint8_t data16[16];
  if (sameKey) {
    memcpy(data16, key16, 16);
  } else {
    char okHex[40];
    if (!jsonGetString(gLineBuf, "oldKey", okHex, sizeof(okHex))) {
      sendErr(cmd, "INVALID_PARAM", NULL, "oldKey required to change a key other than the authenticated one");
      return;
    }
    uint8_t ob[16]; int ol = 0;
    if (!hexToBin(okHex, ob, 16, &ol) || (ol != 8 && ol != 16)) {
      sendErr(cmd, "INVALID_PARAM", NULL, "oldKey must be 8 or 16 bytes hex");
      return;
    }
    uint8_t oldKey16[16];
    if (ol == 8) { memcpy(oldKey16, ob, 8); memcpy(oldKey16 + 8, ob, 8); }
    else         { memcpy(oldKey16, ob, 16); }
    desfire_xor_block(data16, key16, oldKey16, 16);  
  }

  /* AES anahtarlari 1 bayt versiyon tasir; EV2/EV3 bunu (XOR'lu) anahtardan
     hemen sonra bekler, komut CRC'sine dahil ama yeni-anahtar CRC'sine degil,
     XOR'lanmaz. 3DES/ISO'da yok. Koymamak AES kartta duzeni 1 bayt kaydirir ->
     CRC uymaz -> 1E. EN: AES key-version byte, fixes the 1E error. */
  uint8_t crypto[48];
  memcpy(crypto, data16, 16);
  uint16_t clen = 16;
  if (isAes) crypto[clen++] = 0x00;               

  uint8_t crcIn[19];
  uint16_t ci = 0;
  crcIn[ci++] = CMD_CHANGE_KEY;
  crcIn[ci++] = txKeyNo;
  memcpy(crcIn + ci, data16, 16); ci += 16;
  if (isAes) crcIn[ci++] = 0x00;                
  put32LE(crypto + clen, desfireCrc32(crcIn, ci, 0xFFFFFFFFUL));
  clen += 4;

  if (!sameKey) {                                 
    put32LE(crypto + clen, desfireCrc32(key16, 16, 0xFFFFFFFFUL));
    clen += 4;
  }

  while (clen % gSmBlk) crypto[clen++] = 0x00;    

  smEncrypt(crypto, clen);                    

  uint8_t apdu[2 + sizeof(crypto)];
  apdu[0] = CMD_CHANGE_KEY;
  apdu[1] = txKeyNo;
  memcpy(apdu + 2, crypto, clen);

  int n = isoDepExchange(apdu, (uint8_t)(2 + clen), gInf, sizeof(gInf));
  if (n < 1) { handleTransportFailCmd(cmd); return; }
  uint8_t st = gInf[0];

  /* Auth'lu anahtari degistirmek kart oturumunu bitirir; host sonra YENI
     anahtarla tekrar auth olmali. App secimi korunur. EN: re-auth after. */
  clearAuthState();

  if (st != STATUS_OK) { sendStatusErr(cmd, st, "change key failed"); return; }

  String r;
  r.reserve(80);
  r = F("{\"ok\":true,\"cmd\":\"change_key\",\"keyNo\":");
  r += (int)keyNo;
  r += F(",\"authCleared\":true}");
  sendLine(r);
}

static void cmdGetFileIds(const char *cmd) {
  REQUIRE_CARD(cmd);

  uint8_t c[1] = { CMD_GET_FILE_IDS };
  uint8_t out[96];
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 1, out, sizeof(out), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "get file ids failed"); return; }

  uint16_t count = dlen;
  String r;
  r.reserve(64 + count * 4);
  r = F("{\"ok\":true,\"cmd\":\"get_file_ids\",\"files\":[");
  for (uint16_t i = 0; i < count; i++) {
    if (i > 0) r += ',';
    r += (int)out[i];
  }
  r += F("]}");
  sendLine(r);
}

/* fileType/commMode/accessRights/rw/car/r/w (+boyut veya ham) ekler;
   dlen>=4 gerekir. EN: append file-settings fields. */
static void appendFileSettingsFields(const uint8_t *d, uint16_t dlen) {
  uint8_t ft = d[0];
  uint8_t comm = d[1] & 0x03;
  uint8_t ar1 = d[2];
  uint8_t ar2 = d[3];

  txPut(F(",\"fileType\":"));
  txPutNum(ft);
  txPut(F(",\"commMode\":"));
  txPutNum(comm);
  txPut(F(",\"accessRights\":\""));
  txPutHex2(ar1);
  txPutHex2(ar2);
  txPut(F("\",\"rw\":"));
  txPutNum((uint8_t)(ar1 >> 4));
  txPut(F(",\"car\":"));
  txPutNum((uint8_t)(ar1 & 0x0F));
  txPut(F(",\"r\":"));
  txPutNum((uint8_t)(ar2 >> 4));
  txPut(F(",\"w\":"));
  txPutNum((uint8_t)(ar2 & 0x0F));

  if (ft == 0 || ft == 1) {
    if (dlen >= 7) {
      txPut(F(",\"size\":"));
      txPutNum((unsigned long)read3LE(d + 4));
    } else {
      txPut(F(",\"raw\":\""));
      txPutBinHex(d, dlen);
      txPutChar('"');
    }
  } else {
    txPut(F(",\"raw\":\""));
    txPutBinHex(d, dlen);
    txPutChar('"');
    if (dlen >= 16) {
      txPut(F(",\"lowerLimit\":"));
      txPutSigned((long)read3LE(d + 4));
      txPut(F(",\"upperLimit\":"));
      txPutSigned((long)read3LE(d + 8));
      txPut(F(",\"value\":"));
      txPutSigned((long)read3LE(d + 12));
    }
  }
}

static void cmdGetFileSettings(const char *cmd) {
  REQUIRE_CARD(cmd);

  long fileL = -1;
  if (!jsonGetInt(gLineBuf, "file", &fileL) || fileL < 0 || fileL > 31) {
    sendErr(cmd, "INVALID_PARAM", NULL, "file must be 0..31");
    return;
  }

  uint8_t c[2] = { CMD_GET_FILE_SETTINGS, (uint8_t)fileL };
  uint8_t out[32];
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 2, out, sizeof(out), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "get file settings failed"); return; }
  if (dlen < 4) { sendErr(cmd, "RF_ERROR", NULL, "malformed file settings response"); return; }

  txReset();
  txPut(F("{\"ok\":true,\"cmd\":\"get_file_settings\",\"file\":"));
  txPutNum((unsigned long)fileL);
  appendFileSettingsFields(out, dlen);
  txPutChar('}');
  sendTxLine();
}

static void cmdCreateFile(const char *cmd) {
  REQUIRE_CARD(cmd);

  long fileL = -1, sizeL = -1, commL = -1, rwL = -1, carL = -1, rL = -1, wL = -1;
  if (!jsonGetInt(gLineBuf, "file", &fileL) || fileL < 0 || fileL > 31) {
    sendErr(cmd, "INVALID_PARAM", NULL, "file must be 0..31");
    return;
  }
  if (!jsonGetInt(gLineBuf, "size", &sizeL) || sizeL < 1 || sizeL > 0xFFFFFF) {
    sendErr(cmd, "INVALID_PARAM", NULL, "size must be 1..0xFFFFFF");
    return;
  }
  if (!jsonGetInt(gLineBuf, "comm", &commL) ||
      !(commL == 0 || commL == 1 || commL == 3)) {
    sendErr(cmd, "INVALID_PARAM", NULL, "comm must be 0|1|3");
    return;
  }
  if (!jsonGetInt(gLineBuf, "rw", &rwL)   || rwL < 0 || rwL > 15 ||
      !jsonGetInt(gLineBuf, "car", &carL) || carL < 0 || carL > 15 ||
      !jsonGetInt(gLineBuf, "r", &rL)     || rL < 0 || rL > 15 ||
      !jsonGetInt(gLineBuf, "w", &wL)     || wL < 0 || wL > 15) {
    sendErr(cmd, "INVALID_PARAM", NULL, "access rights must be 0..15");
    return;
  }

  uint8_t c[8];
  c[0] = CMD_CREATE_STD_FILE;
  c[1] = (uint8_t)fileL;
  c[2] = (uint8_t)commL;
  c[3] = (uint8_t)((rwL << 4) | (carL & 0x0F));
  c[4] = (uint8_t)((rL << 4) | (wL & 0x0F));
  write3LE(c + 5, (uint32_t)sizeL);

  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 8, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }

  bool already = false;
  if (st == STATUS_DUPLICATE) already = true;
  else if (st != STATUS_OK) { sendStatusErr(cmd, st, "create file failed"); return; }

  String r;
  r.reserve(64);
  r = F("{\"ok\":true,\"cmd\":\"create_file\",\"file\":");
  r += (long)fileL;
  r += F(",\"alreadyExists\":");
  r += already ? F("true") : F("false");
  r += '}';
  sendLine(r);
}

static void cmdDeleteFile(const char *cmd) {
  REQUIRE_CARD(cmd);

  long fileL = -1;
  if (!jsonGetInt(gLineBuf, "file", &fileL) || fileL < 0 || fileL > 31) {
    sendErr(cmd, "INVALID_PARAM", NULL, "file must be 0..31");
    return;
  }

  uint8_t c[2] = { CMD_DELETE_FILE, (uint8_t)fileL };
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 2, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "delete file failed"); return; }

  sendLine(F("{\"ok\":true,\"cmd\":\"delete_file\"}"));
}

/* ------------------------------------------------------------------ */
/*  File information (used for range and access checks)                 */
/* ------------------------------------------------------------------ */
#define READ_MAX_BYTES    200
#define WRITE_MAX_BYTES   48
#define FILE_SIZE_UNKNOWN 0xFFFFFFFFUL

struct FileInfo {
  uint8_t  type;      /* 0 = standard, 1 = deprecated, other = special */
  uint8_t  comm;      /* communication mode (0 = plain) */
  uint8_t  ar1;       /* access rights 1: read (hi nibble) / change (lo) */
  uint8_t  ar2;       /* access rights 2: write (hi nibble) / read (lo) */
  uint32_t size;      /* file size in bytes */
  bool     hasSize;   /* false for file types without a size field */
};

/* Bir dosyanin ayarlarini okur. 0=basari, -1=transport, pozitif=kart
   reddetti (*outSt status; 2=bozuk yanit). EN: read one file's settings. */
static int getFileInfo(uint8_t file, FileInfo *out, uint8_t *outSt) {
  uint8_t c[2] = { CMD_GET_FILE_SETTINGS, file };
  uint8_t d[32];
  uint16_t dlen = 0;
  uint8_t st = 0xFF;

  out->type = 0;
  out->comm = 0;
  out->ar1 = 0;
  out->ar2 = 0;
  out->size = FILE_SIZE_UNKNOWN;
  out->hasSize = false;
  if (outSt) *outSt = 0xFF;

  int rc = desfireNative(c, 2, d, sizeof(d), &dlen, &st);
  if (rc < 0) return -1;
  if (st != STATUS_OK) { if (outSt) *outSt = st; return 1; }
  if (dlen < 4) return 2;                

  out->type = d[0];
  out->comm = d[1] & 0x03;
  out->ar1  = d[2];
  out->ar2  = d[3];
  if ((out->type == 0 || out->type == 1) && dlen >= 7) {
    out->size = read3LE(d + 4);
    out->hasSize = true;
  }
  return 0;
}

static void cmdChangeFileSettings(const char *cmd) {
  REQUIRE_CARD(cmd);

  long fileL = -1, commL = -1, rwL = -1, carL = -1, rL = -1, wL = -1;
  if (!jsonGetInt(gLineBuf, "file", &fileL) || fileL < 0 || fileL > 31) {
    sendErr(cmd, "INVALID_PARAM", NULL, "file must be 0..31");
    return;
  }
  if (!jsonGetInt(gLineBuf, "comm", &commL) ||
      !(commL == 0 || commL == 1 || commL == 3)) {
    sendErr(cmd, "INVALID_PARAM", NULL, "comm must be 0|1|3");
    return;
  }
  if (!jsonGetInt(gLineBuf, "rw", &rwL)   || rwL < 0 || rwL > 15 ||
      !jsonGetInt(gLineBuf, "car", &carL) || carL < 0 || carL > 15 ||
      !jsonGetInt(gLineBuf, "r", &rL)     || rL < 0 || rL > 15 ||
      !jsonGetInt(gLineBuf, "w", &wL)     || wL < 0 || wL > 15) {
    sendErr(cmd, "INVALID_PARAM", NULL, "access rights must be 0..15");
    return;
  }

  /* Dosya ayarini kimin degistirecegine kart karar verir: "change access
     rights" alani yetkili anahtari belirtir (0x0E=serbest). Guvenli modda
     ayrica sifreli/MAC'li komut ister - firmware yapamaz. EN: CAR gates it. */
  FileInfo fi;
  uint8_t st = 0xFF;
  int frc = getFileInfo((uint8_t)fileL, &fi, &st);
  if (frc < 0) { handleTransportFailCmd(cmd); return; }
  if (frc > 0) {
    if (frc == 2) sendErr(cmd, "RF_ERROR", NULL, "malformed file settings response");
    else          sendStatusErr(cmd, st, "get file settings failed");
    return;
  }
  if (fi.comm == 1) {
    sendErr(cmd, "UNSUPPORTED", NULL, "MACed (comm=1) read not supported; use plain or enciphered");
    return;
  }
  uint8_t changeKey = fi.ar1 & 0x0F;
  if (changeKey != 0x0E) {
    if (!gIsAuthenticated) {
      sendErr(cmd, "AUTH_REQUIRED", NULL, "changing file settings requires an authenticated key");
      return;
    }
    if (gAuthKeyNo != changeKey) {
      char msg[52];
      if (changeKey == 0x0E)
        snprintf(msg, sizeof(msg), "wrong key: only the PICC master key may change this file");
      else
        snprintf(msg, sizeof(msg), "wrong key: this operation needs key %u", (unsigned)changeKey);
      sendErr(cmd, "AUTH_REQUIRED", NULL, msg);
      return;
    }
  }

  uint8_t c[5];
  c[0] = CMD_CHANGE_FILE_SETTINGS;
  c[1] = (uint8_t)fileL;
  c[2] = (uint8_t)(commL & 0x03);
  c[3] = (uint8_t)((rwL << 4) | (carL & 0x0F));
  c[4] = (uint8_t)((rL << 4) | (wL & 0x0F));

  uint16_t dlen = 0;
  int rc = desfireNative(c, 5, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "change file settings failed"); return; }

  sendLine(F("{\"ok\":true,\"cmd\":\"change_file_settings\"}"));
}

static void cmdReadData(const char *cmd) {
  REQUIRE_CARD(cmd);

  long fileL = -1, offsetL = -1, lengthL = -1;
  if (!jsonGetInt(gLineBuf, "file", &fileL) || fileL < 0 || fileL > 31) {
    sendErr(cmd, "INVALID_PARAM", NULL, "file must be 0..31");
    return;
  }
  if (!jsonGetInt(gLineBuf, "offset", &offsetL) || offsetL < 0 || offsetL > 0xFFFFFF) {
    sendErr(cmd, "INVALID_PARAM", NULL, "offset out of range");
    return;
  }
  if (!jsonGetInt(gLineBuf, "length", &lengthL) || lengthL < 0 || lengthL > 0xFFFFFF) {
    sendErr(cmd, "INVALID_PARAM", NULL, "length out of range");
    return;
  }
  /* Gercek dosya boyutunun tek guvenilir kaynagi dosya ayarlari; okuma komutu
     kurulmadan once okunur. Duz olmayan modda okunamaz. EN: read size first. */
  FileInfo fi;
  uint8_t st = 0xFF;
  int frc = getFileInfo((uint8_t)fileL, &fi, &st);
  if (frc < 0) { handleTransportFailCmd(cmd); return; }
  if (frc > 0) {
    if (frc == 2) sendErr(cmd, "RF_ERROR", NULL, "malformed file settings response");
    else          sendStatusErr(cmd, st, "get file settings failed");
    return;
  }
  if (fi.comm != 0) {
    sendErr(cmd, "UNSUPPORTED", NULL, "file is not in plain communication mode");
    return;
  }

  uint32_t want;
  if (fi.hasSize) {
    if ((uint32_t)offsetL > fi.size) {
      sendErr(cmd, "INVALID_PARAM", NULL, "offset is beyond the end of the file");
      return;
    }
    uint32_t avail = fi.size - (uint32_t)offsetL;
    if (lengthL == 0) {
      want = avail < READ_MAX_BYTES ? avail : READ_MAX_BYTES;
    } else {
      if ((uint32_t)lengthL > READ_MAX_BYTES) {
        sendErr(cmd, "INVALID_PARAM", NULL, "length must be 1..200");
        return;
      }
      if ((uint32_t)lengthL > avail) {
        sendErr(cmd, "INVALID_PARAM", NULL, "offset+length exceeds the file size");
        return;
      }
      want = (uint32_t)lengthL;
    }
  } else {
 
    want = (lengthL == 0) ? READ_MAX_BYTES : (uint32_t)lengthL;
    if (want > READ_MAX_BYTES) {
      sendErr(cmd, "INVALID_PARAM", NULL, "length must be 1..200");
      return;
    }
  }
  if (want == 0) {
    sendErr(cmd, "INVALID_PARAM", NULL, "nothing to read at this offset");
    return;
  }

  uint8_t c[8];
  c[0] = CMD_READ_DATA;
  c[1] = (uint8_t)fileL;
  write3LE(c + 2, (uint32_t)offsetL);
  write3LE(c + 5, want);

  if (fi.comm == 3) {
    /* EV1 FULL (sifreli) okuma: baslik acik, yanit = Enc(data||CRC32||pad), CRC32
       (data||0x00); calisan oturum IV'si, HAM. crcOk bildirilir (sert hata
       degil) ki RX-CRC farkliysa baytlar gorunsun. Tek cerceve (<= ~48 bayt).
       EN: EV1 enciphered read, reports crcOk. */
    if (!(gIsAuthenticated && gSmBlk != 0)) {
      sendErr(cmd, "AUTH_REQUIRED", NULL, "enciphered read needs an authenticated session");
      return;
    }
    int ne = isoDepExchange(c, 8, gInf, sizeof(gInf));
    if (ne < 1) { handleTransportFailCmd(cmd); return; }
    uint8_t rst = gInf[0];
    if (rst != STATUS_OK) { clearAuthState(); sendStatusErr(cmd, rst, "enciphered read failed"); return; }
    uint16_t enclen = (uint16_t)(ne - 1);
    uint8_t dec[256];
    if (enclen == 0 || (enclen % gSmBlk) != 0 || enclen > sizeof(dec)) {
      clearAuthState(); sendErr(cmd, "RF_ERROR", NULL, "bad enciphered read length"); return;
    }
    memcpy(dec, gInf + 1, enclen);
    smDecrypt(dec, enclen);
    clearAuthState();
    bool crcOk = false;
    if ((uint32_t)want + 4 <= enclen) {
      /* EV1 RX-CRC (data||0x00); desfireCrc32 seed ile devam, ek tampon gerekmez.
         EN: RX-CRC over data||0x00, resumable. */
      uint8_t zero = 0x00;
      uint32_t calc = desfireCrc32(dec, (uint16_t)want, 0xFFFFFFFFUL);
      calc = desfireCrc32(&zero, 1, calc);
      uint32_t got = (uint32_t)dec[want] | ((uint32_t)dec[want + 1] << 8) |
                     ((uint32_t)dec[want + 2] << 16) | ((uint32_t)dec[want + 3] << 24);
      crcOk = (calc == got);
    }
    String etext; etext.reserve((size_t)want);
    for (uint16_t i = 0; i < (uint16_t)want; i++) { uint8_t ch = dec[i]; if (ch >= 0x20 && ch < 0x7F) etext += (char)ch; }
    String er; er.reserve(96 + (size_t)want * 2 + etext.length() + 16);
    er = F("{\"ok\":true,\"cmd\":\"read_data\",\"file\":");
    er += (long)fileL;
    er += F(",\"offset\":"); er += (long)offsetL;
    er += F(",\"enciphered\":true,\"crcOk\":"); er += (crcOk ? F("true") : F("false"));
    er += F(",\"bytes\":\""); appendBinHex(er, dec, (uint16_t)want);
    er += F("\",\"text\":\""); appendEscaped(er, etext); er += F("\"}");
    sendLine(er);
    return;
  }

  uint16_t dlen = 0;
  int rc = desfireNative(c, 8, gRead, sizeof(gRead), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "read data failed"); return; }

  String text;
  text.reserve(dlen);
  for (uint16_t i = 0; i < dlen; i++) {
    uint8_t ch = gRead[i];
    if (ch >= 0x20 && ch < 0x7F) text += (char)ch;
  }

  String r;
  r.reserve(96 + dlen * 2 + text.length() + 8);
  r = F("{\"ok\":true,\"cmd\":\"read_data\",\"file\":");
  r += (long)fileL;
  r += F(",\"offset\":");
  r += (long)offsetL;
  r += F(",\"bytes\":\"");
  appendBinHex(r, gRead, dlen);
  r += F("\",\"text\":\"");
  appendEscaped(r, text);
  r += F("\"}");
  sendLine(r);
}

static void cmdWriteData(const char *cmd) {
  REQUIRE_CARD(cmd);

  long fileL = -1, offsetL = -1;
  if (!jsonGetInt(gLineBuf, "file", &fileL) || fileL < 0 || fileL > 31) {
    sendErr(cmd, "INVALID_PARAM", NULL, "file must be 0..31");
    return;
  }
  if (!jsonGetInt(gLineBuf, "offset", &offsetL) || offsetL < 0 || offsetL > 0xFFFFFF) {
    sendErr(cmd, "INVALID_PARAM", NULL, "offset out of range");
    return;
  }

  char hexStr[2 * WRITE_MAX_BYTES + 4];
  if (!jsonGetString(gLineBuf, "hex", hexStr, sizeof(hexStr))) {
    if (jsonFindKey(gLineBuf, "hex") != NULL)
      sendErr(cmd, "INVALID_PARAM", NULL, "max 48 bytes per write");
    else
      sendErr(cmd, "INVALID_PARAM", NULL, "hex missing");
    return;
  }

  uint8_t data[WRITE_MAX_BYTES];
  int len = 0;
  if (!hexToBin(hexStr, data, WRITE_MAX_BYTES, &len)) {
    size_t n = strlen(hexStr);
    if (n > (size_t)(2 * WRITE_MAX_BYTES)) sendErr(cmd, "INVALID_PARAM", NULL, "max 48 bytes per write");
    else                                   sendErr(cmd, "INVALID_PARAM", NULL, "invalid hex data");
    return;
  }
  if (len == 0) {
    sendErr(cmd, "INVALID_PARAM", NULL, "empty write data");
    return;
  }

  /* Yazma dosya icinde kalmali: gercek boyut dosya ayarlarindan gelir, komut
     kurulmadan once okunur. Guvenli mesajlasma dosyalari reddedilir.
     EN: bound write by file size. */
  FileInfo fi;
  uint8_t st = 0xFF;
  int frc = getFileInfo((uint8_t)fileL, &fi, &st);
  if (frc < 0) { handleTransportFailCmd(cmd); return; }
  if (frc > 0) {
    if (frc == 2) sendErr(cmd, "RF_ERROR", NULL, "malformed file settings response");
    else          sendStatusErr(cmd, st, "get file settings failed");
    return;
  }
  if (fi.comm == 1) {
    sendErr(cmd, "UNSUPPORTED", NULL, "MACed (comm=1) write not supported; use plain or enciphered");
    return;
  }
  if (fi.hasSize) {
    if ((uint32_t)offsetL > fi.size) {
      sendErr(cmd, "INVALID_PARAM", NULL, "offset is beyond the end of the file");
      return;
    }
    if ((uint32_t)offsetL + (uint32_t)len > fi.size) {
      sendErr(cmd, "INVALID_PARAM", NULL, "write would exceed the file size");
      return;
    }
  } else if ((uint32_t)offsetL + (uint32_t)len > 0xFFFFFFUL) {
    sendErr(cmd, "INVALID_PARAM", NULL, "offset+length out of range");
    return;
  }

  if (fi.comm == 3) {
    /* EV1 FULL (sifreli) yazma: alan = Enc(data||CRC32||pad), CRC32
       Cmd|fileNo|offset|length|data; baslik acik, calisan oturum IV'si, ek
       CMAC yok. STATUS_OK = kart CRC'yi kabul etti. HAM gonderilir.
       EN: EV1 enciphered write, sent raw. */
    if (!(gIsAuthenticated && gSmBlk != 0)) {
      sendErr(cmd, "AUTH_REQUIRED", NULL, "enciphered write needs an authenticated session");
      return;
    }
    uint8_t crcbuf[8 + WRITE_MAX_BYTES];
    crcbuf[0] = CMD_WRITE_DATA;
    crcbuf[1] = (uint8_t)fileL;
    write3LE(crcbuf + 2, (uint32_t)offsetL);
    write3LE(crcbuf + 5, (uint32_t)len);
    memcpy(crcbuf + 8, data, (size_t)len);
    uint32_t crc = desfireCrc32(crcbuf, (uint16_t)(8 + len), 0xFFFFFFFFUL);

    uint8_t enc[WRITE_MAX_BYTES + 4 + 16];
    memcpy(enc, data, (size_t)len);
    put32LE(enc + len, crc);
    uint16_t elen = (uint16_t)(len + 4);
    while (elen % gSmBlk) enc[elen++] = 0x00;
    smEncrypt(enc, elen);

    uint8_t apdu[8 + sizeof(enc)];
    apdu[0] = CMD_WRITE_DATA;
    apdu[1] = (uint8_t)fileL;
    write3LE(apdu + 2, (uint32_t)offsetL);
    write3LE(apdu + 5, (uint32_t)len);
    memcpy(apdu + 8, enc, elen);

    int n = isoDepExchange(apdu, (uint8_t)(8 + elen), gInf, sizeof(gInf));
    if (n < 1) { handleTransportFailCmd(cmd); return; }
    uint8_t wst = gInf[0];
    clearAuthState();
    if (wst != STATUS_OK) { sendStatusErr(cmd, wst, "enciphered write failed"); return; }
  } else {
    uint8_t c[8 + WRITE_MAX_BYTES];
    c[0] = CMD_WRITE_DATA;
    c[1] = (uint8_t)fileL;
    write3LE(c + 2, (uint32_t)offsetL);
    write3LE(c + 5, (uint32_t)len);
    memcpy(c + 8, data, (size_t)len);

    uint16_t dlen = 0;
    int rc = desfireNative(c, (uint8_t)(8 + len), gResp, sizeof(gResp), &dlen, &st);
    if (rc < 0) { handleTransportFailCmd(cmd); return; }
    if (st != STATUS_OK) { sendStatusErr(cmd, st, "write data failed"); return; }
  }

  String r;
  r.reserve(56);
  r = F("{\"ok\":true,\"cmd\":\"write_data\",\"written\":");
  r += len;
  r += '}';
  sendLine(r);
}

/* ------------------------------------------------------------------ */
/*  Format confirmation                                                  */
/*                                                                     */
/*  Erasing a card is not undoable, so it is done in two phases:       */
/*    1) {"cmd":"format","confirm":true}     -> a one time token      */
/*    2) {"cmd":"format","confirm":true,"token":"<token>"} -> erase    */
/*  The token is bound to the card that is present and expires, so a   */
/*  stray "confirm:true" can never wipe a card.  The token state and   */
/*  clearFormatToken() live next to the other session state.           */
/* ------------------------------------------------------------------ */

static void cmdFormat(const char *cmd) {
  REQUIRE_CARD(cmd);

  bool confirm = false;
  if (!jsonGetBool(gLineBuf, "confirm", &confirm) || !confirm) {
    sendErr(cmd, "INVALID_PARAM", NULL, "confirm must be true");
    return;
  }

  char token[17];
  bool haveToken = jsonGetString(gLineBuf, "token", token, sizeof(token));

  if (!haveToken) {

    uint8_t rnd[8];
    fillRandom(rnd, sizeof(rnd));
    for (uint8_t i = 0; i < 8; i++) toHex2(rnd[i], gFormatToken + i * 2);
    gFormatToken[16] = 0;
    gFormatTokenAt = millis();
    gFormatTokenUidLen = gCurrentUIDLen;
    if (gFormatTokenUidLen > 7) gFormatTokenUidLen = 7;
    memcpy(gFormatTokenUid, gCurrentUID, gFormatTokenUidLen);

    String r;
    r.reserve(96);
    r = F("{\"ok\":true,\"cmd\":\"format\",\"stage\":\"confirm\",\"token\":\"");
    r += gFormatToken;
    r += F("\",\"expiresInMs\":");
    r += (unsigned long)FORMAT_CONFIRM_TTL_MS;
    r += '}';
    sendLine(r);
    return;
  }


  char want[17];
  strncpy(want, gFormatToken, sizeof(want));
  asciiLower(want);
  asciiLower(token);

  bool tokenOk = (strlen(token) == 16) && (strcmp(want, token) == 0);
  if (tokenOk && (millis() - gFormatTokenAt) > FORMAT_CONFIRM_TTL_MS) tokenOk = false;
  if (tokenOk && gFormatTokenUidLen != gCurrentUIDLen) tokenOk = false;
  if (tokenOk && gFormatTokenUidLen > 0 &&
      memcmp(gFormatTokenUid, gCurrentUID, gFormatTokenUidLen) != 0) tokenOk = false;

  gFormatToken[0] = 0;               

  if (!tokenOk) {
    sendErr(cmd, "INVALID_PARAM", NULL, "invalid or expired confirmation token");
    return;
  }

  uint8_t c[1] = { CMD_FORMAT_PICC };
  uint16_t dlen = 0;
  uint8_t st = 0xFF;
  int rc = desfireNative(c, 1, gResp, sizeof(gResp), &dlen, &st);
  if (rc < 0) { handleTransportFailCmd(cmd); return; }
  if (st != STATUS_OK) { sendStatusErr(cmd, st, "format failed"); return; }

  /* the card is wiped: no session key and no app selection survive */
  clearAuthState();
  gCurrentAID = 0;

  sendLine(F("{\"ok\":true,\"cmd\":\"format\",\"formatted\":true}"));
}

/* ------------------------------------------------------------------ */
/*  Line dispatcher                                                    */
/* ------------------------------------------------------------------ */
static void handleLine(const char *line) {
  const char *s = skipWs(line);
  size_t L = strlen(s);
  while (L > 0 && (s[L - 1] == ' ' || s[L - 1] == '\t' || s[L - 1] == '\r')) L--;

  bool shapeOk = (L >= 2 && s[0] == '{' && s[L - 1] == '}');

  char cmdBuf[32];
  bool hasCmd = jsonGetString(line, "cmd", cmdBuf, sizeof(cmdBuf));

  if (!shapeOk || !hasCmd) {
    sendErr(hasCmd ? cmdBuf : "", "BAD_JSON", NULL,
            shapeOk ? "cmd missing" : "malformed JSON object");
    return;
  }

  const char *cmd = cmdBuf;

  /* Bir sey yapmadan once tum dokumani dogrula: dengesiz parantez / yarim
     string'li istek yari-ayristirilmamali. EN: validate full JSON first. */
  if (!jsonValidate(line)) {
    sendErr(cmd, "BAD_JSON", NULL, "invalid JSON structure");
    return;
  }

  if      (strcmp(cmd, "ping") == 0)                 cmdPing(cmd);
  else if (strcmp(cmd, "status") == 0)               cmdStatus(cmd);
  else if (strcmp(cmd, "reset") == 0)                cmdResetScan(cmd);
  else if (strcmp(cmd, "scan") == 0)                 cmdResetScan(cmd);
  else if (strcmp(cmd, "version") == 0)              cmdVersion(cmd);
  else if (strcmp(cmd, "dump") == 0)                 cmdDump(cmd);
  else if (strcmp(cmd, "auth") == 0)                 cmdAuth(cmd);
  else if (strcmp(cmd, "zero_scan") == 0)            cmdZeroScan(cmd);
  else if (strcmp(cmd, "select_app") == 0)           cmdSelectApp(cmd);
  else if (strcmp(cmd, "list_apps") == 0)            cmdListApps(cmd);
  else if (strcmp(cmd, "create_app") == 0)           cmdCreateApp(cmd);
  else if (strcmp(cmd, "delete_app") == 0)           cmdDeleteApp(cmd);
  else if (strcmp(cmd, "free_memory") == 0)          cmdFreeMemory(cmd);
  else if (strcmp(cmd, "get_key_settings") == 0)     cmdGetKeySettings(cmd);
  else if (strcmp(cmd, "get_key_version") == 0)      cmdGetKeyVersion(cmd);
  else if (strcmp(cmd, "change_key") == 0)           cmdChangeKey(cmd);
  else if (strcmp(cmd, "get_file_ids") == 0)         cmdGetFileIds(cmd);
  else if (strcmp(cmd, "get_file_settings") == 0)    cmdGetFileSettings(cmd);
  else if (strcmp(cmd, "create_file") == 0)          cmdCreateFile(cmd);
  else if (strcmp(cmd, "delete_file") == 0)          cmdDeleteFile(cmd);
  else if (strcmp(cmd, "change_file_settings") == 0) cmdChangeFileSettings(cmd);
  else if (strcmp(cmd, "read_data") == 0)            cmdReadData(cmd);
  else if (strcmp(cmd, "write_data") == 0)           cmdWriteData(cmd);
  else if (strcmp(cmd, "format") == 0)               cmdFormat(cmd);
  else                                               sendErr(cmd, "UNKNOWN_CMD", NULL, "unknown command");
}

/* ------------------------------------------------------------------ */
/*  Arduino entry points                                               */
/* ------------------------------------------------------------------ */
void setup() {
  Serial.setRxBufferSize(1024);
  Serial.begin(115200);
  delay(400);

  pinMode(LED_PIN, OUTPUT);
  ledOff();

  /* nfc.begin() sadece SPI+NSS ayarlar, bloklanmaz. Kutuphanenin nfc.reset()'i
     KULLANILMAZ: gelmeyen IRQ bekler (boot'ta tekrarli soft WDT). Donanim
     reset ayni temiz durumu beklemeden verir. EN: HW reset at boot. */
  nfc.begin();
  pn5180HardReset();

  bool rfOk = pn5180Reinit(false);
  if (!rfOk) rfOk = pn5180Reinit(true);  

  clearAuthState();
  clearFormatToken();
  gLastPoll = 0;
  gLastProbe = 0;

  Serial.println(F("{\"event\":\"boot\",\"fw\":\"" FW_VERSION "\",\"proto\":1}"));
  if (!rfOk) emitLog("error", "PN5180 RF configuration failed (BUSY stuck)");
}

void loop() {
  yield();
  ESP.wdtFeed();

  /* ---- serial input assembly (non-blocking) ---- */
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      if (gLineOverflow) {
        /* tasmis satir basini kaybetti: tamamini at ve bir kez bildir. gLineLen
           onemsiz (LINE_MAX'ta durdu), sonraki isteğe durum sizmaz.
           EN: drop the whole overflowed line, report once. */
        sendErr("", "BAD_JSON", NULL, "line too long");
        gLineOverflow = false;
        gLineLen = 0;
        continue;
      }
      gLineBuf[gLineLen] = 0;
      if (gLineLen > 0) handleLine(gLineBuf);
      gLineLen = 0;
      continue;
    }
    if (gLineLen < LINE_MAX) gLineBuf[gLineLen++] = c;
    else gLineOverflow = true;  
  }

  /* ---- card scanning / presence supervision ---- */
  uint32_t now = millis();

  if (!gCardConnected) {
    if (now - gLastPoll >= 250) {
      gLastPoll = now;
      ledOn();
      delay(5);
      ledOff();
      connectCard();
    }
    return;
  }

  /* baglantida: varlik yokla. GET_VERSION sifrelenmez/MAC'lenmez, auth'dayken
     de guvenli; auth'dayken atlamak re-tap cikarmada gCardConnected takili
     birakip olu ISO-DEP oturumunu kullandiriyordu. Cadence kendi zamanlayicisi.
     EN: probe while connected; own timer, safe during auth. */
  if (now - gLastProbe >= PROBE_INTERVAL_MS) {
    gLastProbe = now;
    /* EV1 (ISO/AES) oturumu GET_VERSION'u CMAC'ler; yoklama o zaman yanit-MAC
       kontrolunu tetikleyip karti kaybetmeden clearAuthState yapabilir (oturum
       auth'tan birkac yuz ms sonra olur). Boyle oturum acikken yoklamayi atla.
       EN: skip probe during EV1 session. */
    if (!(gIsAuthenticated && gSmBlk != 0)) presenceProbe();
  }
}
