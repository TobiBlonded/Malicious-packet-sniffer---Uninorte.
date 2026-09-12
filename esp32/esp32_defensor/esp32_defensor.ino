// ESP32-S3 DEFENSOR -- modo promiscuo, detecta deauth/disassoc floods
// y manda el evento al servidor FastAPI por HTTP POST.
//
// Requiere: estar conectado a la misma red que el router de pruebas
// (usamos la conexión STA para tener IP y poder mandar el HTTP,
// el sniffing promiscuo se hace en paralelo en el mismo canal).

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "esp_wifi.h"

// ---- Configuración de red (mismo router de pruebas) ----
const char* ssid = "COPACO-LTE-4G-8C61";
const char* password = "80M9GFEFT44";

// ---- Configuración del servidor (ajustá con la IP de tu miniserver) ----
const char* SERVER_URL = "http://192.168.1.103:8000/evento";

// ---- Umbral de detección ----
const int UMBRAL_DEAUTH_POR_SEGUNDO = 10;
const unsigned long VENTANA_MS = 1000;

// Boton de prueba: conectado entre GPIO 4 y GND.
// INPUT_PULLUP mantiene el pin en HIGH; una pulsacion lo lleva a LOW.
const int PIN_BOTON_PRUEBA = 4;
const unsigned long DEBOUNCE_MS = 50;
bool ultimaLecturaBoton = HIGH;
bool estadoBoton = HIGH;
unsigned long ultimoCambioBoton = 0;

// Estructura mínima de un frame 802.11 para leer el frame control y las MACs
typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6]; // destino
  uint8_t addr2[6]; // origen
  uint8_t addr3[6]; // bssid
} wifi_ieee80211_mac_hdr_t;

// Contadores para detectar flood por MAC origen
struct ContadorMac {
  uint8_t mac[6];
  int contador;
  unsigned long inicio_ventana;
};

#define MAX_MACS_TRACKEADAS 20
ContadorMac contadores[MAX_MACS_TRACKEADAS];
int cantidad_contadores = 0;

String macToString(const uint8_t* mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void enviarEvento(String tipo, String macOrigen, String bssid, float pps, int canal) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("No hay WiFi, no se puede enviar el evento");
    return;
  }

  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");

  StaticJsonDocument<256> doc;
  doc["tipo"] = tipo;
  doc["mac_origen"] = macOrigen;
  doc["bssid_objetivo"] = bssid;
  doc["paquetes_por_segundo"] = pps;
  doc["canal"] = canal;

  String jsonStr;
  serializeJson(doc, jsonStr);

  int codigoRespuesta = http.POST(jsonStr);
  Serial.printf("Evento enviado -> HTTP %d\n", codigoRespuesta);
  http.end();
}

// Prueba segura: genera el mismo evento que veria el servidor ante un flood,
// pero no transmite ninguna trama WiFi ni desconecta dispositivos.
void enviarPruebaDeauthFlood() {
  String bssid = WiFi.BSSIDstr();
  if (bssid.length() == 0) {
    bssid = "AA:BB:CC:DD:EE:FF";
  }

  Serial.println(">>> Prueba de deauth_flood enviada por boton");
  enviarEvento(
    "deauth_flood_simulado",
    "DE:AD:BE:EF:00:01", // MAC ficticia usada solo en la simulacion
    bssid,
    25.0,
    WiFi.channel()
  );
}

// Se llama por cada paquete capturado en modo promiscuo
void IRAM_ATTR callback_paquete(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return; // solo nos interesan frames de management

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_ieee80211_mac_hdr_t* hdr = (wifi_ieee80211_mac_hdr_t*)pkt->payload;

  uint8_t frame_type = (hdr->frame_ctrl & 0x000C) >> 2;
  uint8_t frame_subtype = (hdr->frame_ctrl & 0x00F0) >> 4;

  // type 0 = management; subtype 12 (0x0C) = deauth, subtype 10 (0x0A) = disassoc
  if (frame_type != 0) return;
  if (frame_subtype != 12 && frame_subtype != 10) return;

  unsigned long ahora = millis();
  String macStr = macToString(hdr->addr2);

  // Buscar si ya trackeamos esta MAC
  int idx = -1;
  for (int i = 0; i < cantidad_contadores; i++) {
    if (memcmp(contadores[i].mac, hdr->addr2, 6) == 0) {
      idx = i;
      break;
    }
  }

  if (idx == -1 && cantidad_contadores < MAX_MACS_TRACKEADAS) {
    idx = cantidad_contadores++;
    memcpy(contadores[idx].mac, hdr->addr2, 6);
    contadores[idx].contador = 0;
    contadores[idx].inicio_ventana = ahora;
  }
  if (idx == -1) return; // tabla llena, ignoramos nuevas MACs por ahora

  // Reiniciar ventana si pasó más de VENTANA_MS
  if (ahora - contadores[idx].inicio_ventana > VENTANA_MS) {
    contadores[idx].contador = 0;
    contadores[idx].inicio_ventana = ahora;
  }

  contadores[idx].contador++;

  if (contadores[idx].contador >= UMBRAL_DEAUTH_POR_SEGUNDO) {
    String tipo = (frame_subtype == 12) ? "deauth_flood" : "disassoc_flood";
    String bssid = macToString(hdr->addr3);
    float pps = contadores[idx].contador * (1000.0 / VENTANA_MS);
    int canal = pkt->rx_ctrl.channel;

    Serial.printf(">>> %s detectado! MAC origen: %s, %.0f pps\n",
                  tipo.c_str(), macStr.c_str(), pps);

    enviarEvento(tipo, macStr, bssid, pps, canal);

    // Reiniciamos el contador para no spamear el servidor con el mismo evento
    contadores[idx].contador = 0;
    contadores[idx].inicio_ventana = ahora;
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("Conectando a WiFi...");
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  int intentos = 0;
  while (WiFi.status() != WL_CONNECTED && intentos < 30) {
    delay(500);
    Serial.print(".");
    intentos++;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\nNo se pudo conectar. Reiniciando...");
    ESP.restart();
  }

  Serial.println("\n¡Conectado!");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());
  Serial.print("Canal WiFi actual: ");
  Serial.println(WiFi.channel());

  pinMode(PIN_BOTON_PRUEBA, INPUT_PULLUP);

  // Activar modo promiscuo -- queda escuchando en el mismo canal
  // donde está conectado el STA (el canal del router de pruebas)
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&callback_paquete);

  Serial.println("Modo promiscuo activado. Escuchando deauth/disassoc...");
}

void loop() {
  // Detecta la pulsacion con anti-rebote. El sniffing sigue en el callback.
  bool lectura = digitalRead(PIN_BOTON_PRUEBA);

  if (lectura != ultimaLecturaBoton) {
    ultimoCambioBoton = millis();
  }

  if (millis() - ultimoCambioBoton > DEBOUNCE_MS && lectura != estadoBoton) {
    estadoBoton = lectura;
    if (estadoBoton == LOW) {
      enviarPruebaDeauthFlood();
    }
  }

  ultimaLecturaBoton = lectura;
  delay(10);
}
