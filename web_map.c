/*
 * Built-in web map server for Iridium ring alerts and satellites
 *
 * Minimal HTTP server with SSE (Server-Sent Events) for real-time
 * map updates. Uses Leaflet.js + OpenStreetMap for visualization.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Built-in web map server for Iridium ring alerts and satellites
 *
 * Minimal HTTP server with SSE (Server-Sent Events) for real-time
 * map updates. Uses Leaflet.js + OpenStreetMap for visualization.
 *
 * Two endpoints:
 *   GET /           → embedded HTML/JS map page
 *   GET /api/events → SSE stream (1 Hz JSON updates)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "web_map.h"

/* ---- Configuration ---- */

#define MAX_RA_POINTS   2000
#define MAX_SATELLITES  100
#define MAX_SSE_CLIENTS 8
#define JSON_BUF_SIZE   65536
#define HTTP_BUF_SIZE   4096

/* ---- SSE client count ---- */
static atomic_int sse_client_count = 0;

/* ---- Shared state ---- */

typedef struct {
    double lat, lon;
    int alt;
    int sat_id, beam_id;
    int n_pages;
    uint32_t tmsi;
    double frequency;
    uint64_t timestamp;
} ra_point_t;

typedef struct {
    int sat_id;
    int beam_id;
    uint64_t last_seen;
    int count;
} sat_entry_t;

static struct {
    pthread_mutex_t lock;
    ra_point_t ra[MAX_RA_POINTS];
    int ra_head;
    int ra_count;
    sat_entry_t sats[MAX_SATELLITES];
    int n_sats;
    unsigned long total_ira;
    unsigned long total_ibc;
    unsigned long total_pages;
    /* Doppler positioning receiver estimate */
    double rx_lat, rx_lon;
    double rx_hdop;
    int rx_valid;
} state;

/* ---- Server state ---- */

static int server_fd = -1;
static pthread_t server_thread;
static volatile int server_running = 0;

/* ---- State update functions (thread-safe) ---- */

void web_map_add_ra(const ira_data_t *ra, uint64_t timestamp,
                     double frequency)
{
    /* Sanity check coordinates and altitude (Iridium orbits ~780 km) */
    if (ra->lat < -90 || ra->lat > 90 || ra->lon < -180 || ra->lon > 180)
        return;
    if (ra->sat_id == 0 && ra->beam_id == 0 && ra->lat == 0 && ra->lon == 0)
        return;
    if (ra->alt < 700 || ra->alt > 900)
        return;

    pthread_mutex_lock(&state.lock);

    ra_point_t *p = &state.ra[state.ra_head];
    p->lat = ra->lat;
    p->lon = ra->lon;
    p->alt = ra->alt;
    p->sat_id = ra->sat_id;
    p->beam_id = ra->beam_id;
    p->n_pages = ra->n_pages;
    p->tmsi = (ra->n_pages > 0) ? ra->pages[0].tmsi : 0;
    p->frequency = frequency;
    p->timestamp = timestamp;

    state.ra_head = (state.ra_head + 1) % MAX_RA_POINTS;
    if (state.ra_count < MAX_RA_POINTS)
        state.ra_count++;
    state.total_ira++;
    if (ra->n_pages > 0)
        state.total_pages++;

    pthread_mutex_unlock(&state.lock);
}

void web_map_add_sat(const ibc_data_t *ibc, uint64_t timestamp)
{
    if (ibc->sat_id == 0) return;

    pthread_mutex_lock(&state.lock);

    /* Find or create satellite entry */
    int idx = -1;
    for (int i = 0; i < state.n_sats; i++) {
        if (state.sats[i].sat_id == ibc->sat_id) {
            idx = i;
            break;
        }
    }

    if (idx < 0 && state.n_sats < MAX_SATELLITES) {
        idx = state.n_sats++;
        state.sats[idx].sat_id = ibc->sat_id;
        state.sats[idx].count = 0;
    }

    if (idx >= 0) {
        state.sats[idx].beam_id = ibc->beam_id;
        state.sats[idx].last_seen = timestamp;
        state.sats[idx].count++;
    }
    state.total_ibc++;

    pthread_mutex_unlock(&state.lock);
}

void web_map_set_position(double lat, double lon, double hdop)
{
    pthread_mutex_lock(&state.lock);
    state.rx_lat = lat;
    state.rx_lon = lon;
    state.rx_hdop = hdop;
    state.rx_valid = 1;
    pthread_mutex_unlock(&state.lock);
}

/* ---- JSON serialization ---- */

static int build_json(char *buf, int bufsize)
{
    pthread_mutex_lock(&state.lock);

    int off = 0;
    off += snprintf(buf + off, bufsize - off,
                    "{\"total_ira\":%lu,\"total_ibc\":%lu,\"total_pages\":%lu,",
                    state.total_ira, state.total_ibc, state.total_pages);

    /* Ring alert points (most recent first, max 500 for browser) */
    off += snprintf(buf + off, bufsize - off, "\"ra\":[");
    int n_out = 0;
    int max_out = 500;
    for (int i = 0; i < state.ra_count && n_out < max_out; i++) {
        int idx = (state.ra_head - 1 - i + MAX_RA_POINTS) % MAX_RA_POINTS;
        ra_point_t *p = &state.ra[idx];
        if (n_out > 0) off += snprintf(buf + off, bufsize - off, ",");
        off += snprintf(buf + off, bufsize - off,
            "{\"lat\":%.4f,\"lon\":%.4f,\"alt\":%d,"
            "\"sat\":%d,\"beam\":%d,\"pages\":%d,"
            "\"tmsi\":%u,\"freq\":%.0f,\"t\":%llu}",
            p->lat, p->lon, p->alt,
            p->sat_id, p->beam_id, p->n_pages,
            p->tmsi, p->frequency,
            (unsigned long long)(p->timestamp / 1000000000ULL));
        n_out++;
        if (off >= bufsize - 256) break;
    }
    off += snprintf(buf + off, bufsize - off, "],");

    /* Active satellites (only those seen in last 15 minutes) */
    uint64_t max_ts = 0;
    for (int i = 0; i < state.n_sats; i++) {
        if (state.sats[i].last_seen > max_ts)
            max_ts = state.sats[i].last_seen;
    }
    uint64_t sat_window = 15ULL * 60 * 1000000000ULL;  /* 15 minutes in ns */

    off += snprintf(buf + off, bufsize - off, "\"sats\":[");
    int first_sat = 1;
    for (int i = 0; i < state.n_sats; i++) {
        if (max_ts > sat_window && state.sats[i].last_seen < max_ts - sat_window)
            continue;
        if (!first_sat) off += snprintf(buf + off, bufsize - off, ",");
        off += snprintf(buf + off, bufsize - off,
            "{\"id\":%d,\"beam\":%d,\"count\":%d}",
            state.sats[i].sat_id, state.sats[i].beam_id,
            state.sats[i].count);
        first_sat = 0;
    }
    off += snprintf(buf + off, bufsize - off, "]");

    /* Receiver position estimate (Doppler positioning) */
    if (state.rx_valid) {
        off += snprintf(buf + off, bufsize - off,
            ",\"rx\":{\"lat\":%.6f,\"lon\":%.6f,\"hdop\":%.1f}",
            state.rx_lat, state.rx_lon, state.rx_hdop);
    }

    off += snprintf(buf + off, bufsize - off, "}");

    pthread_mutex_unlock(&state.lock);
    return off;
}

/* ---- Embedded HTML/JS ---- */

static const char HTML_PAGE[] =
"<!DOCTYPE html>\n"
"<html><head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>iridium-sniffer</title>\n"
"<link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\">\n"
"<script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\"></script>\n"
"<style>\n"
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a}\n"
"#map{width:100vw;height:calc(100vh - 44px)}\n"
"#bar{height:44px;background:#1e293b;color:#e2e8f0;display:flex;\n"
"  align-items:center;padding:0 16px;gap:20px;font-size:13px;\n"
"  border-bottom:1px solid #334155}\n"
"#bar .title{font-weight:600;color:#f8fafc;letter-spacing:0.5px}\n"
".stat{color:#94a3b8}\n"
".val{color:#38bdf8;font-weight:600;font-variant-numeric:tabular-nums}\n"
"#status{margin-left:auto;font-size:12px}\n"
".leaflet-popup-content{font-family:'SF Mono',Consolas,monospace;\n"
"  font-size:12px;line-height:1.6}\n"
".popup-title{font-weight:700;font-size:13px;margin-bottom:4px;\n"
"  padding-bottom:4px;border-bottom:1px solid #e2e8f0}\n"
".popup-page{color:#dc2626;font-weight:600}\n"
".legend{position:absolute;bottom:28px;right:10px;z-index:1000;\n"
"  background:rgba(15,23,42,0.92);color:#e2e8f0;padding:10px 14px;\n"
"  border-radius:6px;font-size:12px;line-height:2;\n"
"  border:1px solid #334155;pointer-events:auto}\n"
".legend-title{font-weight:700;font-size:11px;text-transform:uppercase;\n"
"  letter-spacing:1px;color:#94a3b8;margin-bottom:2px}\n"
".legend-row{display:flex;align-items:center;gap:8px}\n"
".legend-swatch{display:inline-block}\n"
".leaflet-container{background:#0f172a}\n"
"</style></head><body>\n"
"<div id=\"bar\">\n"
"  <span class=\"title\">iridium-sniffer</span>\n"
"  <span class=\"stat\">IRA <span id=\"n-ira\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">IBC <span id=\"n-ibc\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">Satellites <span id=\"n-sats\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">Pages <span id=\"n-pages\" class=\"val\">0</span></span>\n"
"  <span id=\"status\" style=\"color:#64748b\">connecting...</span>\n"
"</div>\n"
"<div id=\"map\"></div>\n"
"<div class=\"legend\">\n"
"  <div class=\"legend-title\">Map</div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:16px;height:16px;\n"
"      border-radius:50%;border:1px solid #3b82f6;\n"
"      background:rgba(59,130,246,0.12)\"></span>\n"
"    Beam coverage\n"
"  </div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:10px;height:10px;\n"
"      border-radius:50%;background:#ef4444\"></span>\n"
"    Paging event\n"
"  </div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:10px;height:10px;\n"
"      border-radius:50%;background:#22c55e\"></span>\n"
"    Receiver position\n"
"  </div>\n"
"</div>\n"
"<script>\n"
"var map=L.map('map',{zoomControl:true}).setView([20,0],2);\n"
"L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{\n"
"  attribution:'CartoDB',maxZoom:18,subdomains:'abcd'}).addTo(map);\n"
"\n"
"var C=[\n"
"  '#3b82f6','#22d3ee','#10b981','#a78bfa','#f472b6',\n"
"  '#fb923c','#facc15','#4ade80','#818cf8','#f87171',\n"
"  '#2dd4bf','#c084fc','#38bdf8','#fb7185','#a3e635'];\n"
"function sc(id){return C[id%C.length]}\n"
"\n"
"var coverLy=L.layerGroup().addTo(map);\n"
"var satLy=L.layerGroup().addTo(map);\n"
"var pageLy=L.layerGroup().addTo(map);\n"
"var rxLy=L.layerGroup().addTo(map);\n"
"var centered=false;\n"
"var TW=300;\n"
"var popupOpen=false;\n"
"map.on('popupopen',function(){popupOpen=true});\n"
"map.on('popupclose',function(){popupOpen=false});\n"
"\n"
"function update(d){\n"
"  document.getElementById('n-ira').textContent=d.total_ira;\n"
"  document.getElementById('n-ibc').textContent=d.total_ibc;\n"
"  document.getElementById('n-pages').textContent=d.total_pages;\n"
"  document.getElementById('status').style.color='#22c55e';\n"
"  document.getElementById('status').textContent='live';\n"
"\n"
"  if(popupOpen)return;\n"
"\n"
"  coverLy.clearLayers();\n"
"  satLy.clearLayers();\n"
"  pageLy.clearLayers();\n"
"\n"
"  var bySat={},pages=[],now=0;\n"
"  d.ra.forEach(function(p){\n"
"    if(p.t>now)now=p.t;\n"
"    if(!bySat[p.sat])bySat[p.sat]=[];\n"
"    bySat[p.sat].push(p);\n"
"    if(p.pages>0)pages.push(p);\n"
"  });\n"
"\n"
"  var cut=now-TW,nSat=0;\n"
"  Object.keys(bySat).forEach(function(sid){\n"
"    var pts=bySat[sid]\n"
"      .filter(function(p){return p.t>=cut})\n"
"      .sort(function(a,b){return a.t-b.t});\n"
"    if(!pts.length)return;\n"
"    nSat++;\n"
"    var col=sc(parseInt(sid));\n"
"    var last=pts[pts.length-1];\n"
"\n"
"    pts.forEach(function(pt){\n"
"      var age=(now-pt.t)/TW;\n"
"      L.circle([pt.lat,pt.lon],{radius:400000,\n"
"        stroke:false,fillColor:col,fillOpacity:0.12*(1-age)\n"
"      }).addTo(coverLy);\n"
"    });\n"
"\n"
"    var m=L.circleMarker([last.lat,last.lon],{\n"
"      radius:5,color:col,fillColor:col,fillOpacity:0.9,weight:2\n"
"    });\n"
"    m.bindTooltip('Sat '+sid,{direction:'top',offset:[0,-8]});\n"
"    m.bindPopup('<div class=\"popup-title\">Satellite '+sid+'</div>'\n"
"      +'Beam: '+last.beam+'<br>'\n"
"      +'Position: '+last.lat.toFixed(2)+', '+last.lon.toFixed(2)+'<br>'\n"
"      +'Altitude: '+last.alt+' km<br>'\n"
"      +'Frequency: '+last.freq.toFixed(0)+' Hz<br>'\n"
"      +'Beams: '+pts.length);\n"
"    m.addTo(satLy);\n"
"  });\n"
"\n"
"  document.getElementById('n-sats').textContent=nSat;\n"
"\n"
"  pages.forEach(function(p){\n"
"    if(p.t<cut)return;\n"
"    var pm=L.circleMarker([p.lat,p.lon],{\n"
"      radius:6,color:'#ef4444',fillColor:'#ef4444',\n"
"      fillOpacity:0.7,weight:1\n"
"    });\n"
"    pm.bindPopup('<div class=\"popup-title popup-page\">Paging</div>'\n"
"      +'Satellite: '+p.sat+'<br>'\n"
"      +'TMSI: 0x'+(p.tmsi>>>0).toString(16).toUpperCase()+'<br>'\n"
"      +'Position: '+p.lat.toFixed(2)+', '+p.lon.toFixed(2));\n"
"    pm.addTo(pageLy);\n"
"  });\n"
"\n"
"  rxLy.clearLayers();\n"
"  if(d.rx){\n"
"    var rm=L.circleMarker([d.rx.lat,d.rx.lon],{\n"
"      radius:8,color:'#22c55e',fillColor:'#22c55e',\n"
"      fillOpacity:0.9,weight:3\n"
"    });\n"
"    rm.bindPopup('<div class=\"popup-title\">Receiver Position</div>'\n"
"      +'Estimated: '+d.rx.lat.toFixed(6)+', '+d.rx.lon.toFixed(6)+'<br>'\n"
"      +'HDOP: '+d.rx.hdop.toFixed(1));\n"
"    rm.addTo(rxLy);\n"
"    if(d.rx.hdop<50){\n"
"      L.circle([d.rx.lat,d.rx.lon],{radius:d.rx.hdop*20,\n"
"        color:'#22c55e',fillColor:'#22c55e',\n"
"        fillOpacity:0.1,weight:1,dashArray:'4'}).addTo(rxLy);\n"
"    }\n"
"  }\n"
"\n"
"  if(!centered && d.rx){\n"
"    map.setView([d.rx.lat,d.rx.lon],6);\n"
"    centered=true;\n"
"  }else if(!centered && d.ra.length>0){\n"
"    map.setView([d.ra[0].lat,d.ra[0].lon],3);\n"
"    centered=true;\n"
"  }\n"
"}\n"
"\n"
"function connect(){\n"
"  var es=new EventSource('/api/events');\n"
"  es.addEventListener('update',function(e){\n"
"    try{update(JSON.parse(e.data))}catch(err){}\n"
"  });\n"
"  es.onerror=function(){\n"
"    document.getElementById('status').style.color='#ef4444';\n"
"    document.getElementById('status').textContent='reconnecting...';\n"
"    es.close();\n"
"    setTimeout(connect,2000);\n"
"  };\n"
"}\n"
"connect();\n"
"</script></body></html>\n";

/* ---- HTTP request handling ---- */

static void send_response(int fd, const char *status, const char *content_type,
                            const char *body, int body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n", status, content_type, body_len);
    if (write(fd, header, hlen) < 0) return;
    if (body_len > 0) {
        if (write(fd, body, body_len) < 0) return;
    }
}

static void handle_sse(int fd)
{
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "X-Accel-Buffering: no\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n");
    if (write(fd, header, hlen) < 0) return;

    char *json = malloc(JSON_BUF_SIZE);
    if (!json) return;

    while (server_running) {
        usleep(1000000);  /* 1 Hz updates */
        if (!server_running) break;

        int jlen = build_json(json, JSON_BUF_SIZE - 64);

        char prefix[] = "event: update\ndata: ";
        char suffix[] = "\n\n";

        struct iovec iov[3];
        iov[0].iov_base = prefix;
        iov[0].iov_len = sizeof(prefix) - 1;
        iov[1].iov_base = json;
        iov[1].iov_len = jlen;
        iov[2].iov_base = suffix;
        iov[2].iov_len = sizeof(suffix) - 1;

        /* Use writev for atomic write */
        if (writev(fd, iov, 3) < 0) break;
    }

    free(json);
}

static void *client_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;

    char buf[HTTP_BUF_SIZE];
    int n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(fd); return NULL; }
    buf[n] = '\0';

    /* Parse GET path */
    if (strncmp(buf, "GET ", 4) != 0) {
        send_response(fd, "405 Method Not Allowed", "text/plain", "405", 3);
        close(fd);
        return NULL;
    }

    char *path = buf + 4;
    char *end = strchr(path, ' ');
    if (end) *end = '\0';

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        send_response(fd, "200 OK", "text/html",
                       HTML_PAGE, sizeof(HTML_PAGE) - 1);
        close(fd);
    } else if (strcmp(path, "/api/events") == 0) {
        if (atomic_fetch_add(&sse_client_count, 1) >= MAX_SSE_CLIENTS) {
            atomic_fetch_sub(&sse_client_count, 1);
            send_response(fd, "503 Service Unavailable", "text/plain",
                          "too many clients", 16);
        } else {
            handle_sse(fd);
            atomic_fetch_sub(&sse_client_count, 1);
        }
        close(fd);
    } else if (strcmp(path, "/api/state") == 0) {
        char *json = malloc(JSON_BUF_SIZE);
        if (json) {
            int jlen = build_json(json, JSON_BUF_SIZE);
            send_response(fd, "200 OK", "application/json", json, jlen);
            free(json);
        }
        close(fd);
    } else {
        send_response(fd, "404 Not Found", "text/plain", "404", 3);
        close(fd);
    }

    return NULL;
}

/* ---- Server thread ---- */

static void *server_thread_fn(void *arg)
{
    (void)arg;

    while (server_running) {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        int client = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client < 0) {
            if (server_running) usleep(10000);
            continue;
        }

        /* Set SO_KEEPALIVE for SSE connections */
        int keepalive = 1;
        setsockopt(client, SOL_SOCKET, SO_KEEPALIVE,
                    &keepalive, sizeof(keepalive));

        /* Spawn client handler thread (detached) */
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, client_thread,
                            (void *)(intptr_t)client) != 0) {
            close(client);
        }
        pthread_attr_destroy(&attr);
    }

    return NULL;
}

/* ---- Public interface ---- */

int web_map_init(int port)
{
    memset(&state, 0, sizeof(state));
    pthread_mutex_init(&state.lock, NULL);

    /* Ignore SIGPIPE (broken SSE connections) */
    signal(SIGPIPE, SIG_IGN);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("web_map: socket");
        return -1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port),
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("web_map: bind");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    if (listen(server_fd, 16) < 0) {
        perror("web_map: listen");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    server_running = 1;
    if (pthread_create(&server_thread, NULL, server_thread_fn, NULL) != 0) {
        perror("web_map: pthread_create");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    fprintf(stderr, "Web map: http://localhost:%d/\n", port);
    return 0;
}

void web_map_shutdown(void)
{
    if (!server_running) return;
    server_running = 0;

    if (server_fd >= 0) {
        shutdown(server_fd, SHUT_RDWR);
        close(server_fd);
        server_fd = -1;
    }

    pthread_join(server_thread, NULL);
    pthread_mutex_destroy(&state.lock);
}
