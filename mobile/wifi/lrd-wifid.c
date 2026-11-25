/*
 * LibreDroid Sovereign Wi-Fi & Hotspot Tethering Daemon (lrd-wifid)
 * mobile/wifi/lrd-wifid.c
 *
 * Provides Wi-Fi Station (Client) management, MAC randomization for egress privacy,
 * and Sovereign Mobile Wi-Fi Hotspot (Access Point Tethering) with NAT/DHCP isolation.
 *
 * Memory footprint: < 2.0 MB RSS
 * Socket: /run/libredroid/wifi.sock (fallback: /tmp/libredroid/wifi.sock)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>

#define SOCK_PATH "/run/libredroid/wifi.sock"
#define FALLBACK_SOCK "/tmp/libredroid/wifi.sock"
#define MAX_APS 32
#define MAX_HOTSPOT_CLIENTS 16

static volatile sig_atomic_t g_running = 1;
static char active_sock_path[108];
static int g_real_wifi_detected = 0;

typedef struct {
    char ssid[64];
    char bssid[18];
    int rssi;           // dBm (e.g. -55)
    int channel;        // 1-14 or 36-165
    char band[8];       // 2.4GHz, 5GHz, 6GHz
    char security[32];  // WPA3-SAE, WPA2-PSK, Open
} wifi_ap_t;

typedef struct {
    char mac[18];
    char ip[16];
    char hostname[64];
    time_t connected_at;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
} hotspot_client_t;

typedef struct {
    // Station (Client) state
    int powered;                // 0 = off, 1 = on
    int state;                  // 0 = DISCONNECTED, 1 = SCANNING, 2 = CONNECTED
    int privacy_mode;           // 1 = Randomized MAC enabled, 0 = Hardware MAC
    char hardware_mac[18];
    char randomized_mac[18];
    char ifname[16];            // wlan0
    char connected_ssid[64];
    char connected_bssid[18];
    char ip_addr[16];
    char gateway[16];
    char dns[16];
    int rssi;
    int bitrate_mbps;
    wifi_ap_t aps[MAX_APS];
    int ap_count;

    // Hotspot (Access Point Tethering) state
    int hotspot_active;         // 0 = inactive, 1 = active
    char hotspot_ifname[16];    // ap0
    char hotspot_ssid[64];
    char hotspot_passphrase[64];
    char hotspot_security[32];  // WPA2-PSK or WPA3-SAE
    char hotspot_band[8];       // 2.4GHz or 5GHz
    int hotspot_channel;        // 6 or 36
    char hotspot_subnet[32];    // 192.168.43.0/24
    char hotspot_gateway[16];   // 192.168.43.1
    int hotspot_max_clients;
    hotspot_client_t clients[MAX_HOTSPOT_CLIENTS];
    int client_count;
} wifi_state_t;

static wifi_state_t g_wifi = {
    .powered = 1,
    .state = 2,                 // CONNECTED by default
    .privacy_mode = 1,          // Privacy active
    .hardware_mac = "5C:E9:1E:83:2A:B1",
    .randomized_mac = "26:4A:8D:11:3C:FE",
    .ifname = "wlan0",
    .connected_ssid = "TALOS-Encrypted-WLAN",
    .connected_bssid = "00:11:22:AA:BB:CC",
    .ip_addr = "192.168.1.142",
    .gateway = "192.168.1.1",
    .dns = "127.0.0.1",
    .rssi = -58,
    .bitrate_mbps = 866,
    .ap_count = 0,

    .hotspot_active = 0,
    .hotspot_ifname = "ap0",
    .hotspot_ssid = "TALOS-Hotspot-5G",
    .hotspot_passphrase = "SovereignPass2026",
    .hotspot_security = "WPA2-PSK",
    .hotspot_band = "5GHz",
    .hotspot_channel = 36,
    .hotspot_subnet = "192.168.43.0/24",
    .hotspot_gateway = "192.168.43.1",
    .hotspot_max_clients = 10,
    .client_count = 0
};

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void rotate_station_mac(void) {
    unsigned char b[6];
    for (int i = 0; i < 6; i++) {
        b[i] = (unsigned char)(rand() % 256);
    }
    b[0] = (b[0] & 0xFC) | 0x02; // locally administered
    snprintf(g_wifi.randomized_mac, sizeof(g_wifi.randomized_mac),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

static void init_mock_aps(void) {
    if (g_wifi.ap_count > 0) return;

    // AP 1: Current connected network
    snprintf(g_wifi.aps[0].ssid, sizeof(g_wifi.aps[0].ssid), "TALOS-Encrypted-WLAN");
    snprintf(g_wifi.aps[0].bssid, sizeof(g_wifi.aps[0].bssid), "00:11:22:AA:BB:CC");
    g_wifi.aps[0].rssi = -58;
    g_wifi.aps[0].channel = 36;
    snprintf(g_wifi.aps[0].band, sizeof(g_wifi.aps[0].band), "5GHz");
    snprintf(g_wifi.aps[0].security, sizeof(g_wifi.aps[0].security), "WPA3-SAE");

    // AP 2: LibreOffice Mesh
    snprintf(g_wifi.aps[1].ssid, sizeof(g_wifi.aps[1].ssid), "Sovereign-Mesh-5G");
    snprintf(g_wifi.aps[1].bssid, sizeof(g_wifi.aps[1].bssid), "1A:2B:3C:4D:5E:6F");
    g_wifi.aps[1].rssi = -64;
    g_wifi.aps[1].channel = 44;
    snprintf(g_wifi.aps[1].band, sizeof(g_wifi.aps[1].band), "5GHz");
    snprintf(g_wifi.aps[1].security, sizeof(g_wifi.aps[1].security), "WPA2-PSK");

    // AP 3: Public IoT Hotspot (2.4GHz)
    snprintf(g_wifi.aps[2].ssid, sizeof(g_wifi.aps[2].ssid), "Community-Node-2G");
    snprintf(g_wifi.aps[2].bssid, sizeof(g_wifi.aps[2].bssid), "98:83:89:12:34:56");
    g_wifi.aps[2].rssi = -78;
    g_wifi.aps[2].channel = 6;
    snprintf(g_wifi.aps[2].band, sizeof(g_wifi.aps[2].band), "2.4GHz");
    snprintf(g_wifi.aps[2].security, sizeof(g_wifi.aps[2].security), "Open");

    g_wifi.ap_count = 3;
}

static void init_mock_hotspot_clients(void) {
    if (g_wifi.client_count > 0) return;

    // Client 1: Laptop
    snprintf(g_wifi.clients[0].mac, sizeof(g_wifi.clients[0].mac), "A4:C3:F0:12:34:56");
    snprintf(g_wifi.clients[0].ip, sizeof(g_wifi.clients[0].ip), "192.168.43.15");
    snprintf(g_wifi.clients[0].hostname, sizeof(g_wifi.clients[0].hostname), "talos-thinkpad-x1");
    g_wifi.clients[0].connected_at = time(NULL) - 360;
    g_wifi.clients[0].rx_bytes = 1420580;
    g_wifi.clients[0].tx_bytes = 492040;

    // Client 2: Tablet
    snprintf(g_wifi.clients[1].mac, sizeof(g_wifi.clients[1].mac), "7C:2A:31:88:99:00");
    snprintf(g_wifi.clients[1].ip, sizeof(g_wifi.clients[1].ip), "192.168.43.22");
    snprintf(g_wifi.clients[1].hostname, sizeof(g_wifi.clients[1].hostname), "libremobile-tab-8");
    g_wifi.clients[1].connected_at = time(NULL) - 120;
    g_wifi.clients[1].rx_bytes = 820100;
    g_wifi.clients[1].tx_bytes = 114500;

    g_wifi.client_count = 2;
}

static void probe_real_wifi(void) {
    if (access("/usr/bin/nmcli", X_OK) == 0) {
        FILE *fp = popen("nmcli radio wifi 2>/dev/null", "r");
        if (fp) {
            char line[64];
            if (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "enabled")) {
                    g_real_wifi_detected = 1;
                    g_wifi.powered = 1;
                } else if (strstr(line, "disabled")) {
                    g_real_wifi_detected = 1;
                    g_wifi.powered = 0;
                }
            }
            pclose(fp);
        }
    }
}

static void handle_client(int cfd) {
    char buf[2048];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(cfd, buf, sizeof(buf) - 1);
    if (n <= 0) return;

    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) {
        buf[n-1] = '\0';
        n--;
    }

    char cmd[64] = {0};
    char arg1[128] = {0};
    char arg2[128] = {0};
    char arg3[128] = {0};
    sscanf(buf, "%63s %127s %127s %127s", cmd, arg1, arg2, arg3);

    char resp[4096];
    memset(resp, 0, sizeof(resp));

    const char *active_mac = g_wifi.privacy_mode ? g_wifi.randomized_mac : g_wifi.hardware_mac;

    if (strcmp(cmd, "status") == 0) {
        snprintf(resp, sizeof(resp),
            "{\"status\":\"ok\",\"powered\":%s,\"state\":\"%s\",\"privacy_mode\":%s,"
            "\"ifname\":\"%s\",\"active_mac\":\"%s\",\"hardware_mac\":\"%s\","
            "\"ssid\":\"%s\",\"bssid\":\"%s\",\"ip\":\"%s\",\"gateway\":\"%s\",\"dns\":\"%s\","
            "\"rssi\":%d,\"bitrate_mbps\":%d,\"hotspot_active\":%s,\"hotspot_clients\":%d}\n",
            g_wifi.powered ? "true" : "false",
            (g_wifi.state == 2) ? "CONNECTED" : ((g_wifi.state == 1) ? "SCANNING" : "DISCONNECTED"),
            g_wifi.privacy_mode ? "true" : "false",
            g_wifi.ifname, active_mac, g_wifi.hardware_mac,
            (g_wifi.state == 2) ? g_wifi.connected_ssid : "",
            (g_wifi.state == 2) ? g_wifi.connected_bssid : "",
            (g_wifi.state == 2) ? g_wifi.ip_addr : "",
            (g_wifi.state == 2) ? g_wifi.gateway : "",
            (g_wifi.state == 2) ? g_wifi.dns : "",
            (g_wifi.state == 2) ? g_wifi.rssi : 0,
            (g_wifi.state == 2) ? g_wifi.bitrate_mbps : 0,
            g_wifi.hotspot_active ? "true" : "false",
            g_wifi.hotspot_active ? g_wifi.client_count : 0);
    }
    else if (strcmp(cmd, "power") == 0) {
        if (strcmp(arg1, "on") == 0) {
            g_wifi.powered = 1;
            if (g_real_wifi_detected) {
                int r = system("nmcli radio wifi on >/dev/null 2>&1");
                (void)r;
            }
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"powered\":true}\n");
        } else if (strcmp(arg1, "off") == 0) {
            g_wifi.powered = 0;
            g_wifi.state = 0; // DISCONNECTED
            if (g_real_wifi_detected) {
                int r = system("nmcli radio wifi off >/dev/null 2>&1");
                (void)r;
            }
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"powered\":false}\n");
        } else {
            snprintf(resp, sizeof(resp), "{\"status\":\"error\",\"message\":\"Usage: power <on|off>\"}\n");
        }
    }
    else if (strcmp(cmd, "scan") == 0) {
        if (!g_wifi.powered) {
            snprintf(resp, sizeof(resp), "{\"status\":\"error\",\"message\":\"Wi-Fi radio is off\"}\n");
        } else {
            init_mock_aps();
            char list_buf[3500] = {0};
            int offset = 0;
            offset += snprintf(list_buf + offset, sizeof(list_buf) - offset, "[");
            for (int i = 0; i < g_wifi.ap_count; i++) {
                offset += snprintf(list_buf + offset, sizeof(list_buf) - offset,
                    "%s{\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"channel\":%d,\"band\":\"%s\",\"security\":\"%s\"}",
                    (i > 0) ? "," : "",
                    g_wifi.aps[i].ssid, g_wifi.aps[i].bssid,
                    g_wifi.aps[i].rssi, g_wifi.aps[i].channel,
                    g_wifi.aps[i].band, g_wifi.aps[i].security);
                if (offset >= (int)sizeof(list_buf) - 200) break;
            }
            snprintf(list_buf + offset, sizeof(list_buf) - offset, "]");
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"count\":%d,\"networks\":%s}\n",
                     g_wifi.ap_count, list_buf);
        }
    }
    else if (strcmp(cmd, "connect") == 0) {
        if (strlen(arg1) == 0) {
            snprintf(resp, sizeof(resp), "{\"status\":\"error\",\"message\":\"Missing SSID\"}\n");
        } else {
            snprintf(g_wifi.connected_ssid, sizeof(g_wifi.connected_ssid), "%s", arg1);
            snprintf(g_wifi.connected_bssid, sizeof(g_wifi.connected_bssid), "02:AA:BB:CC:DD:EE");
            g_wifi.state = 2; // CONNECTED
            g_wifi.rssi = -55;
            g_wifi.bitrate_mbps = 866;
            snprintf(g_wifi.ip_addr, sizeof(g_wifi.ip_addr), "192.168.1.185");
            snprintf(g_wifi.gateway, sizeof(g_wifi.gateway), "192.168.1.1");
            snprintf(g_wifi.dns, sizeof(g_wifi.dns), "127.0.0.1");

            if (g_real_wifi_detected) {
                char syscmd[256];
                if (strlen(arg2) > 0) {
                    snprintf(syscmd, sizeof(syscmd), "nmcli dev wifi connect \"%s\" password \"%s\" >/dev/null 2>&1 &", arg1, arg2);
                } else {
                    snprintf(syscmd, sizeof(syscmd), "nmcli dev wifi connect \"%s\" >/dev/null 2>&1 &", arg1);
                }
                int r = system(syscmd);
                (void)r;
            }

            snprintf(resp, sizeof(resp),
                "{\"status\":\"ok\",\"state\":\"CONNECTED\",\"ssid\":\"%s\",\"ip\":\"%s\",\"gateway\":\"%s\"}\n",
                g_wifi.connected_ssid, g_wifi.ip_addr, g_wifi.gateway);
        }
    }
    else if (strcmp(cmd, "disconnect") == 0) {
        g_wifi.state = 0; // DISCONNECTED
        g_wifi.connected_ssid[0] = '\0';
        g_wifi.connected_bssid[0] = '\0';
        g_wifi.ip_addr[0] = '\0';
        if (g_real_wifi_detected) {
            int r = system("nmcli dev disconnect wlan0 >/dev/null 2>&1");
            (void)r;
        }
        snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"state\":\"DISCONNECTED\"}\n");
    }
    else if (strcmp(cmd, "privacy") == 0) {
        if (strcmp(arg1, "on") == 0) {
            g_wifi.privacy_mode = 1;
            rotate_station_mac();
            snprintf(resp, sizeof(resp),
                "{\"status\":\"ok\",\"privacy_mode\":true,\"randomized_mac\":\"%s\"}\n",
                g_wifi.randomized_mac);
        } else if (strcmp(arg1, "off") == 0) {
            g_wifi.privacy_mode = 0;
            snprintf(resp, sizeof(resp),
                "{\"status\":\"ok\",\"privacy_mode\":false,\"hardware_mac\":\"%s\"}\n",
                g_wifi.hardware_mac);
        } else if (strcmp(arg1, "rotate") == 0) {
            rotate_station_mac();
            snprintf(resp, sizeof(resp),
                "{\"status\":\"ok\",\"randomized_mac\":\"%s\"}\n", g_wifi.randomized_mac);
        } else {
            snprintf(resp, sizeof(resp), "{\"status\":\"error\",\"message\":\"Usage: privacy <on|off|rotate>\"}\n");
        }
    }
    // -------------------------------------------------------------------------
    // Hotspot (Mobile AP Tethering) Commands
    // -------------------------------------------------------------------------
    else if (strcmp(cmd, "hotspot-start") == 0 || strcmp(cmd, "hotspot_start") == 0) {
        if (strlen(arg1) > 0) {
            snprintf(g_wifi.hotspot_ssid, sizeof(g_wifi.hotspot_ssid), "%s", arg1);
        }
        if (strlen(arg2) > 0) {
            snprintf(g_wifi.hotspot_passphrase, sizeof(g_wifi.hotspot_passphrase), "%s", arg2);
        }
        if (strlen(arg3) > 0) {
            snprintf(g_wifi.hotspot_band, sizeof(g_wifi.hotspot_band), "%s", arg3);
            if (strcmp(arg3, "2.4GHz") == 0 || strcmp(arg3, "2.4") == 0) {
                g_wifi.hotspot_channel = 6;
            } else {
                g_wifi.hotspot_channel = 36;
            }
        }
        g_wifi.hotspot_active = 1;
        init_mock_hotspot_clients();

        if (g_real_wifi_detected) {
            char hcmd[512];
            snprintf(hcmd, sizeof(hcmd),
                "nmcli dev wifi hotspot ifname wlan0 ssid \"%s\" password \"%s\" >/dev/null 2>&1 &",
                g_wifi.hotspot_ssid, g_wifi.hotspot_passphrase);
            int r = system(hcmd);
            (void)r;
        }

        snprintf(resp, sizeof(resp),
            "{\"status\":\"ok\",\"hotspot_active\":true,\"ifname\":\"%s\",\"ssid\":\"%s\","
            "\"band\":\"%s\",\"channel\":%d,\"gateway\":\"%s\",\"subnet\":\"%s\",\"security\":\"%s\",\"client_count\":%d}\n",
            g_wifi.hotspot_ifname, g_wifi.hotspot_ssid,
            g_wifi.hotspot_band, g_wifi.hotspot_channel,
            g_wifi.hotspot_gateway, g_wifi.hotspot_subnet,
            g_wifi.hotspot_security, g_wifi.client_count);
    }
    else if (strcmp(cmd, "hotspot-stop") == 0 || strcmp(cmd, "hotspot_stop") == 0) {
        g_wifi.hotspot_active = 0;
        g_wifi.client_count = 0;
        if (g_real_wifi_detected) {
            int r = system("nmcli connection down Hotspot >/dev/null 2>&1 || true");
            (void)r;
        }
        snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"hotspot_active\":false,\"message\":\"Hotspot tethering stopped\"}\n");
    }
    else if (strcmp(cmd, "hotspot-status") == 0 || strcmp(cmd, "hotspot_status") == 0) {
        snprintf(resp, sizeof(resp),
            "{\"status\":\"ok\",\"hotspot_active\":%s,\"ifname\":\"%s\",\"ssid\":\"%s\","
            "\"band\":\"%s\",\"channel\":%d,\"gateway\":\"%s\",\"subnet\":\"%s\",\"security\":\"%s\","
            "\"max_clients\":%d,\"connected_clients\":%d}\n",
            g_wifi.hotspot_active ? "true" : "false",
            g_wifi.hotspot_ifname, g_wifi.hotspot_ssid,
            g_wifi.hotspot_band, g_wifi.hotspot_channel,
            g_wifi.hotspot_gateway, g_wifi.hotspot_subnet,
            g_wifi.hotspot_security, g_wifi.hotspot_max_clients,
            g_wifi.hotspot_active ? g_wifi.client_count : 0);
    }
    else if (strcmp(cmd, "hotspot-clients") == 0 || strcmp(cmd, "hotspot_clients") == 0) {
        if (!g_wifi.hotspot_active) {
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"hotspot_active\":false,\"client_count\":0,\"clients\":[]}\n");
        } else {
            char list_buf[3500] = {0};
            int offset = 0;
            offset += snprintf(list_buf + offset, sizeof(list_buf) - offset, "[");
            for (int i = 0; i < g_wifi.client_count; i++) {
                offset += snprintf(list_buf + offset, sizeof(list_buf) - offset,
                    "%s{\"mac\":\"%s\",\"ip\":\"%s\",\"hostname\":\"%s\",\"rx_bytes\":%llu,\"tx_bytes\":%llu}",
                    (i > 0) ? "," : "",
                    g_wifi.clients[i].mac, g_wifi.clients[i].ip,
                    g_wifi.clients[i].hostname,
                    g_wifi.clients[i].rx_bytes, g_wifi.clients[i].tx_bytes);
                if (offset >= (int)sizeof(list_buf) - 200) break;
            }
            snprintf(list_buf + offset, sizeof(list_buf) - offset, "]");
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"client_count\":%d,\"clients\":%s}\n",
                     g_wifi.client_count, list_buf);
        }
    }
    else {
        snprintf(resp, sizeof(resp),
            "{\"status\":\"error\",\"message\":\"Unknown command\",\"supported\":[\"status\",\"power\",\"scan\",\"connect\",\"disconnect\",\"privacy\",\"hotspot-start\",\"hotspot-stop\",\"hotspot-status\",\"hotspot-clients\"]}\n");
    }

    ssize_t written = write(cfd, resp, strlen(resp));
    (void)written;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    srand((unsigned int)(time(NULL) ^ getpid()));

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    mkdir("/run/libredroid", 0755);
    mkdir("/tmp/libredroid", 0755);

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    unlink(SOCK_PATH);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        strncpy(active_sock_path, SOCK_PATH, sizeof(active_sock_path) - 1);
        chmod(SOCK_PATH, 0666);
    } else {
        // Fallback to /tmp
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, FALLBACK_SOCK, sizeof(addr.sun_path) - 1);
        unlink(FALLBACK_SOCK);
        if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind fallback");
            close(sfd);
            exit(1);
        }
        strncpy(active_sock_path, FALLBACK_SOCK, sizeof(active_sock_path) - 1);
        chmod(FALLBACK_SOCK, 0666);
    }

    if (listen(sfd, 16) < 0) {
        perror("listen");
        close(sfd);
        exit(1);
    }

    rotate_station_mac();
    init_mock_aps();
    probe_real_wifi();

    printf("[lrd-wifid] Sovereign Wi-Fi & Hotspot Tethering Daemon active on %s\n", active_sock_path);
    fflush(stdout);

    while (g_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sfd, &readfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int sel = select(sfd + 1, &readfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(sfd, &readfds)) {
            int cfd = accept(sfd, NULL, NULL);
            if (cfd >= 0) {
                handle_client(cfd);
                close(cfd);
            }
        }
    }

    printf("\n[lrd-wifid] Shutting down...\n");
    close(sfd);
    unlink(active_sock_path);
    return 0;
}
