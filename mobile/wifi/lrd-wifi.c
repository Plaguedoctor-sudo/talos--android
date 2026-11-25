/*
 * LibreDroid Sovereign Wi-Fi & Hotspot Controller CLI (lrd-wifi)
 * mobile/wifi/lrd-wifi.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/run/libredroid/wifi.sock"
#define FALLBACK_SOCK "/tmp/libredroid/wifi.sock"

static int connect_wifi(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        return fd;
    }

    // Try fallback
    strncpy(addr.sun_path, FALLBACK_SOCK, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        return fd;
    }

    close(fd);
    return -1;
}

static void send_and_print(const char *cmd) {
    int fd = connect_wifi();
    if (fd < 0) {
        fprintf(stderr, "Error: Could not connect to lrd-wifid daemon (wifi.sock)\n");
        exit(1);
    }

    if (write(fd, cmd, strlen(cmd)) < 0 || write(fd, "\n", 1) < 0) {
        perror("write");
        close(fd);
        exit(1);
    }

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <command> [args...]\n", argv[0]);
        printf("Station (Client) Commands:\n");
        printf("  status                    - View Wi-Fi station and mobile hotspot status\n");
        printf("  scan                      - Scan and list available Wi-Fi access points\n");
        printf("  connect <ssid> [pass]     - Connect to Wi-Fi network with WPA2/WPA3\n");
        printf("  disconnect                - Disconnect from current Wi-Fi network\n");
        printf("  power <on|off>            - Turn Wi-Fi radio on or off\n");
        printf("  privacy <on|off|rotate>   - Toggle or rotate station MAC address randomization\n");
        printf("\nMobile Hotspot (Tethering) Commands:\n");
        printf("  hotspot-start [ssid] [pass] [band] - Start sovereign Wi-Fi hotspot AP\n");
        printf("  hotspot-stop                       - Stop Wi-Fi hotspot AP\n");
        printf("  hotspot-status                     - View hotspot configuration & client count\n");
        printf("  hotspot-clients                    - List active tethered client stations\n");
        return 1;
    }

    const char *action = argv[1];
    char cmd[2048] = {0};

    if (strcmp(action, "status") == 0) {
        snprintf(cmd, sizeof(cmd), "status");
    } else if (strcmp(action, "scan") == 0) {
        snprintf(cmd, sizeof(cmd), "scan");
    } else if (strcmp(action, "connect") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: missing SSID\n"); return 1; }
        const char *pass = (argc >= 4) ? argv[3] : "";
        snprintf(cmd, sizeof(cmd), "connect %s %s", argv[2], pass);
    } else if (strcmp(action, "disconnect") == 0) {
        snprintf(cmd, sizeof(cmd), "disconnect");
    } else if (strcmp(action, "power") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: usage: power <on|off>\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "power %s", argv[2]);
    } else if (strcmp(action, "privacy") == 0) {
        const char *sub = (argc >= 3) ? argv[2] : "rotate";
        snprintf(cmd, sizeof(cmd), "privacy %s", sub);
    } else if (strcmp(action, "hotspot-start") == 0 || strcmp(action, "hotspot") == 0) {
        const char *ssid = (argc >= 3) ? argv[2] : "TALOS-Hotspot-5G";
        const char *pass = (argc >= 4) ? argv[3] : "SovereignPass2026";
        const char *band = (argc >= 5) ? argv[4] : "5GHz";
        snprintf(cmd, sizeof(cmd), "hotspot-start %s %s %s", ssid, pass, band);
    } else if (strcmp(action, "hotspot-stop") == 0) {
        snprintf(cmd, sizeof(cmd), "hotspot-stop");
    } else if (strcmp(action, "hotspot-status") == 0) {
        snprintf(cmd, sizeof(cmd), "hotspot-status");
    } else if (strcmp(action, "hotspot-clients") == 0) {
        snprintf(cmd, sizeof(cmd), "hotspot-clients");
    } else {
        fprintf(stderr, "Unknown command: %s\n", action);
        return 1;
    }

    send_and_print(cmd);
    return 0;
}
