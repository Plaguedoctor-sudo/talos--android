/*
 * LibreDroid Sovereign Firewall Controller CLI (lrd-firewall)
 * mobile/firewall/lrd-firewall.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/run/libredroid/firewall.sock"
#define FALLBACK_SOCK "/tmp/libredroid/firewall.sock"

static int connect_firewall(void) {
    for (int retry = 0; retry < 5; retry++) {
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
        usleep(10000);
    }
    return -1;
}

static void send_and_print(const char *cmd) {
    int fd = connect_firewall();
    if (fd < 0) {
        fprintf(stderr, "Error: Could not connect to lrd-firewalld daemon (firewall.sock)\n");
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
        printf("Firewall Commands:\n");
        printf("  status                    - View firewall state, killswitch, mode, and drop statistics\n");
        printf("  killswitch <on|off>       - Arm or disarm anti-leak unmediated traffic drop\n");
        printf("  mode <vpn|tor|lan|panic>  - Switch global routing enforcement mode\n");
        printf("  allow-ip <ip>             - Add IP to dynamic egress allowlist\n");
        printf("  block-ip <ip>             - Add IP to tracker / telemetry blacklist\n");
        printf("  allow-app <app_id> [mode] - Set application policy (ALLOWED, VPN_ONLY, TOR_ONLY)\n");
        printf("  block-app <app_id>        - Completely block application from network access\n");
        printf("  app-policies              - View all per-app firewall sandboxing rules\n");
        printf("  hotspot-egress <vpn|tor|lan|direct> - Set mobile tethering egress routing policy\n");
        printf("  panic                     - Trigger emergency instant zero-egress lockdown\n");
        printf("  restore                   - Restore normal sovereign firewall operation\n");
        printf("  audit                     - Stream recent kernel/firewall dropped packet audit\n");
        return 1;
    }

    const char *action = argv[1];
    char cmd[2048] = {0};

    if (strcmp(action, "status") == 0) {
        snprintf(cmd, sizeof(cmd), "status");
    } else if (strcmp(action, "killswitch") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: usage: killswitch <on|off>\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "killswitch %s", argv[2]);
    } else if (strcmp(action, "mode") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: usage: mode <vpn|tor|lan|panic>\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "mode %s", argv[2]);
    } else if (strcmp(action, "allow-ip") == 0 || strcmp(action, "allow") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: missing IP address\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "allow-ip %s", argv[2]);
    } else if (strcmp(action, "block-ip") == 0 || strcmp(action, "deny-ip") == 0 || strcmp(action, "deny") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: missing IP address\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "block-ip %s", argv[2]);
    } else if (strcmp(action, "allow-app") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: missing app ID\n"); return 1; }
        const char *m = (argc >= 4) ? argv[3] : "VPN_ONLY";
        snprintf(cmd, sizeof(cmd), "allow-app %s %s", argv[2], m);
    } else if (strcmp(action, "block-app") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: missing app ID\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "block-app %s", argv[2]);
    } else if (strcmp(action, "app-policies") == 0 || strcmp(action, "apps") == 0) {
        snprintf(cmd, sizeof(cmd), "app-policies");
    } else if (strcmp(action, "hotspot-egress") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: usage: hotspot-egress <vpn|tor|lan|direct>\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "hotspot-egress %s", argv[2]);
    } else if (strcmp(action, "panic") == 0) {
        snprintf(cmd, sizeof(cmd), "panic");
    } else if (strcmp(action, "restore") == 0) {
        snprintf(cmd, sizeof(cmd), "restore");
    } else if (strcmp(action, "audit") == 0) {
        snprintf(cmd, sizeof(cmd), "audit");
    } else {
        fprintf(stderr, "Unknown command: %s\n", action);
        return 1;
    }

    send_and_print(cmd);
    return 0;
}
