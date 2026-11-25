/*
 * LibreDroid Sovereign Bluetooth Controller CLI (lrd-bluetooth)
 * mobile/bluetooth/lrd-bluetooth.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/run/libredroid/bluetooth.sock"
#define FALLBACK_SOCK "/tmp/libredroid/bluetooth.sock"

static int connect_bluetooth(void) {
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
    int fd = connect_bluetooth();
    if (fd < 0) {
        fprintf(stderr, "Error: Could not connect to lrd-bluetoothd daemon (bluetooth.sock)\n");
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
        printf("Commands:\n");
        printf("  status                - View Bluetooth adapter status, power, active MAC & privacy state\n");
        printf("  power <on|off>        - Turn Bluetooth radio on or off\n");
        printf("  scan [start|stop]     - Trigger or stop device discovery\n");
        printf("  devices               - List discovered, paired, and connected devices\n");
        printf("  pair <mac>            - Pair with remote Bluetooth device\n");
        printf("  connect <mac>         - Connect to paired device\n");
        printf("  disconnect [mac]      - Disconnect device (or all devices if omitted)\n");
        printf("  privacy <on|off|rot>  - Toggle or rotate anti-tracking BLE randomized MAC address\n");
        printf("  name [new-name]       - View or set adapter friendly name\n");
        return 1;
    }

    const char *action = argv[1];
    char cmd[2048] = {0};

    if (strcmp(action, "status") == 0) {
        snprintf(cmd, sizeof(cmd), "status");
    } else if (strcmp(action, "power") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: usage: power <on|off>\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "power %s", argv[2]);
    } else if (strcmp(action, "scan") == 0) {
        const char *sub = (argc >= 3) ? argv[2] : "on";
        snprintf(cmd, sizeof(cmd), "scan %s", sub);
    } else if (strcmp(action, "devices") == 0 || strcmp(action, "list") == 0) {
        snprintf(cmd, sizeof(cmd), "devices");
    } else if (strcmp(action, "pair") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: missing MAC address\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "pair %s", argv[2]);
    } else if (strcmp(action, "connect") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: missing MAC address\n"); return 1; }
        snprintf(cmd, sizeof(cmd), "connect %s", argv[2]);
    } else if (strcmp(action, "disconnect") == 0) {
        if (argc >= 3) {
            snprintf(cmd, sizeof(cmd), "disconnect %s", argv[2]);
        } else {
            snprintf(cmd, sizeof(cmd), "disconnect");
        }
    } else if (strcmp(action, "privacy") == 0) {
        const char *sub = (argc >= 3) ? argv[2] : "rotate";
        snprintf(cmd, sizeof(cmd), "privacy %s", sub);
    } else if (strcmp(action, "name") == 0) {
        if (argc >= 3) {
            snprintf(cmd, sizeof(cmd), "name %s", argv[2]);
        } else {
            snprintf(cmd, sizeof(cmd), "name");
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", action);
        return 1;
    }

    send_and_print(cmd);
    return 0;
}
