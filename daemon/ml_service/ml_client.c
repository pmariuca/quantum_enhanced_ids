#include "ml_client.h"
#include "../cJSON.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static const char *g_socket_path = NULL;

int ml_client_init(const char *socket_path) {
    g_socket_path = socket_path;
    return 0;
}

void ml_client_close(void) {}

float ml_client_infer(const ml_pid_buffer_t *buf) {
    if (!g_socket_path || !buf) return -1.0f;

    // Build JSON payload
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "sc_exec_count",          buf->sc_exec_count);
    cJSON_AddNumberToObject(root, "sc_memfd_count",         buf->sc_memfd_count);
    cJSON_AddNumberToObject(root, "sc_mprotect_x_count",    buf->sc_mprotect_x_count);
    cJSON_AddNumberToObject(root, "sc_mmap_x_count",        buf->sc_mmap_x_count);
    cJSON_AddNumberToObject(root, "sc_priv_change_count",   buf->sc_priv_change_count);
    cJSON_AddNumberToObject(root, "sc_clone_count",         buf->sc_clone_count);
    cJSON_AddNumberToObject(root, "sc_namespace_count",     buf->sc_namespace_count);
    cJSON_AddNumberToObject(root, "sc_socket_create_count", buf->sc_socket_create_count);

    cJSON_AddNumberToObject(root, "net_packet_out_count",      buf->net_packet_out_count);
    cJSON_AddNumberToObject(root, "net_packet_in_count",       buf->net_packet_in_count);
    cJSON_AddNumberToObject(root, "net_dns_count",             buf->net_dns_count);
    cJSON_AddNumberToObject(root, "net_suspicious_port_count", buf->net_suspicious_port_count);
    cJSON_AddNumberToObject(root, "net_unique_dst_ip",         buf->net_unique_dst_ips);
    cJSON_AddNumberToObject(root, "net_unique_dst_port",       buf->net_unique_dst_ports);

    float mean_len = buf->net_packet_out_count > 0
        ? (float)buf->net_total_packet_len / buf->net_packet_out_count
        : 0.0f;
    cJSON_AddNumberToObject(root, "net_mean_packet_len",    mean_len);
    cJSON_AddNumberToObject(root, "net_tcp_flags_anomaly",  buf->net_tcp_flags_anomaly);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    // Connect to ML server
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { free(json_str); return -1.0f; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[ML CLIENT ERROR] connect() failed: errno=%d (%s), socket_path=%s\n", 
               errno, strerror(errno), g_socket_path);
        close(sock);
        free(json_str);
        return -1.0f;
    }

    send(sock, json_str, strlen(json_str), 0);
    free(json_str);

    char resp[64] = {0};
    recv(sock, resp, sizeof(resp) - 1, 0);
    close(sock);

    return atof(resp);
}