#include "response_parser.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ---------- Network CSV parsing ---------- */

bool parse_network_line(const char *line, parsed_network_t *net)
{
    if (!line || line[0] != '"') return false;

    char tmp[256];
    strncpy(tmp, line, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *fields[8] = {NULL};
    int idx = 0;
    char *p = tmp;

    while (*p && idx < 8) {
        if (*p == '"') {
            p++;
            fields[idx] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') { *p = '\0'; p++; }
            idx++;
            if (*p == ',') p++;
        } else {
            p++;
        }
    }

    if (idx < 8) return false;

    memset(net, 0, sizeof(*net));
    net->index   = atoi(fields[0]);
    strncpy(net->ssid,     fields[1], sizeof(net->ssid) - 1);
    strncpy(net->bssid,    fields[3], sizeof(net->bssid) - 1);
    net->channel = atoi(fields[4]);
    strncpy(net->security, fields[5], sizeof(net->security) - 1);
    net->rssi    = atoi(fields[6]);
    strncpy(net->band,     fields[7], sizeof(net->band) - 1);

    return net->index > 0;
}

/* ---------- Password parsing ---------- */

bool parse_password_line(const char *line, parsed_password_t *pw)
{
    if (!line || line[0] != '"') return false;

    const char *ssid_start = line + 1;
    const char *ssid_end   = strchr(ssid_start, '"');
    if (!ssid_end) return false;

    const char *after = ssid_end + 1;
    while (*after == ',' || *after == ' ') after++;
    if (*after != '"') return false;

    const char *pw_start = after + 1;
    const char *pw_end   = strchr(pw_start, '"');
    if (!pw_end) return false;

    memset(pw, 0, sizeof(*pw));
    int ssid_len = ssid_end - ssid_start;
    if (ssid_len > (int)sizeof(pw->ssid) - 1) ssid_len = sizeof(pw->ssid) - 1;
    memcpy(pw->ssid, ssid_start, ssid_len);

    int pw_len = pw_end - pw_start;
    if (pw_len > (int)sizeof(pw->password) - 1) pw_len = sizeof(pw->password) - 1;
    memcpy(pw->password, pw_start, pw_len);

    return true;
}

/* ---------- Portal file parsing ---------- */

bool parse_portal_file_line(const char *line, parsed_portal_file_t *f)
{
    if (!line) return false;

    const char *p = line;
    while (*p == ' ') p++;
    if (!isdigit((unsigned char)*p)) return false;

    memset(f, 0, sizeof(*f));
    f->index = 0;
    while (isdigit((unsigned char)*p)) {
        f->index = f->index * 10 + (*p - '0');
        p++;
    }
    while (*p == ' ') p++;
    if (*p == '\0') return false;

    strncpy(f->filename, p, sizeof(f->filename) - 1);
    /* Trim trailing whitespace */
    int len = strlen(f->filename);
    while (len > 0 && f->filename[len - 1] <= ' ') {
        f->filename[--len] = '\0';
    }

    return f->index > 0 && len > 0;
}

/* ---------- Sniffer parsing ---------- */

bool parse_sniffer_ap_line(const char *line, parsed_sniffer_ap_t *ap)
{
    /* Format: "AX3, CH40: 2" */
    if (!line || line[0] == ' ') return false;

    const char *comma = strstr(line, ", CH");
    if (!comma) return false;

    const char *colon = strchr(comma, ':');
    if (!colon) return false;

    memset(ap, 0, sizeof(*ap));

    int ssid_len = comma - line;
    if (ssid_len > (int)sizeof(ap->ssid) - 1) ssid_len = sizeof(ap->ssid) - 1;
    memcpy(ap->ssid, line, ssid_len);

    ap->channel      = atoi(comma + 4); /* skip ", CH" */
    ap->client_total = atoi(colon + 1);
    ap->client_count = 0;

    return true;
}

bool parse_sniffer_client_line(const char *line, char *mac_out, int mac_len)
{
    if (!line || line[0] != ' ') return false;

    const char *p = line;
    while (*p == ' ') p++;

    /* Expect MAC format XX:XX:XX:XX:XX:XX (17 chars) */
    int len = strlen(p);
    if (len < 17) return false;

    /* Quick validation: check colons at expected positions */
    if (p[2] != ':' || p[5] != ':') return false;

    strncpy(mac_out, p, mac_len - 1);
    mac_out[mac_len - 1] = '\0';
    /* Trim to 17 chars if longer */
    if (strlen(mac_out) > 17) mac_out[17] = '\0';

    return true;
}

bool parse_sniffer_empty_line(const char *line)
{
    return line && strcmp(line, "No APs with clients found.") == 0;
}

/* ---------- Attack event detection ---------- */

attack_event_t parse_attack_event(const char *line)
{
    attack_event_t ev = { .type = ATTACK_EVENT_NONE, .detail = "", .int_val = 0 };
    if (!line) return ev;

    if (strstr(line, "Scan results printed")) {
        ev.type = ATTACK_EVENT_SCAN_COMPLETE;
    } else if (strstr(line, "HANDSHAKE IS COMPLETE AND VALID")) {
        ev.type = ATTACK_EVENT_HANDSHAKE_VALID;
    } else if (strstr(line, "PCAP saved:")) {
        ev.type = ATTACK_EVENT_PCAP_SAVED;
        const char *path = strstr(line, "PCAP saved:") + 11;
        while (*path == ' ') path++;
        strncpy(ev.detail, path, sizeof(ev.detail) - 1);
    } else if (strstr(line, "Password received:")) {
        ev.type = ATTACK_EVENT_PASSWORD_RECEIVED;
        const char *pw = strstr(line, "Password received:") + 18;
        while (*pw == ' ') pw++;
        strncpy(ev.detail, pw, sizeof(ev.detail) - 1);
    } else if (strstr(line, "password=")) {
        ev.type = ATTACK_EVENT_PASSWORD_RECEIVED;
        const char *pw = strstr(line, "password=") + 9;
        strncpy(ev.detail, pw, sizeof(ev.detail) - 1);
    } else if (strstr(line, "Password verified!")) {
        ev.type = ATTACK_EVENT_PASSWORD_VERIFIED;
    } else if (strstr(line, "AP: Client connected")) {
        ev.type = ATTACK_EVENT_CLIENT_CONNECTED;
        const char *mac = strstr(line, "MAC:");
        if (mac) {
            mac += 4;
            while (*mac == ' ') mac++;
            strncpy(ev.detail, mac, sizeof(ev.detail) - 1);
        }
    } else if (strstr(line, "AP: Client disconnected")) {
        ev.type = ATTACK_EVENT_CLIENT_DISCONNECTED;
        const char *mac = strstr(line, "MAC:");
        if (mac) {
            mac += 4;
            while (*mac == ' ') mac++;
            strncpy(ev.detail, mac, sizeof(ev.detail) - 1);
        }
    } else if (strstr(line, "Sniffer packet count:")) {
        ev.type = ATTACK_EVENT_SNIFFER_COUNT;
        ev.int_val = atoi(strstr(line, "count:") + 6);
    } else if (strstr(line, "Stop command received")) {
        ev.type = ATTACK_EVENT_STOP_ACK;
    }

    return ev;
}
