#include "response_parser.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ---------- Network CSV parsing ---------- */

/* Read one RFC 4180 quoted field from *pp.
 * `""` inside the field becomes a single `"`. On success *pp is advanced
 * past the field and a single separating comma, if one is present.
 * Bytes that do not fit in `out` are discarded so a long SSID or vendor
 * cannot shift BSSID / channel / RSSI / band. `out` is always NUL-terminated
 * when out_len > 0. Does not write past out_len. */
static bool csv_quoted_field(const char **pp, char *out, size_t out_len)
{
    const char *p;
    size_t n = 0;

    if (!pp || !out || out_len == 0) return false;
    p = *pp;
    if (!p || *p != '"') return false;
    p++;

    while (*p) {
        if (*p == '"') {
            if (p[1] == '"') {
                if (n + 1 < out_len) out[n++] = '"';
                p += 2;
                continue;
            }
            p++;
            out[n] = '\0';
            if (*p == ',') p++;
            *pp = p;
            return true;
        }
        if (n + 1 < out_len) out[n++] = *p;
        p++;
    }
    return false;
}

bool parse_network_line(const char *line, parsed_network_t *net)
{
    parsed_network_t tmp;
    char index_s[16];
    char channel_s[16];
    char rssi_s[16];
    const char *p;

    if (!line || !net || line[0] != '"') return false;

    memset(&tmp, 0, sizeof(tmp));
    p = line;
    if (!csv_quoted_field(&p, index_s, sizeof(index_s))) return false;
    if (!csv_quoted_field(&p, tmp.ssid, sizeof(tmp.ssid))) return false;
    if (!csv_quoted_field(&p, tmp.vendor, sizeof(tmp.vendor))) return false;
    if (!csv_quoted_field(&p, tmp.bssid, sizeof(tmp.bssid))) return false;
    if (!csv_quoted_field(&p, channel_s, sizeof(channel_s))) return false;
    if (!csv_quoted_field(&p, tmp.security, sizeof(tmp.security))) return false;
    if (!csv_quoted_field(&p, rssi_s, sizeof(rssi_s))) return false;
    if (!csv_quoted_field(&p, tmp.band, sizeof(tmp.band))) return false;

    tmp.index   = atoi(index_s);
    tmp.channel = atoi(channel_s);
    tmp.rssi    = atoi(rssi_s);
    if (tmp.index <= 0) return false;

    *net = tmp;
    return true;
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

bool parse_portal_password_line(const char *line, parsed_password_t *pw)
{
    if (!line || line[0] != '"') return false;

    const char *ssid_start = line + 1;
    const char *ssid_end   = strchr(ssid_start, '"');
    if (!ssid_end) return false;

    memset(pw, 0, sizeof(*pw));
    int ssid_len = ssid_end - ssid_start;
    if (ssid_len > (int)sizeof(pw->ssid) - 1) ssid_len = sizeof(pw->ssid) - 1;
    memcpy(pw->ssid, ssid_start, ssid_len);

    /* Join every remaining quoted field into the password/detail buffer. */
    const char *p = ssid_end + 1;
    int  out   = 0;
    bool first = true;
    while (*p) {
        const char *q1 = strchr(p, '"');
        if (!q1) break;
        const char *q2 = strchr(q1 + 1, '"');
        if (!q2) break;

        if (!first && out < (int)sizeof(pw->password) - 3) {
            pw->password[out++] = ';';
            pw->password[out++] = ' ';
        }
        for (const char *c = q1 + 1; c < q2 && out < (int)sizeof(pw->password) - 1; c++) {
            pw->password[out++] = *c;
        }
        first = false;
        p = q2 + 1;
    }
    pw->password[out] = '\0';

    return pw->ssid[0] != '\0';
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

/* ---------- Probe parsing ---------- */

bool parse_probe_line(const char *line, parsed_probe_t *p)
{
    if (!line || !p) return false;

    const char *q = line;
    while (*q == ' ' || *q == '\t') q++;
    if (!isdigit((unsigned char)*q)) return false;

    int idx = 0;
    while (isdigit((unsigned char)*q)) {
        idx = idx * 10 + (*q - '0');
        q++;
    }
    if (idx <= 0) return false;
    if (*q != ' ' && *q != '\t') return false;
    while (*q == ' ' || *q == '\t') q++;
    if (*q == '\0') return false;

    memset(p, 0, sizeof(*p));
    p->index = idx;
    strncpy(p->ssid, q, sizeof(p->ssid) - 1);

    int len = strlen(p->ssid);
    while (len > 0 && p->ssid[len - 1] <= ' ') {
        p->ssid[--len] = '\0';
    }

    return len > 0;
}

/* ---------- Sniffer parsing ---------- */

bool parse_sniffer_ap_line(const char *line, parsed_sniffer_ap_t *ap)
{
    /* Primary format from SKILL:
     *   "AX3, CH40: 2"
     * Additional tolerated variants:
     *   "AX3,CH40:2"
     *   "AX3, CH40: 2 [Vendor]"
     */
    if (!line) return false;

    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0') return false;

    /* Client lines are indented MACs; AP lines are not. */
    if (line[0] == ' ' || line[0] == '\t') return false;

    const char *ch = strstr(p, "CH");
    if (!ch) return false;

    const char *colon = strchr(ch, ':');
    if (!colon) return false;

    const char *ssid_end = ch;
    while (ssid_end > p && (ssid_end[-1] == ' ' || ssid_end[-1] == ',')) ssid_end--;
    if (ssid_end <= p) return false;

    memset(ap, 0, sizeof(*ap));

    int ssid_len = (int)(ssid_end - p);
    if (ssid_len > (int)sizeof(ap->ssid) - 1) ssid_len = sizeof(ap->ssid) - 1;
    memcpy(ap->ssid, p, ssid_len);
    ap->ssid[ssid_len] = '\0';

    ap->channel = atoi(ch + 2);
    ap->client_total = atoi(colon + 1);
    if (ap->client_total < 0) ap->client_total = 0;

    /* Caller owns client storage (heap-backed dynvec under the hood); leave
     * the pointer fields in a defined "no clients yet" state. */
    ap->client_count = 0;
    ap->client_cap   = 0;
    ap->clients      = NULL;

    return ap->channel > 0;
}

bool parse_sniffer_client_line(const char *line, char *mac_out, int mac_len)
{
    if (!line || !mac_out || mac_len < 18) return false;

    /* In SKILL, client lines are indented with leading whitespace. */
    if (!(line[0] == ' ' || line[0] == '\t')) return false;

    const char *p = line;
    while (*p) {
        if (isxdigit((unsigned char)p[0]) &&
            isxdigit((unsigned char)p[1]) &&
            p[2] == ':' &&
            isxdigit((unsigned char)p[3]) &&
            isxdigit((unsigned char)p[4]) &&
            p[5] == ':' &&
            isxdigit((unsigned char)p[6]) &&
            isxdigit((unsigned char)p[7]) &&
            p[8] == ':' &&
            isxdigit((unsigned char)p[9]) &&
            isxdigit((unsigned char)p[10]) &&
            p[11] == ':' &&
            isxdigit((unsigned char)p[12]) &&
            isxdigit((unsigned char)p[13]) &&
            p[14] == ':' &&
            isxdigit((unsigned char)p[15]) &&
            isxdigit((unsigned char)p[16])) {
            memcpy(mac_out, p, 17);
            mac_out[17] = '\0';
            return true;
        }
        p++;
    }

    return false;
}

bool parse_sniffer_empty_line(const char *line)
{
    return line && strstr(line, "No APs with clients found.") != NULL;
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
    } else if (strstr(line, "Received POST data:")) {
        ev.type = ATTACK_EVENT_PORTAL_DATA;
        const char *d = strstr(line, "Received POST data:") + strlen("Received POST data:");
        while (*d == ' ') d++;
        strncpy(ev.detail, d, sizeof(ev.detail) - 1);
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
    } else if (strstr(line, "Password: ")) {
        ev.type = ATTACK_EVENT_PASSWORD_RECEIVED;
        const char *pw = strstr(line, "Password: ") + 10;
        strncpy(ev.detail, pw, sizeof(ev.detail) - 1);
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
