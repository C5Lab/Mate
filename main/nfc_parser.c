#include "nfc_parser.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

void nfc_card_reset(nfc_ui_card_t *c)
{
    if (!c) return;
    memset(c, 0, sizeof(*c));
}

bool nfc_line_is_end(const char *line)
{
    if (!line) return false;
    return strcmp(line, "[NFC] END") == 0 || strcmp(line, "[NFC] END\r") == 0;
}

static void copy_reason(nfc_ui_card_t *c, const char *line, const char *prefix)
{
    if (!c || !line || !prefix) return;
    const char *p = strstr(line, prefix);
    if (!p) return;
    p += strlen(prefix);
    while (*p == ' ') p++;
    snprintf(c->error, sizeof(c->error), "%s", p);
}

bool nfc_parse_card_line(const char *line, nfc_ui_card_t *c)
{
    if (!line || !c) return false;
    if (strncmp(line, "[NFC]", 5) != 0) return false;

    if (nfc_line_is_end(line))
        return true;

    if (strncmp(line, "[NFC] type: ", 12) == 0) {
        snprintf(c->type, sizeof(c->type), "%s", line + 12);
        return true;
    }
    if (strncmp(line, "[NFC] uid: ", 11) == 0) {
        snprintf(c->uid, sizeof(c->uid), "%s", line + 11);
        return true;
    }
    if (strncmp(line, "[NFC] atqa: ", 12) == 0) {
        unsigned a0 = 0, a1 = 0, sak = 0;
        if (sscanf(line, "[NFC] atqa: %02X %02X  sak: %02X", &a0, &a1, &sak) == 3) {
            c->atqa[0] = (uint8_t)a0;
            c->atqa[1] = (uint8_t)a1;
            c->sak = (uint8_t)sak;
            c->have_atqa_sak = true;
        }
        return true;
    }
    if (strncmp(line, "[NFC] idm: ", 11) == 0) {
        snprintf(c->idm, sizeof(c->idm), "%s", line + 11);
        c->have_idm = true;
        return true;
    }
    if (strncmp(line, "[NFC] data: ", 12) == 0) {
        if (sscanf(line, "[NFC] data: %u bytes, %u blocks x %u",
                   &c->data_len, &c->num_blocks, &c->block_size) >= 1) {
            c->have_data = true;
        }
        return true;
    }
    if (strncmp(line, "[NFC] bus: ", 11) == 0) {
        sscanf(line + 11, "%11s", c->bus);
        c->have_bus = true;
        return true;
    }
    if (strncmp(line, "[NFC] bus set to ", 17) == 0) {
        sscanf(line + 17, "%11s", c->bus);
        c->have_bus = true;
        c->have_bus_set = true;
        return true;
    }
    if (strncmp(line, "[NFC] backend: ", 15) == 0) {
        snprintf(c->backend, sizeof(c->backend), "%s", line + 15);
        c->have_backend = true;
        return true;
    }
    if (strstr(line, "[NFC] present a card")) {
        c->present_card = true;
        return true;
    }
    if (strstr(line, "[NFC] no saved cards")) {
        c->no_saved_cards = true;
        return true;
    }
    if (strstr(line, "[NFC] no card detected")) {
        c->no_card = true;
        return true;
    }
    if (strstr(line, "[NFC] not detected")) {
        c->not_detected = true;
        return true;
    }
    if (strstr(line, "[NFC] detected")) {
        c->detected = true;
        return true;
    }
    if (strstr(line, "[NFC] not initialized")) {
        c->not_initialized = true;
        return true;
    }
    if (strstr(line, "[NFC] nothing to save")) {
        c->nothing_to_save = true;
        return true;
    }
    if (strstr(line, "[NFC] emulate failed")) {
        c->emulate_failed = true;
        return true;
    }
    if (strstr(line, "[NFC] no card loaded")) {
        c->no_card_loaded = true;
        return true;
    }
    if (strstr(line, "[NFC] load failed")) {
        c->load_failed = true;
        copy_reason(c, line, "load failed:");
        return true;
    }
    if (strstr(line, "[NFC] not found")) {
        c->not_found = true;
        copy_reason(c, line, "not found:");
        return true;
    }
    if (strncmp(line, "[NFC] saved: ", 13) == 0) {
        snprintf(c->saved_path, sizeof(c->saved_path), "%s", line + 13);
        c->have_saved = true;
        return true;
    }
    if (strstr(line, "[NFC] save failed")) {
        c->save_failed = true;
        copy_reason(c, line, "save failed:");
        return true;
    }
    if (strncmp(line, "[NFC] loaded: ", 14) == 0) {
        snprintf(c->loaded_path, sizeof(c->loaded_path), "%s", line + 14);
        c->have_loaded = true;
        return true;
    }
    if (strncmp(line, "[NFC] renamed: ", 15) == 0) {
        const char *rest = line + 15;
        const char *arrow = strstr(rest, " -> ");
        if (arrow) {
            size_t n = (size_t)(arrow - rest);
            if (n >= sizeof(c->renamed_from)) n = sizeof(c->renamed_from) - 1;
            memcpy(c->renamed_from, rest, n);
            c->renamed_from[n] = '\0';
            snprintf(c->renamed_to, sizeof(c->renamed_to), "%s", arrow + 4);
        } else {
            snprintf(c->renamed_to, sizeof(c->renamed_to), "%s", rest);
        }
        c->have_renamed = true;
        return true;
    }
    if (strstr(line, "[NFC] rename failed")) {
        c->rename_failed = true;
        copy_reason(c, line, "rename failed:");
        return true;
    }
    if (strncmp(line, "[NFC] deleted: ", 15) == 0) {
        snprintf(c->deleted_path, sizeof(c->deleted_path), "%s", line + 15);
        c->have_deleted = true;
        return true;
    }
    if (strstr(line, "[NFC] delete failed")) {
        c->delete_failed = true;
        copy_reason(c, line, "delete failed:");
        return true;
    }
    if (strncmp(line, "[NFC] emulating ", 16) == 0) {
        snprintf(c->emulating_summary, sizeof(c->emulating_summary), "%s", line + 16);
        char *use = strstr(c->emulating_summary, ". Use ");
        if (use) *use = '\0';
        c->have_emulating = true;
        return true;
    }
    if (strstr(line, "full NTAG/Ultralight page data emulated")) {
        c->emulate_full_ul = true;
        return true;
    }
    if (strstr(line, "UID/ATQA/SAK level only")) {
        c->emulate_uid_only = true;
        return true;
    }

    return true; /* other [NFC] lines still count as handled */
}

bool nfc_parse_list_entry(const char *line, nfc_list_entry_t *out)
{
    if (!line || !out) return false;
    if (strstr(line, "[NFC]")) return false;

    int idx = -1;
    char name[64];
    if (sscanf(line, "%d %63s", &idx, name) != 2) return false;
    if (idx < 0) return false;

    out->idx = idx;
    snprintf(out->name, sizeof(out->name), "%s", name);
    return true;
}

bool nfc_parse_card_count(const char *line, int *out_n)
{
    if (!line || !out_n) return false;
    int n = 0;
    if (sscanf(line, "[NFC] %d card(s)", &n) == 1) {
        *out_n = n;
        return true;
    }
    return false;
}

bool nfc_name_is_valid(const char *name)
{
    if (!name || !name[0]) return false;
    for (const char *p = name; *p; p++) {
        if (isalnum((unsigned char)*p)) continue;
        if (*p == '_' || *p == '-' || *p == '.') continue;
        return false;
    }
    return true;
}

void nfc_path_basename(const char *path, char *out, size_t out_len, bool strip_nfc)
{
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!path || !path[0]) return;

    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    snprintf(out, out_len, "%s", base);

    if (strip_nfc) {
        size_t n = strlen(out);
        if (n > 4 && strcmp(out + n - 4, ".nfc") == 0)
            out[n - 4] = '\0';
    }
}

void nfc_format_card_detail(const nfc_ui_card_t *c,
                            char *status, size_t status_len,
                            char *detail, size_t detail_len)
{
    if (status && status_len)
        status[0] = '\0';
    if (detail && detail_len)
        detail[0] = '\0';
    if (!c) return;

    if (status && status_len) {
        snprintf(status, status_len, "%s", c->type[0] ? c->type : "Card");
    }
    if (!detail || !detail_len) return;

    char extra[64] = {0};
    if (c->have_loaded && c->loaded_path[0])
        nfc_path_basename(c->loaded_path, extra, sizeof(extra), false);

    if (c->have_atqa_sak) {
        snprintf(detail, detail_len,
                 "UID %s\nATQA %02X %02X  SAK %02X%s%s%s",
                 c->uid[0] ? c->uid : "--",
                 c->atqa[0], c->atqa[1], c->sak,
                 c->have_data ? "\nData dumped" : "",
                 extra[0] ? "\n" : "", extra);
    } else if (c->have_idm) {
        snprintf(detail, detail_len, "UID %s\nIDm %s%s%s",
                 c->uid[0] ? c->uid : "--", c->idm,
                 extra[0] ? "\n" : "", extra);
    } else {
        snprintf(detail, detail_len, "UID %s%s%s%s",
                 c->uid[0] ? c->uid : "--",
                 c->have_data ? "\nData dumped" : "",
                 extra[0] ? "\n" : "", extra);
    }
}

bool nfc_type_is_classic(const char *type)
{
    return type && strstr(type, "Classic") != NULL;
}

bool nfc_type_is_ultralight(const char *type)
{
    if (!type) return false;
    return strstr(type, "Ultralight") != NULL ||
           strstr(type, "NTAG") != NULL ||
           strstr(type, "MF0UL") != NULL;
}

bool nfc_card_is_present(const nfc_ui_card_t *c)
{
    if (!c) return false;
    if (c->no_card || c->not_detected || c->not_initialized || c->load_failed)
        return false;
    return c->type[0] || c->uid[0] || c->have_loaded;
}
