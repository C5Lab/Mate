#include "response_parser.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void expect_fail(const char *line)
{
    parsed_network_t net;
    memset(&net, 0x5a, sizeof(net));
    assert(!parse_network_line(line, &net));
    assert(((unsigned char *)&net)[0] == 0x5a);
}

static void test_quoted_ssid_and_vendor(void)
{
    parsed_network_t net;
    const char *line =
        "\"1\",\"moja \"\"specjalna\"\" siec\",\"Acme \"\"X\"\" Inc\","
        "\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"";
    assert(parse_network_line(line, &net));
    assert(net.index == 1);
    assert(strcmp(net.ssid, "moja \"specjalna\" siec") == 0);
    assert(strcmp(net.vendor, "Acme \"X\" Inc") == 0);
    assert(strcmp(net.bssid, "AA:BB:CC:DD:EE:FF") == 0);
    assert(net.channel == 6);
    assert(strcmp(net.security, "WPA2") == 0);
    assert(net.rssi == -50);
    assert(strcmp(net.band, "2.4GHz") == 0);
}

static void test_plain_lines(void)
{
    parsed_network_t net;
    assert(parse_network_line(
        "\"1\",\"AX3\",\"\",\"C4:2B:44:12:29:20\",\"112\",\"WPA2\",\"-59\",\"5GHz\"",
        &net));
    assert(net.index == 1);
    assert(strcmp(net.ssid, "AX3") == 0);
    assert(net.vendor[0] == '\0');
    assert(strcmp(net.bssid, "C4:2B:44:12:29:20") == 0);
    assert(net.channel == 112);
    assert(strcmp(net.security, "WPA2") == 0);
    assert(net.rssi == -59);
    assert(strcmp(net.band, "5GHz") == 0);

    assert(parse_network_line(
        "\"2\",\"BRW\",\"\",\"64:7C:34:41:8F:EC\",\"7\",\"WPA/WPA2 Mixed\",\"-72\",\"2.4GHz\"",
        &net));
    assert(net.index == 2);
    assert(strcmp(net.ssid, "BRW") == 0);
    assert(net.vendor[0] == '\0');
    assert(strcmp(net.bssid, "64:7C:34:41:8F:EC") == 0);
    assert(net.channel == 7);
    assert(strcmp(net.security, "WPA/WPA2 Mixed") == 0);
    assert(net.rssi == -72);
    assert(strcmp(net.band, "2.4GHz") == 0);
}

static void test_commas_inside_fields(void)
{
    parsed_network_t net;
    const char *line =
        "\"9\",\"a, \"\"b\"\", c\",\"Vendor, \"\"Q\"\"\","
        "\"AA:BB:CC:DD:EE:FF\",\"36\",\"WPA2/WPA3 Mixed\",\"-61\",\"5GHz\"";
    assert(parse_network_line(line, &net));
    assert(strcmp(net.ssid, "a, \"b\", c") == 0);
    assert(strcmp(net.vendor, "Vendor, \"Q\"") == 0);
    assert(strcmp(net.bssid, "AA:BB:CC:DD:EE:FF") == 0);
    assert(net.channel == 36);
    assert(strcmp(net.security, "WPA2/WPA3 Mixed") == 0);
    assert(net.rssi == -61);
    assert(strcmp(net.band, "5GHz") == 0);
}

static void test_quote_positions_and_hidden(void)
{
    parsed_network_t net;
    assert(parse_network_line(
        "\"4\",\"\"\"quoted\"\"\",\"v\",\"AA:BB:CC:DD:EE:02\",\"6\",\"WPA2\",\"-40\",\"5GHz\"",
        &net));
    assert(strcmp(net.ssid, "\"quoted\"") == 0);
    assert(strcmp(net.vendor, "v") == 0);

    assert(parse_network_line(
        "\"5\",\"end\"\"\",\"Acme\",\"AA:BB:CC:DD:EE:03\",\"6\",\"WPA2\",\"-55\",\"2.4GHz\"",
        &net));
    assert(strcmp(net.ssid, "end\"") == 0);

    assert(parse_network_line(
        "\"3\",\"\",\"\",\"AA:BB:CC:DD:EE:01\",\"1\",\"OPEN\",\"-90\",\"2.4GHz\"",
        &net));
    assert(net.index == 3);
    assert(net.ssid[0] == '\0');
    assert(net.vendor[0] == '\0');
    assert(net.channel == 1);
    assert(net.rssi == -90);
    assert(strcmp(net.security, "OPEN") == 0);
}

/* A vendor longer than the stored buffer, and a line longer than the old
 * 256-byte copy, must not shift BSSID / channel / RSSI / band. */
static void test_long_vendor_does_not_shift_fields(void)
{
    parsed_network_t net;
    char line[640];
    char vendor[220];
    int n;

    memset(vendor, 'V', sizeof(vendor) - 1);
    vendor[sizeof(vendor) - 1] = '\0';
    n = snprintf(line, sizeof(line),
                 "\"8\",\"moja \"\"specjalna\"\" siec\",\"%s\","
                 "\"AA:BB:CC:DD:EE:FF\",\"11\",\"WPA2\",\"-33\",\"2.4GHz\"",
                 vendor);
    assert(n > 256 && n < (int)sizeof(line));
    assert(parse_network_line(line, &net));
    assert(strcmp(net.ssid, "moja \"specjalna\" siec") == 0);
    assert(strlen(net.vendor) == sizeof(net.vendor) - 1);
    assert(net.vendor[0] == 'V');
    assert(strcmp(net.bssid, "AA:BB:CC:DD:EE:FF") == 0);
    assert(net.channel == 11);
    assert(strcmp(net.security, "WPA2") == 0);
    assert(net.rssi == -33);
    assert(strcmp(net.band, "2.4GHz") == 0);
}

static void test_ssid_truncation_keeps_alignment(void)
{
    parsed_network_t net;
    char ssid[48];
    char line[256];
    memset(ssid, 'S', sizeof(ssid) - 1);
    ssid[sizeof(ssid) - 1] = '\0';
    snprintf(line, sizeof(line),
             "\"12\",\"%s\",\"Cisco\",\"AA:BB:CC:DD:EE:10\",\"44\",\"WPA2\",\"-70\",\"5GHz\"",
             ssid);
    assert(parse_network_line(line, &net));
    assert(strlen(net.ssid) == sizeof(net.ssid) - 1);
    assert(strcmp(net.vendor, "Cisco") == 0);
    assert(strcmp(net.bssid, "AA:BB:CC:DD:EE:10") == 0);
    assert(net.channel == 44);
    assert(net.rssi == -70);
    assert(strcmp(net.band, "5GHz") == 0);
}

static void test_rejects(void)
{
    expect_fail(NULL);
    expect_fail("");
    expect_fail("Scan results printed");
    expect_fail("\"Cafe\", \"secret\"");
    expect_fail("\"1\",\"only-seven\",\"v\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\"");
    expect_fail("\"1\",\"unterminated");
    expect_fail("\"0\",\"AX3\",\"\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"");
    assert(!parse_network_line(
        "\"1\",\"moja \"\"specjalna\"\" siec\",\"Acme \"\"X\"\" Inc\","
        "\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"",
        NULL));
}

int main(void)
{
    test_quoted_ssid_and_vendor();
    test_plain_lines();
    test_commas_inside_fields();
    test_quote_positions_and_hidden();
    test_long_vendor_does_not_shift_fields();
    test_ssid_truncation_keeps_alignment();
    test_rejects();
    puts("scan CSV parser PASS");
    return 0;
}
