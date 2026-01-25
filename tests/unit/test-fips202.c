/*
 * Unit tests for SHA3-256 and SHAKE256 (FIPS 202) primitives used by Kyber.
 */

#include "test-helpers.h"
#include "crypto/newhope/fips202.h"

static void check_sha3_256(const char *name,
                           const uint8_t *msg, size_t msg_len,
                           const char *expected_hex)
{
    uint8_t out[32];
    uint8_t expected[32];
    compare(string_to_data(expected, sizeof(expected), expected_hex), 32);
    sha3256(out, msg, (unsigned int)msg_len);
    compare_blocks(out, sizeof(out), expected, sizeof(expected));
}

static void check_shake256_32(const char *name,
                              const uint8_t *msg, size_t msg_len,
                              const char *expected_hex)
{
    uint8_t out[32];
    uint8_t expected[32];
    compare(string_to_data(expected, sizeof(expected), expected_hex), 32);
    shake256(out, 32, msg, (unsigned int)msg_len);
    compare_blocks(out, sizeof(out), expected, sizeof(expected));
}

void test_fips202(void)
{
    static const uint8_t empty[] = { };
    static const uint8_t abc[] = { 'a','b','c' };

    /* SHA3-256 KATs */
    check_sha3_256("SHA3-256("")", empty, 0,
                   "0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    check_sha3_256("SHA3-256(abc)", abc, sizeof(abc),
                   "0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    /* SHAKE256 KATs (first 32 bytes) */
    check_shake256_32("SHAKE256("")[:32]", empty, 0,
                      "0x46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    check_shake256_32("SHAKE256(abc)[:32]", abc, sizeof(abc),
                      "0x483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
}

