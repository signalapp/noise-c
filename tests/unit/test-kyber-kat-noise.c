/*
 * Kyber R3 KAT runner through the Noise DH wrapper.
 *
 * For each (sk, ct, ss) triplet in the provided .rsp file, constructs:
 *  - Initiator (Alice) with Kyber secret key (3168 bytes)
 *  - Responder-like public key state that holds the ciphertext as kyber_pub
 * Then runs noise_dhstate_calculate(initiator, responder_pubonly) and compares
 * the output shared secret with the expected KAT ss.
 *
 * This explicitly exercises our wrapper (including optional KDF), so it is
 * sensitive to NOISE_KYBER_KDF.
 *
 * Enable with KYBER_KAT_RSP=/path/to/PQCkemKAT_3168.rsp
 */

#include "test-helpers.h"
#include <ctype.h>

static int hexpair(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_to(uint8_t *out, size_t outlen, const char *eq) {
    while (*eq && isspace((unsigned char)*eq)) ++eq;
    if (eq[0] == '0' && (eq[1] == 'x' || eq[1] == 'X')) eq += 2;
    size_t i = 0; int hi = -1;
    for (; *eq; ++eq) {
        if (isspace((unsigned char)*eq)) continue;
        int v = hexpair(*eq);
        if (v < 0) break;
        if (hi < 0) hi = v; else { if (i >= outlen) return -1; out[i++] = (uint8_t)((hi<<4)|v); hi = -1; }
    }
    return (i == outlen && hi < 0) ? 0 : -1;
}

static FILE *open_kat_file(const char **out_path)
{
    const char *env = getenv("KYBER_KAT_RSP");
    if (env && *env) {
        FILE *fp = fopen(env, "r");
        if (fp) { if (out_path) *out_path = env; return fp; }
    }
    /* Try common fallbacks */
    static char candidate[1024];
    const char *srcdir = getenv("srcdir");
    const char *names[] = {
        "PQCkemKAT_3168.rsp",
        "../kat/PQCkemKAT_3168.rsp",
        srcdir ? "" : NULL
    };
    if (srcdir) {
        snprintf(candidate, sizeof(candidate), "%s/../kat/PQCkemKAT_3168.rsp", srcdir);
        FILE *fp = fopen(candidate, "r");
        if (fp) { if (out_path) *out_path = candidate; return fp; }
        snprintf(candidate, sizeof(candidate), "%s/PQCkemKAT_3168.rsp", srcdir);
        fp = fopen(candidate, "r");
        if (fp) { if (out_path) *out_path = candidate; return fp; }
    }
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
        if (!names[i]) continue;
        FILE *fp = fopen(names[i], "r");
        if (fp) { if (out_path) *out_path = names[i]; return fp; }
    }
    return NULL;
}

void test_kyber_kat_noise(void)
{
    const char *path = NULL;
    FILE *fp = open_kat_file(&path);
    if (!fp)
        return; /* skip */

    char line[1<<15];
    uint8_t sk[3168];
    uint8_t ct[1568];
    uint8_t ss[32];
    int got_sk = 0, got_ct = 0, got_ss = 0;
    int cases = 0;
    size_t seen_sk = 0, seen_ct = 0, seen_ss = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *p;
        if ((p = strstr(line, "sk =")) != NULL) {
            got_sk = (parse_hex_to(sk, sizeof(sk), p + 4) == 0);
            ++seen_sk;
        } else if ((p = strstr(line, "ct =")) != NULL) {
            got_ct = (parse_hex_to(ct, sizeof(ct), p + 4) == 0);
            ++seen_ct;
        } else if ((p = strstr(line, "ss =")) != NULL) {
            got_ss = (parse_hex_to(ss, sizeof(ss), p + 4) == 0);
            ++seen_ss;
        }
        if (got_sk && got_ct && got_ss) {
            NoiseDHState *alice, *bobpub;
            uint8_t out[32];
            compare(noise_dhstate_new_by_id(&alice, NOISE_DH_KYBER1024), NOISE_ERROR_NONE);
            compare(noise_dhstate_new_by_id(&bobpub, NOISE_DH_KYBER1024), NOISE_ERROR_NONE);
            compare(noise_dhstate_set_role(alice, NOISE_ROLE_INITIATOR), NOISE_ERROR_NONE);
            compare(noise_dhstate_set_role(bobpub, NOISE_ROLE_RESPONDER), NOISE_ERROR_NONE);
            /* Set Alice's private key (full Kyber sk), derive pk internally */
            compare(noise_dhstate_set_keypair_private(alice, sk, sizeof(sk)), NOISE_ERROR_NONE);
            /* Set Bob's public key to ciphertext */
            compare(noise_dhstate_set_public_key(bobpub, ct, sizeof(ct)), NOISE_ERROR_NONE);
            /* Calculate ss via wrapper */
            compare(noise_dhstate_calculate(alice, bobpub, out, sizeof(out)), NOISE_ERROR_NONE);
            compare_blocks(out, sizeof(out), ss, sizeof(ss));
            compare(noise_dhstate_free(alice), NOISE_ERROR_NONE);
            compare(noise_dhstate_free(bobpub), NOISE_ERROR_NONE);
            ++cases;
            got_sk = got_ct = got_ss = 0;
        }
    }
    fclose(fp);
    if (!(cases > 0)) {
        verify(0);
    }
}
