/*
 * Kyber Round 3 KAT runner (decapsulation side).
 *
 * Reads a NIST-style .rsp file (e.g., PQClean Kyber1024 R3 KAT), and for each
 * test vector with fields sk, ct, ss, verifies that our decapsulation matches
 * the expected shared secret. We also optionally apply the Kyber KDF wrapper
 * used in this repository if KYBER_KDF=1 is set, since our backend is ML-KEM.
 *
 * To enable: set environment variable KYBER_KAT_RSP to the .rsp filepath.
 * The test will be skipped if the file is not specified or cannot be opened.
 */

#include "test-helpers.h"
#include "crypto/newhope/fips202.h"
#include "crypto/mlkem-libjade/src/mlkem1024_amd64_avx2/api.h"
#include <ctype.h>

static int hexpair(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_to(uint8_t *out, size_t outlen, const char *eq) {
    /* eq points at the character after '='; skip spaces */
    while (*eq && isspace((unsigned char)*eq)) ++eq;
    /* expect optional 0x prefix */
    if (eq[0] == '0' && (eq[1] == 'x' || eq[1] == 'X')) eq += 2;
    size_t i = 0; int hi = -1;
    for (; *eq; ++eq) {
        if (isspace((unsigned char)*eq)) continue;
        int v = hexpair(*eq);
        if (v < 0) break;
        if (hi < 0) {
            hi = v;
        } else {
            if (i >= outlen) return -1;
            out[i++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    return (i == outlen && hi < 0) ? 0 : -1;
}

static void kyber_kdf_wrap(uint8_t *out32,
                           const uint8_t *mlkem_ss,
                           const uint8_t *ct, size_t ct_len)
{
    uint8_t buf[64];
    memcpy(buf, mlkem_ss, 32);
    sha3256(buf + 32, ct, (unsigned int)ct_len);
    shake256(out32, 32, buf, 64);
    memset(buf, 0, sizeof(buf));
}

static FILE *open_kat_file2(const char **out_path)
{
    const char *env = getenv("KYBER_KAT_RSP");
    if (env && *env) {
        FILE *fp = fopen(env, "r");
        if (fp) { if (out_path) *out_path = env; return fp; }
    }
    static char candidate[1024];
    const char *srcdir = getenv("srcdir");
    if (srcdir) {
        snprintf(candidate, sizeof(candidate), "%s/../kat/PQCkemKAT_3168.rsp", srcdir);
        FILE *fp = fopen(candidate, "r");
        if (fp) { if (out_path) *out_path = candidate; return fp; }
        snprintf(candidate, sizeof(candidate), "%s/PQCkemKAT_3168.rsp", srcdir);
        fp = fopen(candidate, "r");
        if (fp) { if (out_path) *out_path = candidate; return fp; }
    }
    const char *names[] = { "PQCkemKAT_3168.rsp", "../kat/PQCkemKAT_3168.rsp" };
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
        FILE *fp = fopen(names[i], "r");
        if (fp) { if (out_path) *out_path = names[i]; return fp; }
    }
    return NULL;
}

void test_kyber_kat(void)
{
    const char *path = NULL;
    FILE *fp = open_kat_file2(&path);
    if (!fp)
        return;

    int assert_raw = getenv("KYBER_ASSERT_RAW") ? 1 : 0;
    int apply_kdf = 1; /* Default to Kyber R3 behavior: compare KDF'd value */
    const char *ek = getenv("KYBER_KDF");
    if (ek && (ek[0] == '0' || ek[0] == 'n' || ek[0] == 'N'))
        apply_kdf = 0;
    /* Lines in KAT files can be very long (e.g., sk is 3168 bytes → 6336 hex chars). */
    char line[1<<15];
    int cases = 0;
    size_t seen_sk = 0, seen_ct = 0, seen_ss = 0;
    /* Stream through the file and process any (sk, ct, ss) triplet in order. */
    uint8_t sk[jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES];
    uint8_t ct[jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES];
    uint8_t ss[32];
    int got_sk = 0, got_ct = 0, got_ss = 0;
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
            uint8_t out_mlkem[32];
            uint8_t out_kdf[32];
            compare(jade_kem_mlkem_mlkem1024_amd64_avx2_dec(out_mlkem, ct, sk), 0);
            kyber_kdf_wrap(out_kdf, out_mlkem, ct, sizeof(ct));
            if (assert_raw) {
                compare_blocks(out_mlkem, sizeof(out_mlkem), ss, sizeof(ss));
                verify(memcmp(out_kdf, ss, 32) != 0);
            } else {
                if (apply_kdf)
                    compare_blocks(out_kdf, sizeof(out_kdf), ss, sizeof(ss));
                else
                    compare_blocks(out_mlkem, sizeof(out_mlkem), ss, sizeof(ss));
            }
            ++cases;
            got_sk = got_ct = got_ss = 0;
        }
    }
    fclose(fp);
    /* At least one case should have been tested if file was present */
    if (!(cases > 0)) {
        /* Emit simple counts to help diagnose format issues. */
        printf("KYBER_KAT_COUNTS sk=%zu ct=%zu ss=%zu cases=%d\n",
               seen_sk, seen_ct, seen_ss, cases);
        fflush(stdout);
        verify(0);
    }
}
