/*
 * Unit tests to validate Kyber wrapper KDF application against ML-KEM.
 */

#include "test-helpers.h"
#include "crypto/mlkem-libjade/src/mlkem1024_amd64_avx2/api.h"
#include "crypto/newhope/fips202.h"

void test_kyber(void)
{
    NoiseDHState *alice; /* initiator */
    NoiseDHState *bob;   /* responder */
    uint8_t alice_sk[jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES];
    uint8_t alice_pk[jade_kem_mlkem_mlkem1024_amd64_avx2_PUBLICKEYBYTES];
    uint8_t bob_ct[jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES];
    uint8_t bob_ss[32];
    uint8_t ss_dh[32];
    uint8_t ss_expected[32];
    uint8_t k_mlkem[32];

    /* Set up DH states for Kyber1024 */
    compare(noise_dhstate_new_by_id(&alice, NOISE_DH_KYBER1024), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_id(&bob, NOISE_DH_KYBER1024), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(alice, NOISE_ROLE_INITIATOR), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(bob,   NOISE_ROLE_RESPONDER), NOISE_ERROR_NONE);

    /* Generate keypairs: alice normal, bob dependent on alice */
    compare(noise_dhstate_generate_keypair(alice), NOISE_ERROR_NONE);
    compare(noise_dhstate_generate_dependent_keypair(bob, alice), NOISE_ERROR_NONE);

    /* Extract keys */
    compare(noise_dhstate_get_keypair(alice,
                                      alice_sk, sizeof(alice_sk),
                                      alice_pk, sizeof(alice_pk)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_get_keypair(bob,
                                      bob_ss, sizeof(bob_ss),
                                      bob_ct, sizeof(bob_ct)),
            NOISE_ERROR_NONE);

    /* DH calculate (alice side) */
    compare(noise_dhstate_calculate(alice, bob, ss_dh, sizeof(ss_dh)), NOISE_ERROR_NONE);

    /* Manual: ML-KEM decapsulate then apply Kyber KDF to get expected shared secret */
    compare(jade_kem_mlkem_mlkem1024_amd64_avx2_dec(k_mlkem, bob_ct, alice_sk), 0);
    {
        uint8_t buf[64];
        memcpy(buf, k_mlkem, 32);
        sha3256(buf + 32, bob_ct, jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES);
        shake256(ss_expected, 32, buf, 64);
    }

    /* Compare results */
    compare_blocks(ss_dh, sizeof(ss_dh), ss_expected, sizeof(ss_expected));
    compare_blocks(bob_ss, sizeof(bob_ss), ss_expected, sizeof(ss_expected));

    /* Optional: generate a deterministic KAT using derand (coins all-zero) */
    if (getenv("KYBER_GEN_KAT")) {
        uint8_t coins_kp[jade_kem_mlkem_mlkem1024_amd64_avx2_KEYPAIRCOINBYTES] = {0};
        uint8_t coins_enc[jade_kem_mlkem_mlkem1024_amd64_avx2_ENCCOINBYTES] = {0};
        uint8_t pk[jade_kem_mlkem_mlkem1024_amd64_avx2_PUBLICKEYBYTES];
        uint8_t sk[jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES];
        uint8_t ct[jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES];
        uint8_t ss_mlkem[32];
        uint8_t ss_kat[32];
        jade_kem_mlkem_mlkem1024_amd64_avx2_keypair_derand(pk, sk, coins_kp);
        jade_kem_mlkem_mlkem1024_amd64_avx2_enc_derand(ct, ss_mlkem, pk, coins_enc);
        memcpy(ss_kat, ss_mlkem, sizeof(ss_kat));
        printf("KYBER_KAT_PK=0x");
        for (size_t i = 0; i < sizeof(pk); ++i) printf("%02x", pk[i]);
        printf("\nKYBER_KAT_CT=0x");
        for (size_t i = 0; i < sizeof(ct); ++i) printf("%02x", ct[i]);
        printf("\nKYBER_KAT_SS=0x");
        for (size_t i = 0; i < sizeof(ss_kat); ++i) printf("%02x", ss_kat[i]);
        printf("\n");
    }

    compare(noise_dhstate_free(alice), NOISE_ERROR_NONE);
    compare(noise_dhstate_free(bob), NOISE_ERROR_NONE);
}
