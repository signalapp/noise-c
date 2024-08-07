/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "test-helpers.h"

#define MAX_DH_KEY_LEN 2048

/* Check raw DH output against test vectors */
static void check_dh(int id, size_t private_key_len, size_t public_key_len,
                     size_t other_public_key_len, size_t shared_key_len,
                     const char *name, int is_null, int role,
                     const char *private_key, const char *public_key,
                     const char *other_public_key, const char *shared_key)
{
    int inverse_role =
        (role == NOISE_ROLE_INITIATOR) ? NOISE_ROLE_RESPONDER
                                       : NOISE_ROLE_INITIATOR;
    NoiseDHState *state1;
    NoiseDHState *state2;
    NoiseDHState *state3;
    static uint8_t priv_key[MAX_DH_KEY_LEN];
    static uint8_t pub_key[MAX_DH_KEY_LEN];
    static uint8_t other_pub_key[MAX_DH_KEY_LEN];
    static uint8_t share_key[MAX_DH_KEY_LEN];
    static uint8_t temp[MAX_DH_KEY_LEN];
    static uint8_t temp2[MAX_DH_KEY_LEN];

    /* Convert the test strings into binary data */
    compare(string_to_data(priv_key, sizeof(priv_key), private_key),
            private_key_len);
    compare(string_to_data(pub_key, sizeof(pub_key), public_key),
            public_key_len);
    compare(string_to_data(other_pub_key, sizeof(other_pub_key),
            other_public_key), other_public_key_len);
    compare(string_to_data(share_key, sizeof(share_key), shared_key),
            shared_key_len);

    /* Create the first DH object and check its properties */
    compare(noise_dhstate_new_by_id(&state1, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state1), id);
    compare(noise_dhstate_set_role(state1, role), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_private_key_length(state1), private_key_len);
    compare(noise_dhstate_get_public_key_length(state1), public_key_len);
    compare(noise_dhstate_get_shared_key_length(state1), shared_key_len);
    verify(!noise_dhstate_has_keypair(state1));
    verify(!noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    verify(private_key_len <= MAX_DH_KEY_LEN);
    verify(public_key_len <= MAX_DH_KEY_LEN);
    verify(shared_key_len <= MAX_DH_KEY_LEN);

    /* Create the second DH object */
    compare(noise_dhstate_new_by_id(&state2, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state2, inverse_role), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state2), id);
    if (public_key_len == other_public_key_len)
        compare(noise_dhstate_get_private_key_length(state2), private_key_len);
    compare(noise_dhstate_get_public_key_length(state2), other_public_key_len);
    compare(noise_dhstate_get_shared_key_length(state2), shared_key_len);
    verify(!noise_dhstate_has_keypair(state2));
    verify(!noise_dhstate_has_public_key(state2));
    verify(!noise_dhstate_is_null_public_key(state2));

    /* Set the keys on the DH objects */
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, other_public_key_len),
            NOISE_ERROR_NONE);
    verify(noise_dhstate_has_keypair(state1));
    verify(noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    verify(!noise_dhstate_has_keypair(state2));
    verify(noise_dhstate_has_public_key(state2));
    compare(noise_dhstate_is_null_public_key(state2), is_null);

    /* Calculate the shared key and check against the test data */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, share_key, shared_key_len));

    /* Fetch the keys back from the objects and compare */
    memset(temp, 0xAA, sizeof(temp));
    memset(temp2, 0x66, sizeof(temp2));
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, priv_key, private_key_len));
    verify(!memcmp(temp2, pub_key, public_key_len));
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_get_public_key(state2, temp, other_public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, other_pub_key, other_public_key_len));

    /* Check parameter error conditions */
    compare(noise_dhstate_set_keypair
                (0, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_keypair
                (state1, 0, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len - 1, pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len + 1, pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (0, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_keypair
                (state1, 0, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len - 1, temp2, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len + 1, temp2, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_public_key
                (0, other_pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_public_key
                (state2, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_public_key(0, temp, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_public_key(state2, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_public_key(state2, temp, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_public_key(state2, temp, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate(0, state2, temp, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate(state1, 0, temp, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate(state1, state2, 0, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate(state2, state1, temp, shared_key_len),
            NOISE_ERROR_INVALID_PRIVATE_KEY);

    /* Cannot mix algorithm types */
    if (id == NOISE_DH_CURVE25519) {
        compare(noise_dhstate_new_by_id(&state3, NOISE_DH_CURVE448),
                NOISE_ERROR_NONE);
    } else {
        compare(noise_dhstate_new_by_id(&state3, NOISE_DH_CURVE25519),
                NOISE_ERROR_NONE);
    }
    compare(noise_dhstate_calculate(state1, state3, temp, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_free(state3), NOISE_ERROR_NONE);

    /* Re-create the objects by name and check their properties again */
    compare(noise_dhstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_dhstate_free(state2), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_name(&state1, name), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_name(&state2, name), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state1, role), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state2, inverse_role), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state1), id);
    compare(noise_dhstate_get_dh_id(state2), id);
    compare(noise_dhstate_get_private_key_length(state1), private_key_len);
    compare(noise_dhstate_get_public_key_length(state1), public_key_len);
    compare(noise_dhstate_get_shared_key_length(state1), shared_key_len);
    if (public_key_len == other_public_key_len)
        compare(noise_dhstate_get_private_key_length(state2), private_key_len);
    compare(noise_dhstate_get_public_key_length(state2), other_public_key_len);
    compare(noise_dhstate_get_shared_key_length(state2), shared_key_len);
    verify(!noise_dhstate_has_keypair(state1));
    verify(!noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    verify(!noise_dhstate_has_keypair(state2));
    verify(!noise_dhstate_has_public_key(state2));
    verify(!noise_dhstate_is_null_public_key(state2));

    /* Make sure that it is still the same object by checking DH outputs.
       This time we derive state1's public key from the private key rather
       than use the value from the test data. */
    compare(noise_dhstate_set_keypair_private
                (state1, priv_key, private_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, other_public_key_len),
            NOISE_ERROR_NONE);
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, share_key, shared_key_len));

    /* Deliberately null the other public key and check for a null result */
    if (id == NOISE_DH_CURVE25519 || id == NOISE_DH_CURVE448) {
        compare(noise_dhstate_set_null_public_key(state2), NOISE_ERROR_NONE);
        verify(noise_dhstate_is_null_public_key(state2));
        verify(noise_dhstate_has_public_key(state2));
        memset(temp, 0xAA, sizeof(temp));
        compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len),
                NOISE_ERROR_NONE);
        memset(temp2, 0, sizeof(temp));
        verify(!memcmp(temp, temp2, shared_key_len));
    }

    /* Clear the first key and check that it returns to default properties */
    compare(noise_dhstate_clear_key(state1), NOISE_ERROR_NONE);
    verify(!noise_dhstate_has_keypair(state1));
    verify(!noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_dhstate_get_public_key(state1, temp, public_key_len),
            NOISE_ERROR_NONE);

    /* Deliberately mess up the first keypair and perform validation.
       The existing Curve25519 and Curve448 back ends validate the
       public key but all private key values are valid. */
    if (id == NOISE_DH_CURVE25519 || id == NOISE_DH_CURVE448) {
        priv_key[private_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_INVALID_PUBLIC_KEY);
        priv_key[private_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_NONE);
        pub_key[public_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_INVALID_PUBLIC_KEY);
        pub_key[public_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_NONE);
    }

    /* Clean up */
    compare(noise_dhstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_dhstate_free(state2), NOISE_ERROR_NONE);
}

/* Check against test vectors from the various specifications
   to validate that the algorithms work as low level primitives */
static void dhstate_check_test_vectors(void)
{
    /* Curve25519 - From section 6.1 of RFC 7748 */
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, 32, "25519", 0, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         /* Alice's public key */
         "0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         /* Bob's public key */
         "0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
         /* Shared secret */
         "0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, 32, "25519", 0, NOISE_ROLE_RESPONDER,
         /* Bob's private key */
         "0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
         /* Bob's public key */
         "0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
         /* Alice's public key */
         "0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         /* Shared secret */
         "0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    /* Curve25519 - Check the behaviour of null public keys */
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, 32, "25519", 1, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         /* Alice's public key */
         "0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         /* Null public key */
         "0x0000000000000000000000000000000000000000000000000000000000000000",
         /* Shared secret - also null */
         "0x0000000000000000000000000000000000000000000000000000000000000000");

    /* Curve448 - From section 6.2 of RFC 7748 */
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, 56, "448", 0, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
           "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
         /* Alices's public key */
         "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
           "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
         /* Bob's public key */
         "0x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
           "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
         /* Shared secret */
         "0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
           "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, 56, "448", 0, NOISE_ROLE_RESPONDER,
         /* Bob's private key */
         "0x1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
           "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
         /* Bob's public key */
         "0x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
           "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
         /* Alices's public key */
         "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
           "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
         /* Shared secret */
         "0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
           "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    /* Curve448 - Check the behaviour of null public keys */
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, 56, "448", 1, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
           "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
         /* Alices's public key */
         "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
           "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
         /* Null public key */
         "0x00000000000000000000000000000000000000000000000000000000"
           "00000000000000000000000000000000000000000000000000000000",
         /* Shared secret - also null */
         "0x00000000000000000000000000000000000000000000000000000000"
           "00000000000000000000000000000000000000000000000000000000");

    /* KYBER1024 - Test vectors from the reference implementation of "torref" */
    check_dh
        (NOISE_DH_KYBER1024, 64, 1824, 2048, 32, "Kyber1024",
         0, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x891865aef10cb22387cae735180b85d14c436f931790804047f7363715b2c1c4"
           "30d39667f765af885a7ca5aa79dc54cdfcbac3b7aa5b55868b79d69498f858a7"
           "3476a605877a1449f58ccc25107367ab3e335202a59a7a40d7a24a107d099a19"
           "80c3164150b3b7c5339a745f3ab31bdd9c7d23a38592287bdd113864a41bd728"
           "45ca192189fca702545c28f7a7cc670f81c9be5584325074238380c469055b6e"
           "3c42e8288e93830a8b1c29ce858dd8a0a155a1504df4a82d893be8646c232134"
           "4638900d2916eea42f4c35ab16e77bca81a5e2f8086e5a5685e8a839c0960ac0"
           "574ca43d79fbc367534a71cc7e5ab40b8eec306b82c784c8b2cc48068cc165ad"
           "4cc039d934f6b222cab4971177687d2075d66abd8ba0ab7fdc5caeebb9aeba1b"
           "50c5c6ecf7c5ba6c242b444ae8375acde408fe61617bf87c7359ca8513a2b8a3"
           "3b5447298b063fd8cb15cc0059cfd38679e53447100baed9a5e41986bff15aa1"
           "1837214cb6b239bc74c190df138904d96f5f7305ff3cb0cbca9208f79163613e"
           "da4797ce8c5b2b257ab13c4aca24b367a6617136bee92ba57a22c45925909585"
           "3acd53ad6e739efa51312ce685a180b522e4ba54f847129ba97c171979b008c8"
           "02b0e1a33200e51081c18116a5213ed386d47c3414278957cc0e18d65b9ce866"
           "f34aacf800be7cfc7bee51314476881b49422f2c8cad276d24707b996ab4ffe6"
           "c50a4c2323e6563b602bd5631b5bbb4cb60311ec8564b715442e9470dc906c0e"
           "184e2cb66b5ebb4e9b9b5d726247f3a77b46844ab6b1ac88fb84a263c6944070"
           "31e223cba49b51a624612518c2106c7ebbab910a14a9b120dbbbbb1dcb705735"
           "b37b828e17d15da3d47cd7a5c3e6d40504a4b65bbc10a5699d11d29eebfc862f"
           "daaa5f71bec94170ed703717b40da37436f2cc5ecfd1905a824d09703092a0b6"
           "02c7cf480986dcab5e038729a7b3213cdac265306685455fa38bca3550739bf6"
           "8bac89989d087339e19c4b6446f8e96692396cab453ec1238ed8a796c9f234ed"
           "2a38a1e51dc0978dfa9c6099134b49197f4ec86b9863962e857f62c715b3898a"
           "2b996ca446772203a9c1e15bcb140d959a7cd60c9952742bd30872b22897e303"
           "7795da5ab2c2485f41ba8e2c2b0879509066ae4b509025fbaf9f92b5744729da"
           "57c40f195ca7bac0910c680de01ac5665d93b04404a5702f94431039a9cd7884"
           "a7ca74a76046a5430e6b4cc43964b40ce0260631572dc7c45cd58a2c9c6df806"
           "9d4d6c59ba418f76a9387e7712ecd65630f6c0ecb67893e06ddd68851c3c4939"
           "e3add0d2989b76b11032cb5aeb8d61195e55097bc82a4c26141869a5ceb8f380"
           "5468c1abd53bc9b198d9a528238a8e9f57811963ab56c40713396f09d917dce7"
           "8f88bb639dca488526a4cb9894b6a50e1bc38476d895af8c0733b16d851a2094"
           "53180fe318ba7371137688974c6a229179bdaba129f27ea999350f952e4eaa62"
           "e489cad6d969984842942338554a69f9e41659a6c87e5b284a8173e9700219ec"
           "298f812cb6e350b6d314a83017def1300ae57ada03af9f76534eb82d8f4abe9d"
           "10a23f2656aa73cab38497725c408ba0429aa85a374b449664288ebab79cb3cc"
           "4de15ddce0482b12127ed14106872c2ef93cece980f9ac2327f8c3aec7858e89"
           "c9957b5c15ccad712904198440faab535cdb2bb85640a69bb0467c77e8575bde"
           "418db3a1364b7b41b6d67dbc61274cd47a4b00c74b347e874a76b58256211648"
           "072b44dd06225fd929f5863f3d3280e93787d37620c33350fe26596805b33e79"
           "3e6fa886f4925d0475089de91de7515afa2b0e40e592f0967d0f20bf244358a8"
           "57484c6855e1079ced6636080673f7219d5e59afa1055ed2e478b83201c59128"
           "4bcb1f5032566ebabad3bcce471ac40537a1a08cb43e3aaa7005ab392375a1f7"
           "70dde1923f071c88c33e06bc1349d3cefcc904b04b310c4ca51849a3105a99c7"
           "f90e89732136488aeff7b71ea1c019407eed3440c503be3fbb9bf587113d1104"
           "73c6aa3fc07a910b78971994d087a17abb8059477ba3c0b04bb30929d98be0d4"
           "3c08fb1615609c5a7b80a47ab8da97a139c1c72612b6dbd8ab215b718803beac"
           "4cc7865007f3983c590c68012c27d8230a6a279221c29e70b017b9a6be99e088"
           "e4b43dd6b402b61c32f0191d13b1b54c50b8dcc224482864d7c818f7a242a818"
           "1e3263bc4332501b2359dba9a84218862487a54b4a6afd4aa8ed866800e1af36"
           "d7b6d3498121740738c4cafb10ca54743f4be207dda52ea1c9b14a36819f5818"
           "915b746fdca9757a4b594769c876a530ec95fb568acef03f900499b0b2caaa01"
           "58be137e864c95461b3422e8cd0a888ca7d302cff86a64038fce2891bab669d2"
           "8104a8f6a1b864a18e037b3954b7561845c44a318e8736fe090df18a7db7db52"
           "8f245d09e901a57a40c93a0bb1772480b789a49825f7d47ee57c73b5f34c8019"
           "24eaeb60e82987e0b96f50694534982393d70baa6765cfb8c0e08117a212a7e8"
           "0c1416c4b17fd655cf6289e3c61292f20a2c829d9404c96a3411830b9f204c01"
           "02f206511877f46a8931dc015d0003fc78b1e655123ca014bdc4c392bbaf7d1c"
           "4e99e793f52228afe3c934f4c4c33636a560937ec0a265a696625281df607f0a"
           "4c0662d3777003502f474eb7e894caf4479feab418b1360471b96fdabe8cf45f"
           "3c59ce79992ef8ab1f4a8a1dc1e030baf9c0217142b7c93855d8341f4923cd27"
           "6693d3686fc4c96c4703ad604c3438582bfb036fd962b0f8a0f4d6223b0cb038"
           "3215e7db8c7582933933ad095119fbca1f35d03e82562a4e17204a455927060a"
           "efec2596c6ca487b3e3b94cc4d3b1584b79080555c879c69aec2a8caccb00ef0"
           "23aba886721201342a2be68b67c9312480441d9b71568e690e20728fb22749cc"
           "ca948679aa70d5acefe38a91e026f42508b449c719d57027fa42b623b2801469"
           "91900c854b725dc3b656c4b9e7a697bd5719115b7cbfd26821493505db5f9e40"
           "a44f2a38177c3bc4525bfe05606ec65b77294c16a18c939453c66141789a9db5"
           "515a2d230a34a1ad5e622a0c27cbca07c49f359e4f255fd7048a93e8cf120864"
           "d069664cc30be261b631a911436b491ef01986ea3bf8915f20ca526641cb44fa"
           "963169b2099b307f86131596024988946b014e12f67465897abe2504f2f8139a"
           "7b1c94bb5ffc7324701ca4a62bcfa342bafe536fc4022cbcb19a2b746fdd442c"
           "456b98a2776f0c409f94430d33a0bd9436381f4943bcc68c6ee08957c1b94c95"
           "4374e6b01b83af8b3b2be01847e5d04f742bbb30bccfb8528b58f97e5ab848ae"
           "683001660e69b4bca0602cbb43b3d5a288aa8b938c26670d31a79f704a14546b"
           "52fcbc8169a8fdd540660a3a56e36939a753d639247358adb6b4b7ebf0979648"
           "25b7ea8005680f2ae5820a6bcf60a615282b710736bae6bb55e748ad3fb73dd3"
           "aca03e0a68f6b713cfa61b2016ca8a4764af256eb9f876fe6a703fa164d6ec9a"
           "27c684fde5001d7594df7004591046b3caaf6548819b6038cdf378a033b87c8c"
           "1a45045713125d4e617f7c52b7dc270c7c552adb032ef63811713b066e33c2c1"
           "425b0214a1e3d8cf69b5c337d16b12d36460fc3ad14c2720f869ae4ba294f62c"
           "67e24740b89352a38a734cb535b58b6d94568d2c65a6d6623bb5c905513f6220"
           "1d48cb60a946c97c865f96c9c4df39334523a1d15395a90195a3b57b34b1b7c1"
           "27944c2a2a39c2c067a714ac13cb768a68b4ab6a973469f0a442d7e07a702543"
           "29d801926927d7fbbcc888476862336ea2026d68aa348b4b6e3cb972d42cc098"
           "291479a4be24b233a7155fb9aa77353ebbc64f0e0aa0284acc51f5c926315e0b"
           "440079a7619bb4b2e80880d51c1c18cbccaea04de7c569bef53161e3c3b7310e"
           "9137530e410d40ca55a6a51f62e2214e622bd0255b71ab5944c50f92b6342ce7"
           "c2f6eb6c018770a9080e20546ea9812b7ce65c7aa5ae0aa65d2f9036a9e45c7d"
           "da0dc32b311365bacf489d9e708802b1626c392f9aa00cb6d5a237f3bca3908c"
           "0c853993e94a558a0551a375555153d34430b4f5a16ed4482d950630ca3fea06"
           "1ca0e5836d1812700bca26d36d920a3c49d946cbd8a1f2010a3e8b44e49b1428"
           "233a7a3a7e2c0964ec47cac2b6a527310fe3196145f0b700b1bcacd94b8afb9e"
           "1f3366acb783f37abdc898bf1a6b9ef48b6071e29ca9481c14830403964aa6f2"
           "aeb22342c0816d7e02257d41a88f790a1372719742acaf760d7b412904644d8b"
           "0b9c7ff33ae7aa0806a7454a38c81cb5319bf34690212b06e3b6f6ab7f05e01e"
           "ad56c35cab5063b9e7ea568314ec81c40ba577aae630de902004009e88f18da5"
           "102776aa21a3d0b97c61c50fb83ce3c4c46bc74e184a04355b466350823342ba"
           "0000000000000000000000000000000000000000000000000000000000000000",
         /* Alice's public key */
         "0xe4b43dd6b402b61c32f0191d13b1b54c50b8dcc224482864d7c818f7a242a818"
           "1e3263bc4332501b2359dba9a84218862487a54b4a6afd4aa8ed866800e1af36"
           "d7b6d3498121740738c4cafb10ca54743f4be207dda52ea1c9b14a36819f5818"
           "915b746fdca9757a4b594769c876a530ec95fb568acef03f900499b0b2caaa01"
           "58be137e864c95461b3422e8cd0a888ca7d302cff86a64038fce2891bab669d2"
           "8104a8f6a1b864a18e037b3954b7561845c44a318e8736fe090df18a7db7db52"
           "8f245d09e901a57a40c93a0bb1772480b789a49825f7d47ee57c73b5f34c8019"
           "24eaeb60e82987e0b96f50694534982393d70baa6765cfb8c0e08117a212a7e8"
           "0c1416c4b17fd655cf6289e3c61292f20a2c829d9404c96a3411830b9f204c01"
           "02f206511877f46a8931dc015d0003fc78b1e655123ca014bdc4c392bbaf7d1c"
           "4e99e793f52228afe3c934f4c4c33636a560937ec0a265a696625281df607f0a"
           "4c0662d3777003502f474eb7e894caf4479feab418b1360471b96fdabe8cf45f"
           "3c59ce79992ef8ab1f4a8a1dc1e030baf9c0217142b7c93855d8341f4923cd27"
           "6693d3686fc4c96c4703ad604c3438582bfb036fd962b0f8a0f4d6223b0cb038"
           "3215e7db8c7582933933ad095119fbca1f35d03e82562a4e17204a455927060a"
           "efec2596c6ca487b3e3b94cc4d3b1584b79080555c879c69aec2a8caccb00ef0"
           "23aba886721201342a2be68b67c9312480441d9b71568e690e20728fb22749cc"
           "ca948679aa70d5acefe38a91e026f42508b449c719d57027fa42b623b2801469"
           "91900c854b725dc3b656c4b9e7a697bd5719115b7cbfd26821493505db5f9e40"
           "a44f2a38177c3bc4525bfe05606ec65b77294c16a18c939453c66141789a9db5"
           "515a2d230a34a1ad5e622a0c27cbca07c49f359e4f255fd7048a93e8cf120864"
           "d069664cc30be261b631a911436b491ef01986ea3bf8915f20ca526641cb44fa"
           "963169b2099b307f86131596024988946b014e12f67465897abe2504f2f8139a"
           "7b1c94bb5ffc7324701ca4a62bcfa342bafe536fc4022cbcb19a2b746fdd442c"
           "456b98a2776f0c409f94430d33a0bd9436381f4943bcc68c6ee08957c1b94c95"
           "4374e6b01b83af8b3b2be01847e5d04f742bbb30bccfb8528b58f97e5ab848ae"
           "683001660e69b4bca0602cbb43b3d5a288aa8b938c26670d31a79f704a14546b"
           "52fcbc8169a8fdd540660a3a56e36939a753d639247358adb6b4b7ebf0979648"
           "25b7ea8005680f2ae5820a6bcf60a615282b710736bae6bb55e748ad3fb73dd3"
           "aca03e0a68f6b713cfa61b2016ca8a4764af256eb9f876fe6a703fa164d6ec9a"
           "27c684fde5001d7594df7004591046b3caaf6548819b6038cdf378a033b87c8c"
           "1a45045713125d4e617f7c52b7dc270c7c552adb032ef63811713b066e33c2c1"
           "425b0214a1e3d8cf69b5c337d16b12d36460fc3ad14c2720f869ae4ba294f62c"
           "67e24740b89352a38a734cb535b58b6d94568d2c65a6d6623bb5c905513f6220"
           "1d48cb60a946c97c865f96c9c4df39334523a1d15395a90195a3b57b34b1b7c1"
           "27944c2a2a39c2c067a714ac13cb768a68b4ab6a973469f0a442d7e07a702543"
           "29d801926927d7fbbcc888476862336ea2026d68aa348b4b6e3cb972d42cc098"
           "291479a4be24b233a7155fb9aa77353ebbc64f0e0aa0284acc51f5c926315e0b"
           "440079a7619bb4b2e80880d51c1c18cbccaea04de7c569bef53161e3c3b7310e"
           "9137530e410d40ca55a6a51f62e2214e622bd0255b71ab5944c50f92b6342ce7"
           "c2f6eb6c018770a9080e20546ea9812b7ce65c7aa5ae0aa65d2f9036a9e45c7d"
           "da0dc32b311365bacf489d9e708802b1626c392f9aa00cb6d5a237f3bca3908c"
           "0c853993e94a558a0551a375555153d34430b4f5a16ed4482d950630ca3fea06"
           "1ca0e5836d1812700bca26d36d920a3c49d946cbd8a1f2010a3e8b44e49b1428"
           "233a7a3a7e2c0964ec47cac2b6a527310fe3196145f0b700b1bcacd94b8afb9e"
           "1f3366acb783f37abdc898bf1a6b9ef48b6071e29ca9481c14830403964aa6f2"
           "aeb22342c0816d7e02257d41a88f790a1372719742acaf760d7b412904644d8b"
           "0b9c7ff33ae7aa0806a7454a38c81cb5319bf34690212b06e3b6f6ab7f05e01e"
           "ad56c35cab5063b9e7ea568314ec81c40ba577aae630de902004009e88f18da5",
         /* Bob's public key */
         "0x757479c28d4e754a8f5042dcfbf82ae14f36acebc297f107c54c6a980d42256b"
           "9b88b202077163ea129d3d0b3921f0f9cf04e4a94da22d96d7002a67db833e8a"
           "0e550302128348b6968c1bc09eb797cd71aea4d2bc4e6667fbce16336ad90e43"
           "1ea717982ba6c1e97d1fc41a12405b070e4ab5e8143665f12d2bb8ec616c9b02"
           "5e00d57254c2608c608841a755b76f5ca8277efd9a56c4da0f9b6e48fb686f7f"
           "4fd82268988d9fc2d2b59f5aab0f4e8ffe3d1b4e5461d6e156131225fcdf2fd8"
           "d2ec25c797daed9bf19a5b4d9d4079f52041b7fc7ad5100475aeeccc3aa241ac"
           "6b75911728edd25ffb11dd30067cdf836392347fd41c0a386d59185f8cf0ca2e"
           "082c9480993d8911546b04a6d468736f760582b7a10d5090a3a46764c14bc5e4"
           "cedab296b9b92bc4c0d24953eb0037450a58316cdffa7f4951341b08225672f9"
           "197fa51bd4735cd8ee2ff399229716ecd72d4e50ce71e14e98609c5b5402d580"
           "2cb7a21acac9421095852a53f1154332ae3793f1d1889ed542a16d3e87ed36b7"
           "66c164c0a708ea9d3a562fc6911ef303501a171d546ad28a0f89aede9fe2ad7f"
           "261167072b90fc6d060aa1a44172aad8ce7f84435ca16d23e29a32740d8c3685"
           "dd33f7a71c5d6711ec5673c093d8812a51f5a3df937404d3b0c62ed1e8ecdcfb"
           "91db4e2483bc13142380da5ac22a43fd6054163ff731f6974ffb3e9d8e620d8f"
           "b65a190b79ebea8fbd9d407b88c913d39318c6403f00cfb09dbd564574584fd7"
           "25bad79ab224751204bf75d04281fd2faa080616a70331d99ebe2a250d85def3"
           "f5d82791a132da9818ae6a0a459d9e55e058dc6d4d51cec4faba64c95f43a5cf"
           "f98c5ea8e6c10c8d00948759dfdfb469458aa6b1ef8587ba2920e46bbea6a8e2"
           "7bb8abce6e7c1fc5e1642e47c03410c9982c87efdfb340cbb3ea12de262dcb7f"
           "fc158aa533a001ab84c769b866cb717647e7459ab29618284772c7da4acd11e3"
           "7ac1ed9a88f75b689621c80af91074819daeed0617325d71f2d270242a806543"
           "2db8fcd4dd28a8d4e6c8586d78a15ec091c3951651760f3d0d031542bf5957d4"
           "a617f1a91dc1fbeac7aac0982a971e167a2a51e255422cc9493b8e67b5769a21"
           "5350284811f54c24a59dc2b1b8a786ba00856c6a7ab661c73901d33535f0c529"
           "f2905e15c360ba9b8411698eb842a9051106baa854b10df9799d00db3208a9c4"
           "14735a5e18b4dfaad1919783d4ae8ea980a68a7387e974cb09aa42b8842acc13"
           "7969ef3f42f2a0193e512f4d6eb9e3c1b3c839385d62b129d90137cb15bd84ae"
           "9fe250a76d8b09147ffe7ca9b500a4e3ee150a377ab322f55c3d5873b4622aa3"
           "a6c5f3f5fc090d659bf3df28389afd2cb486427a5b367815514c0a78535051ff"
           "e67371f57e4d2bef477ffc9c6484574c289fc6b5678661d3bbb3770edf67dde7"
           "d0d620cfb7247d62dad1965557197975c6e618cc6050fa0a340b268ef0aae000"
           "84c3882ae670504299b6a9a5ea651aa2abb508944f48be76bfe30c48a622cb7f"
           "8ee604d1c124853255897524fbf4e9c76c5730634f139cc98dfe9f391fd527ad"
           "9d68ee66b71b3ecb076bbd41f82bb5805cbc8265d038d967c1085ee74b137a38"
           "6ea7197da40f979023fa566858318779c553085c64b8aaf2147572a248d0bf52"
           "31041d3529d756a716ddf099b2b78786087d8a9aabbdf07d9eac4967c3b91d5d"
           "9dcf2f91296c0ae96759eb651121e611134fa4e49bab4b9feaab5ea8ea25954e"
           "7909c2b675bba8773dcbd3f68fc5902bd995a2c76d162f1bf0f914c6cc266eca"
           "c46767acfcd09676f3721dcb57b4ff5344d4b50494e9c8830d2e51b88328dec1"
           "d165e5a8a39993aa9e3e7ac4b74e7e37a8a56567e308bf5535c18be4371ac6fe"
           "9bf78a9651e4f4a8fa37e3313833127ff8fa3669ff0ea8785d65ed3c37086d3f"
           "c9c64e4f44d85bd730131e27ee99c1ad0867bfc45e5288ffe374470388cf87d8"
           "717733329ad7f14f00f75ccc3b5a6a2612286619aa94d68f5976bc6eff447e5d"
           "9d2cee6bcca8bdc51bb9024d76191313dd810c11f1e8a6a18426cbc7a6f54cc4"
           "32eddd94d8ba87de0648fe1824f05aa889343a50c7f3c09e68a1ca50c85f23ee"
           "dd04768568b44f6705f4d9a1d18064b8f6d1c0313fe3ef789093294fd4b7784e"
           "5423472959a4a0b31c2158d106c0d3d195c020d0c6936dcca09133d86b30afc7",
         /* Shared secret */
         "0xd21f12340f877656fbb2733d0c73cab35a689313892a28d539a43442d7c40a83");
    check_dh
        (NOISE_DH_KYBER1024, 32, 2048, 1824, 32, "Kyber1024",
         0, NOISE_ROLE_RESPONDER,
         "0x891865aef10cb22387cae735180b85d14c436f931790804047f7363715b2c1c4"
           "30d39667f765af885a7ca5aa79dc54cdfcbac3b7aa5b55868b79d69498f858a7"
           "3476a605877a1449f58ccc25107367ab3e335202a59a7a40d7a24a107d099a19"
           "80c3164150b3b7c5339a745f3ab31bdd9c7d23a38592287bdd113864a41bd728"
           "45ca192189fca702545c28f7a7cc670f81c9be5584325074238380c469055b6e"
           "3c42e8288e93830a8b1c29ce858dd8a0a155a1504df4a82d893be8646c232134"
           "4638900d2916eea42f4c35ab16e77bca81a5e2f8086e5a5685e8a839c0960ac0"
           "574ca43d79fbc367534a71cc7e5ab40b8eec306b82c784c8b2cc48068cc165ad"
           "4cc039d934f6b222cab4971177687d2075d66abd8ba0ab7fdc5caeebb9aeba1b"
           "50c5c6ecf7c5ba6c242b444ae8375acde408fe61617bf87c7359ca8513a2b8a3"
           "3b5447298b063fd8cb15cc0059cfd38679e53447100baed9a5e41986bff15aa1"
           "1837214cb6b239bc74c190df138904d96f5f7305ff3cb0cbca9208f79163613e"
           "da4797ce8c5b2b257ab13c4aca24b367a6617136bee92ba57a22c45925909585"
           "3acd53ad6e739efa51312ce685a180b522e4ba54f847129ba97c171979b008c8"
           "02b0e1a33200e51081c18116a5213ed386d47c3414278957cc0e18d65b9ce866"
           "f34aacf800be7cfc7bee51314476881b49422f2c8cad276d24707b996ab4ffe6"
           "c50a4c2323e6563b602bd5631b5bbb4cb60311ec8564b715442e9470dc906c0e"
           "184e2cb66b5ebb4e9b9b5d726247f3a77b46844ab6b1ac88fb84a263c6944070"
           "31e223cba49b51a624612518c2106c7ebbab910a14a9b120dbbbbb1dcb705735"
           "b37b828e17d15da3d47cd7a5c3e6d40504a4b65bbc10a5699d11d29eebfc862f"
           "daaa5f71bec94170ed703717b40da37436f2cc5ecfd1905a824d09703092a0b6"
           "02c7cf480986dcab5e038729a7b3213cdac265306685455fa38bca3550739bf6"
           "8bac89989d087339e19c4b6446f8e96692396cab453ec1238ed8a796c9f234ed"
           "2a38a1e51dc0978dfa9c6099134b49197f4ec86b9863962e857f62c715b3898a"
           "2b996ca446772203a9c1e15bcb140d959a7cd60c9952742bd30872b22897e303"
           "7795da5ab2c2485f41ba8e2c2b0879509066ae4b509025fbaf9f92b5744729da"
           "57c40f195ca7bac0910c680de01ac5665d93b04404a5702f94431039a9cd7884"
           "a7ca74a76046a5430e6b4cc43964b40ce0260631572dc7c45cd58a2c9c6df806"
           "9d4d6c59ba418f76a9387e7712ecd65630f6c0ecb67893e06ddd68851c3c4939"
           "e3add0d2989b76b11032cb5aeb8d61195e55097bc82a4c26141869a5ceb8f380"
           "5468c1abd53bc9b198d9a528238a8e9f57811963ab56c40713396f09d917dce7"
           "8f88bb639dca488526a4cb9894b6a50e1bc38476d895af8c0733b16d851a2094"
           "53180fe318ba7371137688974c6a229179bdaba129f27ea999350f952e4eaa62"
           "e489cad6d969984842942338554a69f9e41659a6c87e5b284a8173e9700219ec"
           "298f812cb6e350b6d314a83017def1300ae57ada03af9f76534eb82d8f4abe9d"
           "10a23f2656aa73cab38497725c408ba0429aa85a374b449664288ebab79cb3cc"
           "4de15ddce0482b12127ed14106872c2ef93cece980f9ac2327f8c3aec7858e89"
           "c9957b5c15ccad712904198440faab535cdb2bb85640a69bb0467c77e8575bde"
           "418db3a1364b7b41b6d67dbc61274cd47a4b00c74b347e874a76b58256211648"
           "072b44dd06225fd929f5863f3d3280e93787d37620c33350fe26596805b33e79"
           "3e6fa886f4925d0475089de91de7515afa2b0e40e592f0967d0f20bf244358a8"
           "57484c6855e1079ced6636080673f7219d5e59afa1055ed2e478b83201c59128"
           "4bcb1f5032566ebabad3bcce471ac40537a1a08cb43e3aaa7005ab392375a1f7"
           "70dde1923f071c88c33e06bc1349d3cefcc904b04b310c4ca51849a3105a99c7"
           "f90e89732136488aeff7b71ea1c019407eed3440c503be3fbb9bf587113d1104"
           "73c6aa3fc07a910b78971994d087a17abb8059477ba3c0b04bb30929d98be0d4"
           "3c08fb1615609c5a7b80a47ab8da97a139c1c72612b6dbd8ab215b718803beac"
           "4cc7865007f3983c590c68012c27d8230a6a279221c29e70b017b9a6be99e088"
           "e4b43dd6b402b61c32f0191d13b1b54c50b8dcc224482864d7c818f7a242a818"
           "1e3263bc4332501b2359dba9a84218862487a54b4a6afd4aa8ed866800e1af36"
           "d7b6d3498121740738c4cafb10ca54743f4be207dda52ea1c9b14a36819f5818"
           "915b746fdca9757a4b594769c876a530ec95fb568acef03f900499b0b2caaa01"
           "58be137e864c95461b3422e8cd0a888ca7d302cff86a64038fce2891bab669d2"
           "8104a8f6a1b864a18e037b3954b7561845c44a318e8736fe090df18a7db7db52"
           "8f245d09e901a57a40c93a0bb1772480b789a49825f7d47ee57c73b5f34c8019"
           "24eaeb60e82987e0b96f50694534982393d70baa6765cfb8c0e08117a212a7e8"
           "0c1416c4b17fd655cf6289e3c61292f20a2c829d9404c96a3411830b9f204c01"
           "02f206511877f46a8931dc015d0003fc78b1e655123ca014bdc4c392bbaf7d1c"
           "4e99e793f52228afe3c934f4c4c33636a560937ec0a265a696625281df607f0a"
           "4c0662d3777003502f474eb7e894caf4479feab418b1360471b96fdabe8cf45f"
           "3c59ce79992ef8ab1f4a8a1dc1e030baf9c0217142b7c93855d8341f4923cd27"
           "6693d3686fc4c96c4703ad604c3438582bfb036fd962b0f8a0f4d6223b0cb038"
           "3215e7db8c7582933933ad095119fbca1f35d03e82562a4e17204a455927060a"
           "efec2596c6ca487b3e3b94cc4d3b1584b79080555c879c69aec2a8caccb00ef0"
           "23aba886721201342a2be68b67c9312480441d9b71568e690e20728fb22749cc"
           "ca948679aa70d5acefe38a91e026f42508b449c719d57027fa42b623b2801469"
           "91900c854b725dc3b656c4b9e7a697bd5719115b7cbfd26821493505db5f9e40"
           "a44f2a38177c3bc4525bfe05606ec65b77294c16a18c939453c66141789a9db5"
           "515a2d230a34a1ad5e622a0c27cbca07c49f359e4f255fd7048a93e8cf120864"
           "d069664cc30be261b631a911436b491ef01986ea3bf8915f20ca526641cb44fa"
           "963169b2099b307f86131596024988946b014e12f67465897abe2504f2f8139a"
           "7b1c94bb5ffc7324701ca4a62bcfa342bafe536fc4022cbcb19a2b746fdd442c"
           "456b98a2776f0c409f94430d33a0bd9436381f4943bcc68c6ee08957c1b94c95"
           "4374e6b01b83af8b3b2be01847e5d04f742bbb30bccfb8528b58f97e5ab848ae"
           "683001660e69b4bca0602cbb43b3d5a288aa8b938c26670d31a79f704a14546b"
           "52fcbc8169a8fdd540660a3a56e36939a753d639247358adb6b4b7ebf0979648"
           "25b7ea8005680f2ae5820a6bcf60a615282b710736bae6bb55e748ad3fb73dd3"
           "aca03e0a68f6b713cfa61b2016ca8a4764af256eb9f876fe6a703fa164d6ec9a"
           "27c684fde5001d7594df7004591046b3caaf6548819b6038cdf378a033b87c8c"
           "1a45045713125d4e617f7c52b7dc270c7c552adb032ef63811713b066e33c2c1"
           "425b0214a1e3d8cf69b5c337d16b12d36460fc3ad14c2720f869ae4ba294f62c"
           "67e24740b89352a38a734cb535b58b6d94568d2c65a6d6623bb5c905513f6220"
           "1d48cb60a946c97c865f96c9c4df39334523a1d15395a90195a3b57b34b1b7c1"
           "27944c2a2a39c2c067a714ac13cb768a68b4ab6a973469f0a442d7e07a702543"
           "29d801926927d7fbbcc888476862336ea2026d68aa348b4b6e3cb972d42cc098"
           "291479a4be24b233a7155fb9aa77353ebbc64f0e0aa0284acc51f5c926315e0b"
           "440079a7619bb4b2e80880d51c1c18cbccaea04de7c569bef53161e3c3b7310e"
           "9137530e410d40ca55a6a51f62e2214e622bd0255b71ab5944c50f92b6342ce7"
           "c2f6eb6c018770a9080e20546ea9812b7ce65c7aa5ae0aa65d2f9036a9e45c7d"
           "da0dc32b311365bacf489d9e708802b1626c392f9aa00cb6d5a237f3bca3908c"
           "0c853993e94a558a0551a375555153d34430b4f5a16ed4482d950630ca3fea06"
           "1ca0e5836d1812700bca26d36d920a3c49d946cbd8a1f2010a3e8b44e49b1428"
           "233a7a3a7e2c0964ec47cac2b6a527310fe3196145f0b700b1bcacd94b8afb9e"
           "1f3366acb783f37abdc898bf1a6b9ef48b6071e29ca9481c14830403964aa6f2"
           "aeb22342c0816d7e02257d41a88f790a1372719742acaf760d7b412904644d8b"
           "0b9c7ff33ae7aa0806a7454a38c81cb5319bf34690212b06e3b6f6ab7f05e01e"
           "ad56c35cab5063b9e7ea568314ec81c40ba577aae630de902004009e88f18da5"
           "102776aa21a3d0b97c61c50fb83ce3c4c46bc74e184a04355b466350823342ba"
           "0000000000000000000000000000000000000000000000000000000000000000",
         /* Alice's public key */
         "0xe4b43dd6b402b61c32f0191d13b1b54c50b8dcc224482864d7c818f7a242a818"
           "1e3263bc4332501b2359dba9a84218862487a54b4a6afd4aa8ed866800e1af36"
           "d7b6d3498121740738c4cafb10ca54743f4be207dda52ea1c9b14a36819f5818"
           "915b746fdca9757a4b594769c876a530ec95fb568acef03f900499b0b2caaa01"
           "58be137e864c95461b3422e8cd0a888ca7d302cff86a64038fce2891bab669d2"
           "8104a8f6a1b864a18e037b3954b7561845c44a318e8736fe090df18a7db7db52"
           "8f245d09e901a57a40c93a0bb1772480b789a49825f7d47ee57c73b5f34c8019"
           "24eaeb60e82987e0b96f50694534982393d70baa6765cfb8c0e08117a212a7e8"
           "0c1416c4b17fd655cf6289e3c61292f20a2c829d9404c96a3411830b9f204c01"
           "02f206511877f46a8931dc015d0003fc78b1e655123ca014bdc4c392bbaf7d1c"
           "4e99e793f52228afe3c934f4c4c33636a560937ec0a265a696625281df607f0a"
           "4c0662d3777003502f474eb7e894caf4479feab418b1360471b96fdabe8cf45f"
           "3c59ce79992ef8ab1f4a8a1dc1e030baf9c0217142b7c93855d8341f4923cd27"
           "6693d3686fc4c96c4703ad604c3438582bfb036fd962b0f8a0f4d6223b0cb038"
           "3215e7db8c7582933933ad095119fbca1f35d03e82562a4e17204a455927060a"
           "efec2596c6ca487b3e3b94cc4d3b1584b79080555c879c69aec2a8caccb00ef0"
           "23aba886721201342a2be68b67c9312480441d9b71568e690e20728fb22749cc"
           "ca948679aa70d5acefe38a91e026f42508b449c719d57027fa42b623b2801469"
           "91900c854b725dc3b656c4b9e7a697bd5719115b7cbfd26821493505db5f9e40"
           "a44f2a38177c3bc4525bfe05606ec65b77294c16a18c939453c66141789a9db5"
           "515a2d230a34a1ad5e622a0c27cbca07c49f359e4f255fd7048a93e8cf120864"
           "d069664cc30be261b631a911436b491ef01986ea3bf8915f20ca526641cb44fa"
           "963169b2099b307f86131596024988946b014e12f67465897abe2504f2f8139a"
           "7b1c94bb5ffc7324701ca4a62bcfa342bafe536fc4022cbcb19a2b746fdd442c"
           "456b98a2776f0c409f94430d33a0bd9436381f4943bcc68c6ee08957c1b94c95"
           "4374e6b01b83af8b3b2be01847e5d04f742bbb30bccfb8528b58f97e5ab848ae"
           "683001660e69b4bca0602cbb43b3d5a288aa8b938c26670d31a79f704a14546b"
           "52fcbc8169a8fdd540660a3a56e36939a753d639247358adb6b4b7ebf0979648"
           "25b7ea8005680f2ae5820a6bcf60a615282b710736bae6bb55e748ad3fb73dd3"
           "aca03e0a68f6b713cfa61b2016ca8a4764af256eb9f876fe6a703fa164d6ec9a"
           "27c684fde5001d7594df7004591046b3caaf6548819b6038cdf378a033b87c8c"
           "1a45045713125d4e617f7c52b7dc270c7c552adb032ef63811713b066e33c2c1"
           "425b0214a1e3d8cf69b5c337d16b12d36460fc3ad14c2720f869ae4ba294f62c"
           "67e24740b89352a38a734cb535b58b6d94568d2c65a6d6623bb5c905513f6220"
           "1d48cb60a946c97c865f96c9c4df39334523a1d15395a90195a3b57b34b1b7c1"
           "27944c2a2a39c2c067a714ac13cb768a68b4ab6a973469f0a442d7e07a702543"
           "29d801926927d7fbbcc888476862336ea2026d68aa348b4b6e3cb972d42cc098"
           "291479a4be24b233a7155fb9aa77353ebbc64f0e0aa0284acc51f5c926315e0b"
           "440079a7619bb4b2e80880d51c1c18cbccaea04de7c569bef53161e3c3b7310e"
           "9137530e410d40ca55a6a51f62e2214e622bd0255b71ab5944c50f92b6342ce7"
           "c2f6eb6c018770a9080e20546ea9812b7ce65c7aa5ae0aa65d2f9036a9e45c7d"
           "da0dc32b311365bacf489d9e708802b1626c392f9aa00cb6d5a237f3bca3908c"
           "0c853993e94a558a0551a375555153d34430b4f5a16ed4482d950630ca3fea06"
           "1ca0e5836d1812700bca26d36d920a3c49d946cbd8a1f2010a3e8b44e49b1428"
           "233a7a3a7e2c0964ec47cac2b6a527310fe3196145f0b700b1bcacd94b8afb9e"
           "1f3366acb783f37abdc898bf1a6b9ef48b6071e29ca9481c14830403964aa6f2"
           "aeb22342c0816d7e02257d41a88f790a1372719742acaf760d7b412904644d8b"
           "0b9c7ff33ae7aa0806a7454a38c81cb5319bf34690212b06e3b6f6ab7f05e01e"
           "ad56c35cab5063b9e7ea568314ec81c40ba577aae630de902004009e88f18da5",
         /* Bob's public key */
         "0x757479c28d4e754a8f5042dcfbf82ae14f36acebc297f107c54c6a980d42256b"
           "9b88b202077163ea129d3d0b3921f0f9cf04e4a94da22d96d7002a67db833e8a"
           "0e550302128348b6968c1bc09eb797cd71aea4d2bc4e6667fbce16336ad90e43"
           "1ea717982ba6c1e97d1fc41a12405b070e4ab5e8143665f12d2bb8ec616c9b02"
           "5e00d57254c2608c608841a755b76f5ca8277efd9a56c4da0f9b6e48fb686f7f"
           "4fd82268988d9fc2d2b59f5aab0f4e8ffe3d1b4e5461d6e156131225fcdf2fd8"
           "d2ec25c797daed9bf19a5b4d9d4079f52041b7fc7ad5100475aeeccc3aa241ac"
           "6b75911728edd25ffb11dd30067cdf836392347fd41c0a386d59185f8cf0ca2e"
           "082c9480993d8911546b04a6d468736f760582b7a10d5090a3a46764c14bc5e4"
           "cedab296b9b92bc4c0d24953eb0037450a58316cdffa7f4951341b08225672f9"
           "197fa51bd4735cd8ee2ff399229716ecd72d4e50ce71e14e98609c5b5402d580"
           "2cb7a21acac9421095852a53f1154332ae3793f1d1889ed542a16d3e87ed36b7"
           "66c164c0a708ea9d3a562fc6911ef303501a171d546ad28a0f89aede9fe2ad7f"
           "261167072b90fc6d060aa1a44172aad8ce7f84435ca16d23e29a32740d8c3685"
           "dd33f7a71c5d6711ec5673c093d8812a51f5a3df937404d3b0c62ed1e8ecdcfb"
           "91db4e2483bc13142380da5ac22a43fd6054163ff731f6974ffb3e9d8e620d8f"
           "b65a190b79ebea8fbd9d407b88c913d39318c6403f00cfb09dbd564574584fd7"
           "25bad79ab224751204bf75d04281fd2faa080616a70331d99ebe2a250d85def3"
           "f5d82791a132da9818ae6a0a459d9e55e058dc6d4d51cec4faba64c95f43a5cf"
           "f98c5ea8e6c10c8d00948759dfdfb469458aa6b1ef8587ba2920e46bbea6a8e2"
           "7bb8abce6e7c1fc5e1642e47c03410c9982c87efdfb340cbb3ea12de262dcb7f"
           "fc158aa533a001ab84c769b866cb717647e7459ab29618284772c7da4acd11e3"
           "7ac1ed9a88f75b689621c80af91074819daeed0617325d71f2d270242a806543"
           "2db8fcd4dd28a8d4e6c8586d78a15ec091c3951651760f3d0d031542bf5957d4"
           "a617f1a91dc1fbeac7aac0982a971e167a2a51e255422cc9493b8e67b5769a21"
           "5350284811f54c24a59dc2b1b8a786ba00856c6a7ab661c73901d33535f0c529"
           "f2905e15c360ba9b8411698eb842a9051106baa854b10df9799d00db3208a9c4"
           "14735a5e18b4dfaad1919783d4ae8ea980a68a7387e974cb09aa42b8842acc13"
           "7969ef3f42f2a0193e512f4d6eb9e3c1b3c839385d62b129d90137cb15bd84ae"
           "9fe250a76d8b09147ffe7ca9b500a4e3ee150a377ab322f55c3d5873b4622aa3"
           "a6c5f3f5fc090d659bf3df28389afd2cb486427a5b367815514c0a78535051ff"
           "e67371f57e4d2bef477ffc9c6484574c289fc6b5678661d3bbb3770edf67dde7"
           "d0d620cfb7247d62dad1965557197975c6e618cc6050fa0a340b268ef0aae000"
           "84c3882ae670504299b6a9a5ea651aa2abb508944f48be76bfe30c48a622cb7f"
           "8ee604d1c124853255897524fbf4e9c76c5730634f139cc98dfe9f391fd527ad"
           "9d68ee66b71b3ecb076bbd41f82bb5805cbc8265d038d967c1085ee74b137a38"
           "6ea7197da40f979023fa566858318779c553085c64b8aaf2147572a248d0bf52"
           "31041d3529d756a716ddf099b2b78786087d8a9aabbdf07d9eac4967c3b91d5d"
           "9dcf2f91296c0ae96759eb651121e611134fa4e49bab4b9feaab5ea8ea25954e"
           "7909c2b675bba8773dcbd3f68fc5902bd995a2c76d162f1bf0f914c6cc266eca"
           "c46767acfcd09676f3721dcb57b4ff5344d4b50494e9c8830d2e51b88328dec1"
           "d165e5a8a39993aa9e3e7ac4b74e7e37a8a56567e308bf5535c18be4371ac6fe"
           "9bf78a9651e4f4a8fa37e3313833127ff8fa3669ff0ea8785d65ed3c37086d3f"
           "c9c64e4f44d85bd730131e27ee99c1ad0867bfc45e5288ffe374470388cf87d8"
           "717733329ad7f14f00f75ccc3b5a6a2612286619aa94d68f5976bc6eff447e5d"
           "9d2cee6bcca8bdc51bb9024d76191313dd810c11f1e8a6a18426cbc7a6f54cc4"
           "32eddd94d8ba87de0648fe1824f05aa889343a50c7f3c09e68a1ca50c85f23ee"
           "dd04768568b44f6705f4d9a1d18064b8f6d1c0313fe3ef789093294fd4b7784e"
           "5423472959a4a0b31c2158d106c0d3d195c020d0c6936dcca09133d86b30afc7",
         /* Shared secret */
         "0xd21f12340f877656fbb2733d0c73cab35a689313892a28d539a43442d7c40a83");
}

/* Check the generation and use of new key pairs */
static void check_dh_generate(int id)
{
    NoiseDHState *state1;
    NoiseDHState *state2;
    uint8_t shared1[MAX_DH_KEY_LEN];
    uint8_t shared2[MAX_DH_KEY_LEN];
    size_t shared_key_len;

    /* Create the DH objects and get the properties */
    compare(noise_dhstate_new_by_id(&state1, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_id(&state2, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state1), id);
    compare(noise_dhstate_get_dh_id(state2), id);
    shared_key_len = noise_dhstate_get_shared_key_length(state1);
    verify(shared_key_len <= MAX_DH_KEY_LEN);

    /* Set the roles for the two DHState objects */
    compare(noise_dhstate_set_role(state1, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state2, NOISE_ROLE_RESPONDER),
            NOISE_ERROR_NONE);

    /* Generate keypairs for Alice and Bob */
    compare(noise_dhstate_generate_keypair(state1), NOISE_ERROR_NONE);
    if (id != NOISE_DH_KYBER1024) {
        verify(!noise_dhstate_is_ephemeral_only(state1));
        verify(!noise_dhstate_is_ephemeral_only(state2));
        compare(noise_dhstate_generate_keypair(state2), NOISE_ERROR_NONE);
    } else {
        /* Check the KYBER1024 parameters */
        verify(noise_dhstate_is_ephemeral_only(state1));
        verify(noise_dhstate_is_ephemeral_only(state2));
        compare(noise_dhstate_get_private_key_length(state1), 64);
        compare(noise_dhstate_get_public_key_length(state1), 1824);
        compare(noise_dhstate_get_private_key_length(state2), 32);
        compare(noise_dhstate_get_public_key_length(state2), 2048);

        /* KYBER1024 is "mutual" so Bob's object needs to know about Alice's
         * so that it will generate Bob's "keypair" with respect to the
         * parameters in Alice's public key. */
        compare(noise_dhstate_generate_dependent_keypair(state2, state1),
                NOISE_ERROR_NONE);
    }

    /* Calculate the shared key on both ends and compare */
    memset(shared1, 0xAA, sizeof(shared1));
    memset(shared2, 0x66, sizeof(shared2));
    compare(noise_dhstate_calculate(state1, state2, shared1, shared_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_calculate (state2, state1, shared2, shared_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(shared1, shared2, shared_key_len));

    /* Check parameter error conditions */
    compare(noise_dhstate_generate_keypair(0), NOISE_ERROR_INVALID_PARAM);

    /* Clean up */
    compare(noise_dhstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_dhstate_free(state2), NOISE_ERROR_NONE);
}

/* Check the generation and use of new key pairs */
static void dhstate_check_generate_keypair(void)
{
    check_dh_generate(NOISE_DH_CURVE25519);
    check_dh_generate(NOISE_DH_CURVE448);
    check_dh_generate(NOISE_DH_KYBER1024);
}

/* Check other error conditions that can be reported by the functions */
static void dhstate_check_errors(void)
{
    NoiseDHState *state;

    /* NULL parameters in various positions */
    compare(noise_dhstate_free(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_dh_id(0), NOISE_DH_NONE);
    compare(noise_dhstate_get_private_key_length(0), 0);
    compare(noise_dhstate_get_public_key_length(0), 0);
    compare(noise_dhstate_get_shared_key_length(0), 0);
    compare(noise_dhstate_has_keypair(0), 0);
    compare(noise_dhstate_has_public_key(0), 0);
    compare(noise_dhstate_new_by_id(0, NOISE_DH_CURVE25519),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_new_by_name(0, "25519"), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_generate_keypair(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_null_public_key(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_is_null_public_key(0), 0);

    /* If the id/name is unknown, the state parameter should be set to NULL */
    state = (NoiseDHState *)8;
    compare(noise_dhstate_new_by_id(&state, NOISE_HASH_SHA512),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseDHState *)8;
    compare(noise_dhstate_new_by_name(&state, 0),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseDHState *)8;
    compare(noise_dhstate_new_by_name(&state, "Curve25519"), /* Should be "25519" */
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
}

void test_dhstate(void)
{
    dhstate_check_test_vectors();
    dhstate_check_generate_keypair();
    dhstate_check_errors();
}
