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

#include "internal.h"
#include "crypto/kyber/api.h"
#include "crypto/kyber/params.h"
#include "crypto/kyber/symmetric.h"
#include <string.h>

#define MAX_OF(a, b) ((a) > (b) ? (a) : (b))

typedef struct NoiseKyberState_s
{
    struct NoiseDHState_s parent;
    /* for INITIATOR, this is the secret key.  for RESPONDER, this is the precomputed shared bytes */
    uint8_t kyber_priv[MAX_OF(pqcrystals_kyber1024_ref_SECRETKEYBYTES, pqcrystals_kyber1024_ref_BYTES)];
    /* for INITIATOR, this is the public key.  for RESPONDER, this is the CIPHERTEXT */
    uint8_t kyber_pub[MAX_OF(pqcrystals_kyber1024_ref_PUBLICKEYBYTES, pqcrystals_kyber1024_ref_CIPHERTEXTBYTES)];
} NoiseKyberState;

static int noise_kyber_generate_keypair
    (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    NoiseKyberState *os = (NoiseKyberState *)other;
    if (st->parent.role == NOISE_ROLE_RESPONDER) {
        /* Generating the keypair for Bob relative to Alice's parameters */
        if (!os || os->parent.key_type == NOISE_KEY_TYPE_NO_KEY)
            return NOISE_ERROR_INVALID_STATE;
        pqcrystals_kyber1024_ref_enc(
            st->kyber_pub,
            st->kyber_priv,
            os->kyber_pub);
    } else {
        /* Generate the keypair for Alice */
        pqcrystals_kyber1024_ref_keypair(
            st->kyber_pub,
            st->kyber_priv);
    }
    return NOISE_ERROR_NONE;
}

static int noise_kyber_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    /* Private key is a concatenation of [priv_key_bytes][pub_key_bytes][pub_key_sha256] */
    uint8_t hash_out[32];
    NoiseKyberState *st = (NoiseKyberState *)state;
    if (st->parent.private_key_len != KYBER_SECRETKEYBYTES)
        return NOISE_ERROR_INVALID_PRIVATE_KEY;
    /* Check that public key hash in private key is valid */
    hash_h(hash_out, 
           private_key + KYBER_INDCPA_SECRETKEYBYTES,
           KYBER_PUBLICKEYBYTES);
    if (!noise_is_equal(hash_out, private_key + KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES, sizeof(hash_out)))
        return NOISE_ERROR_INVALID_PRIVATE_KEY;
    memcpy(st->kyber_priv, private_key, KYBER_SECRETKEYBYTES);
    memcpy(st->kyber_pub, private_key + KYBER_INDCPA_SECRETKEYBYTES, KYBER_PUBLICKEYBYTES);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Ignore the public key and re-generate from the private key */
    return noise_kyber_set_keypair_private(state, private_key);
}

static int noise_kyber_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    return NOISE_ERROR_NOT_IMPLEMENTED;
}

static int noise_kyber_copy
    (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    return NOISE_ERROR_NOT_IMPLEMENTED;
}

static int noise_kyber_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    NoiseKyberState *priv_st = (NoiseKyberState *)private_key_state;
    NoiseKyberState *pub_st = (NoiseKyberState *)public_key_state;
    if (priv_st->parent.role == NOISE_ROLE_RESPONDER) {
        /* We already generated the shared secret for Bob when we
         * generated the "keypair" for him. */
        memcpy(shared_key, priv_st->kyber_priv, pqcrystals_kyber1024_ref_BYTES);
    } else {
        /* Generate the shared secret for Alice */
        pqcrystals_kyber1024_ref_dec(shared_key, pub_st->kyber_pub, priv_st->kyber_priv);
    }
    return NOISE_ERROR_NONE;
}

static void noise_kyber_change_role(NoiseDHState *state)
{
    /* Change the size of the keys based on the object's role */
    if (state->role == NOISE_ROLE_RESPONDER) {
        state->private_key_len = pqcrystals_kyber1024_ref_BYTES;
        state->public_key_len = pqcrystals_kyber1024_ref_CIPHERTEXTBYTES;
    } else {
        state->private_key_len = pqcrystals_kyber1024_ref_SECRETKEYBYTES;
        state->public_key_len = pqcrystals_kyber1024_ref_PUBLICKEYBYTES;
    }
}

NoiseDHState *noise_kyber_new(void)
{
    NoiseKyberState *state = noise_new(NoiseKyberState);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_KYBER;
    state->parent.ephemeral_only = 1;
    state->parent.nulls_allowed = 0;
    state->parent.private_key_len = pqcrystals_kyber1024_ref_SECRETKEYBYTES;
    state->parent.public_key_len = pqcrystals_kyber1024_ref_PUBLICKEYBYTES;
    state->parent.shared_key_len = pqcrystals_kyber1024_ref_BYTES;
    state->parent.private_key = state->kyber_priv;
    state->parent.public_key = state->kyber_pub;
    state->parent.generate_keypair = noise_kyber_generate_keypair;
    state->parent.set_keypair = noise_kyber_set_keypair;
    state->parent.set_keypair_private = noise_kyber_set_keypair_private;
    state->parent.validate_public_key = noise_kyber_validate_public_key;
    state->parent.copy = noise_kyber_copy;
    state->parent.calculate = noise_kyber_calculate;
    state->parent.change_role = noise_kyber_change_role;
    return &(state->parent);
}
