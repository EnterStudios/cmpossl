/*
 * TODO: Add Description
 *
 * Author:  $(git config --get user.name) ($(git config --get user.email))
 * Date:    $(date +%Y-%m-%d)
 *
 * ====================================================================
 * Copyright (c) $(date +%Y) The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/* ====================================================================
 * Copyright (c) 2017 Nokia.  All rights reserved.
 */

#define OPENSSL_UNIT_TEST

/* #include header for interface under test */
#include <openssl/cmp.h>
#include <crypto/cmp/cmp_int.h> /* needed for ASN.1 stuff */
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "testutil.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(OPENSSL_NO_UNIT_TEST)

/* Add test code as per
 * http://wiki.openssl.org/index.php/How_To_Write_Unit_Tests_For_OpenSSL#Style
 */

typedef struct test_fixture
{
    const char* test_case_name;
    CMP_CTX *cmp_ctx;
    int bodytype;
    int err_code;
} CMP_TEST_FIXTURE;

EVP_PKEY *newkey;

static CMP_TEST_FIXTURE set_up(const char* const test_case_name)
{
    CMP_TEST_FIXTURE fixture;
    int setup_ok = 1;
    memset(&fixture, 0, sizeof(fixture));
    fixture.test_case_name = test_case_name;

    /* Allocate memory owned by the fixture, exit on error */

    if (!TEST_ptr(fixture.cmp_ctx = CMP_CTX_create())
            /* || other initializations */) {
        setup_ok = 0;
        goto err;
    }

err:
    if (!setup_ok)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CMP_TEST_FIXTURE fixture)
{
    ERR_print_errors_fp(stderr);
    /* Free any memory owned by the fixture, etc. */
    CMP_CTX_delete(fixture.cmp_ctx);
}

static int execute(CMP_TEST_FIXTURE fixture)
{
    int good = 1;
    CMP_PKIMESSAGE *req = NULL;
    /* Execute the code under test, make assertions, format and print errors,
     * return zero on success and one on error */
    req = CMP_certreq_new(fixture.cmp_ctx,
                          fixture.bodytype,
                          fixture.err_code);
    if (!TEST_ptr(req))
        good = 0;

    if (!good)
    {
        printf("** %s failed **\n--------\n", fixture.test_case_name);
    }

    CMP_PKIMESSAGE_free(req); /* TODO: that's not in cmp.h */
    return good;
}

unsigned char ref_sec[] = {'1', '2', '3', '4'}; /* TODO hardcoded */

static int test_cmp_create_ir_with_msg_sig_alg_protection_plus_rsa_key()
{
    SETUP_TEST_FIXTURE(CMP_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture.bodytype = 0 /* TODO: replace with V_CMP_PKIBODY_IR */;
    fixture.err_code = CMP_R_ERROR_CREATING_IR;
    CMP_CTX_set0_newPkey(fixture.cmp_ctx, newkey);
    CMP_CTX_set1_referenceValue( fixture.cmp_ctx, ref_sec, 3); /* TODO hardcoded */
    CMP_CTX_set1_secretValue( fixture.cmp_ctx, ref_sec, 3); /* TODO hardcoded */
    EXECUTE_TEST(execute, tear_down);
}

#if 0
static int test_REPLACE_ME_WITH_A_MEANINGFUL_NAME()
{
    SETUP_TEST_FIXTURE(CMP_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    EXECUTE_TEST(execute, tear_down);
}
#endif

EVP_PKEY *gen_rsa() {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return NULL;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) /* TODO: hardcoded */
        return NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        return NULL;

    return pkey;
}

int main(int argc, char *argv[])
{
    int result = 0;

    /* needed?
    SSL_library_init();
    SSL_load_error_strings();
    */

    newkey = gen_rsa();

    ADD_TEST(test_cmp_create_ir_with_msg_sig_alg_protection_plus_rsa_key);

    result = run_tests(argv[0]);
    ERR_print_errors_fp(stderr);
    return finish_test(result);
}

#else /* OPENSSL_NO_UNIT_TEST*/

int main(int argc, char *argv[])
{
    return EXIT_SUCCESS;
}
#endif /* OPENSSL_NO_UNIT_TEST */
