/*
 * Copyright OpenSSL 2007-2018
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 *
 * SPDX-License-Identifier: OpenSSL
 *
 * CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.
 */

#include "cmptestlib.h"

#ifndef OPENSSL_NO_CMP

# include <crypto/cmp/cmp_int.h>

/* Add test code as per
 * http://wiki.openssl.org/index.php/How_To_Write_Unit_Tests_For_OpenSSL#Style
 */
typedef struct test_fixture {
    const char *test_case_name;
    CMP_CTX *cmp_ctx;
    /* for protection tests */
    CMP_PKIMESSAGE *msg;
    CMP_PKISTATUSINFO *si;      /* for error and response messages */
    ASN1_OCTET_STRING *secret;
    EVP_PKEY *privkey;
    EVP_PKEY *pubkey;
    unsigned char *mem;
    int memlen;
    int expected;
} CMP_INT_TEST_FIXTURE;

static CMP_INT_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_INT_TEST_FIXTURE *fixture;
    int setup_ok = 0;
    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        goto err;
    fixture->test_case_name = test_case_name;

    if (!TEST_ptr(fixture->cmp_ctx = CMP_CTX_create()))
        goto err;

    setup_ok = 1;
 err:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CMP_INT_TEST_FIXTURE *fixture)
{
    /* ERR_print_errors_fp(stderr);
       Free any memory owned by the fixture, etc. */
    CMP_CTX_delete(fixture->cmp_ctx);
    CMP_PKIMESSAGE_free(fixture->msg);
    ASN1_OCTET_STRING_free(fixture->secret);
    EVP_PKEY_free(fixture->privkey);
    EVP_PKEY_free(fixture->pubkey);
    CMP_PKISTATUSINFO_free(fixture->si);

    OPENSSL_free(fixture->mem);
    OPENSSL_free(fixture);
}

static EVP_PKEY *loadedprivkey = NULL;
static EVP_PKEY *loadedpubkey = NULL;

static int execute_calc_protection_fails_test(CMP_INT_TEST_FIXTURE *fixture)
{
    ASN1_BIT_STRING *protection = NULL;
    int res = TEST_ptr_null(protection =
                            CMP_calc_protection(fixture->msg, fixture->secret,
                                                fixture->privkey));
    ASN1_BIT_STRING_free(protection);
    return res;
}

/* TODO internal test*/
static int execute_calc_protection_test(CMP_INT_TEST_FIXTURE *fixture)
{
    ASN1_BIT_STRING *protection = NULL;
    int res =
        TEST_ptr(protection = CMP_calc_protection(fixture->msg, fixture->secret,
                                                  fixture->privkey)) &&
        TEST_true(ASN1_STRING_cmp(protection, fixture->msg->protection) == 0);
    ASN1_BIT_STRING_free(protection);
    return res;
}

static int execute_cmp_pkiheader_init_test(CMP_INT_TEST_FIXTURE *fixture)
{
    CMP_PKIHEADER *header = NULL;
    int res = 0;
    if (!TEST_ptr(header = CMP_PKIHEADER_new()))
        return 0;
    if (!TEST_int_eq(fixture->expected,
                     CMP_PKIHEADER_init(fixture->cmp_ctx, header)))
        goto err;
    if (fixture->expected) {
        if (!TEST_long_eq(ASN1_INTEGER_get(header->pvno), CMP_VERSION) ||
            !TEST_true(0 == ASN1_OCTET_STRING_cmp(header->senderNonce,
                                                  fixture->
                                                  cmp_ctx->last_senderNonce))
            || !TEST_true(0 ==
                          ASN1_OCTET_STRING_cmp(header->transactionID,
                                                fixture->cmp_ctx->transactionID)))
            goto err;
        if (fixture->cmp_ctx->recipNonce != NULL &&
            (!TEST_ptr(header->recipNonce) ||
             !TEST_int_eq(0,
                          ASN1_OCTET_STRING_cmp(header->recipNonce,
                                                fixture->cmp_ctx->recipNonce))))
            goto err;
    }

    res = 1;

 err:
    CMP_PKIHEADER_free(header);
    return res;
}

/* This function works similar to parts of CMP_verify_signature in cmp_vfy.c,
 * but without the need for a CMP_CTX or a X509 certificate */
static int verify_signature(CMP_PKIMESSAGE *msg, EVP_PKEY *pkey,
                            int digest_nid)
{
    ASN1_BIT_STRING *protection = msg->protection;
    CMP_PROTECTEDPART prot_part;
    unsigned char *prot_part_der = NULL;
    int l;
    EVP_MD_CTX *ctx = NULL;
    int res;

    prot_part.header = msg->header;
    prot_part.body = msg->body;
    res =
        TEST_int_ge(l = i2d_CMP_PROTECTEDPART(&prot_part, &prot_part_der), 0) &&
        TEST_ptr(ctx = EVP_MD_CTX_create()) &&
        TEST_true(EVP_VerifyInit_ex
                  (ctx, (EVP_MD *)EVP_get_digestbynid(digest_nid), NULL))
        && TEST_true(EVP_VerifyUpdate(ctx, prot_part_der, l))
        && TEST_int_eq(EVP_VerifyFinal(ctx, protection->data,
                                       protection->length, pkey), 1);
    /* cleanup */
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(prot_part_der);
    return res;
}

/* Calls CMP_calc_protection and verifies signature*/
static int execute_calc_protection_signature_test(CMP_INT_TEST_FIXTURE *
                                                  fixture)
{
    ASN1_BIT_STRING_free(fixture->msg->protection);
    fixture->msg->protection = NULL;
    return
        TEST_ptr(fixture->msg->protection =
                 CMP_calc_protection(fixture->msg, NULL, fixture->privkey)) &&
        TEST_true(verify_signature
                  (fixture->msg, fixture->pubkey, fixture->cmp_ctx->digest));
}

/* TODO TPa: find a way to set protection algorithm */
static int test_cmp_calc_protection_no_key_no_secret(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    if (!TEST_ptr(fixture->msg =
                  load_pkimsg("../cmp-test/CMP_IR_unprotected.der")) ||
        !TEST_ptr(fixture->msg->header->protectionAlg = X509_ALGOR_new())) {
        tear_down(fixture);
        fixture = NULL;
    }

    EXECUTE_TEST(execute_calc_protection_fails_test, tear_down);
    return result;
}

/* TODO TPa: find openssl-independent reference value */
static int test_cmp_calc_protection_pkey(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    fixture->pubkey = loadedpubkey;
    fixture->privkey = loadedprivkey;
    if (!TEST_true(EVP_PKEY_up_ref(loadedpubkey)) ||
        !TEST_true(EVP_PKEY_up_ref(loadedprivkey)) ||
        !TEST_ptr(fixture->msg =
                  load_pkimsg("../cmp-test/CMP_IR_protected.der"))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_calc_protection_signature_test, tear_down);
    return result;
}

static int test_cmp_calc_protection_pbmac(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    unsigned char sec_insta[] = { 'i', 'n', 's', 't', 'a' };

    if (!TEST_ptr(fixture->secret = ASN1_OCTET_STRING_new()) ||
        !TEST_true(ASN1_OCTET_STRING_set
                   (fixture->secret, sec_insta, sizeof(sec_insta))) ||
        !TEST_ptr(fixture->msg =
                  load_pkimsg("../cmp-test/CMP_IP_insta_PBM.der"))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_calc_protection_test, tear_down);
    return result;
}

static int test_cmp_pkiheader_init(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    unsigned char ref[TEST_CMP_REFVALUE_LENGTH];
    fixture->expected = 1;
    if (!TEST_int_eq(1, RAND_bytes(ref, sizeof(ref))) ||
        !TEST_true(CMP_CTX_set1_referenceValue(fixture->cmp_ctx, ref,
                                               sizeof(ref)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_cmp_pkiheader_init_test, tear_down);
    return result;
}

static int test_cmp_pkiheader_init_with_subject(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    X509_NAME *subject = NULL;
    fixture->expected = 1;
    if (!TEST_ptr(subject = X509_NAME_new()) ||
        !TEST_true(X509_NAME_add_entry_by_txt(subject, "CN", V_ASN1_IA5STRING,
                                              (unsigned char *)"Common Name", -1, -1, -1)) ||
        !TEST_true(CMP_CTX_set1_subjectName(fixture->cmp_ctx, subject))) {
        tear_down(fixture);
        fixture = NULL;
    }
    X509_NAME_free(subject);
    EXECUTE_TEST(execute_cmp_pkiheader_init_test, tear_down);
    return result;
}

static int test_cmp_pkiheader_init_no_ref_no_subject(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    fixture->expected = 0;
    EXECUTE_TEST(execute_cmp_pkiheader_init_test, tear_down);
    return result;
}

void cleanup_tests(void)
{
    EVP_PKEY_free(loadedprivkey);
    EVP_PKEY_free(loadedpubkey);
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_CMP
    if (!TEST_ptr(loadedprivkey = load_pem_key("../cmp-test/server.pem")))
        return 0;
    if (TEST_true(EVP_PKEY_up_ref(loadedprivkey)))
        loadedpubkey = loadedprivkey;

    /* Message protection tests */
    ADD_TEST(test_cmp_calc_protection_no_key_no_secret);
    ADD_TEST(test_cmp_calc_protection_pkey);
    ADD_TEST(test_cmp_calc_protection_pbmac);

    ADD_TEST(test_cmp_pkiheader_init);
    ADD_TEST(test_cmp_pkiheader_init_with_subject);
    ADD_TEST(test_cmp_pkiheader_init_no_ref_no_subject);
#endif

    return 1;
}
