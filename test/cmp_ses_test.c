/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Tobias Pankert, Siemens AG
 */

#include "cmptestlib.h"

#ifndef NDEBUG  /* tests need mock server, which is available only if !NDEBUG */


typedef struct test_fixture {
    const char *test_case_name;
    CMP_CTX *cmp_ctx;
    CMP_SRV_CTX *srv_ctx;
    int expected;
    X509 *(*exec_cert_ses_cb) (CMP_CTX *);
    STACK_OF(X509) *ca_pubs;
} CMP_SES_TEST_FIXTURE;

static X509 *cert = NULL;
static EVP_PKEY *key = NULL;

/*
 * For these unit tests, the client abandons message protection, and for
 * error messages the mock server does so as well.
 * Message protection and verification is tested in cmp_lib_test.c
 */

static void tear_down(CMP_SES_TEST_FIXTURE *fixture)
{
    CMP_CTX_delete(fixture->cmp_ctx);
    CMP_SRV_CTX_delete(fixture->srv_ctx);
    sk_X509_free(fixture->ca_pubs);
    OPENSSL_free(fixture);
}

static CMP_SES_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_SES_TEST_FIXTURE *fixture;
    CMP_CTX *srv_cmp_ctx = NULL;
    int setup_ok = 0;
    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        goto err;
    fixture->test_case_name = test_case_name;
    if (!TEST_ptr(fixture->srv_ctx = CMP_SRV_CTX_create()) ||
        !TEST_true(CMP_SRV_CTX_set_accept_unprotected(fixture->srv_ctx, 1)) ||
        !TEST_true(CMP_SRV_CTX_set1_certOut(fixture->srv_ctx, cert)) ||
        !TEST_ptr(srv_cmp_ctx = CMP_SRV_CTX_get0_ctx(fixture->srv_ctx)) ||
        !TEST_true(CMP_CTX_set1_clCert(srv_cmp_ctx, cert)) ||
        !TEST_true(CMP_CTX_set1_pkey(srv_cmp_ctx, key)))
        goto err;

    if (!TEST_ptr(fixture->cmp_ctx = CMP_CTX_create()) ||
        !TEST_true(CMP_CTX_set_transfer_cb(fixture->cmp_ctx,
                                           CMP_mock_server_perform)) ||
        !TEST_true(CMP_CTX_set_transfer_cb_arg(fixture->cmp_ctx,
                                               fixture->srv_ctx)) ||
        !TEST_true(CMP_CTX_set_option(fixture->cmp_ctx,
                                      CMP_CTX_OPT_UNPROTECTED_SEND, 1)) ||
        !TEST_true(CMP_CTX_set_option(fixture->cmp_ctx,
                                      CMP_CTX_OPT_UNPROTECTED_ERRORS, 1)) ||
        !TEST_true(CMP_CTX_set1_oldClCert(fixture->cmp_ctx, cert)) ||
        !TEST_true(CMP_CTX_set1_srvCert(fixture->cmp_ctx, cert)) ||
        !TEST_true(CMP_CTX_set1_pkey(fixture->cmp_ctx, key)))
        goto err;

    fixture->exec_cert_ses_cb = NULL;
    setup_ok = 1;
 err:
    if (!setup_ok) {
        if (fixture != NULL)
            tear_down(fixture);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static int execute_cmp_exec_rr_ses_test(CMP_SES_TEST_FIXTURE *fixture)
{
    return TEST_int_eq(fixture->expected, CMP_exec_RR_ses(fixture->cmp_ctx));
}

static int execute_cmp_exec_genm_ses_test(CMP_SES_TEST_FIXTURE *fixture)
{
    STACK_OF(CMP_INFOTYPEANDVALUE) *itavs = NULL;
    if (!TEST_ptr(itavs = CMP_exec_GENM_ses(fixture->cmp_ctx)))
        return 0;
    sk_CMP_INFOTYPEANDVALUE_pop_free(itavs, CMP_INFOTYPEANDVALUE_free);
    /* TODO: check if the returned value is the expected one (same as sent) */
    return 1;
}

static int execute_cmp_exec_certrequest_ses_test(CMP_SES_TEST_FIXTURE *fixture)
{
    X509 *res = NULL;
    if (fixture->expected) {
        if (TEST_ptr(res = fixture->exec_cert_ses_cb(fixture->cmp_ctx)) &&
            (res == cert || TEST_int_eq(X509_cmp(res, cert), 0))) {
            if (fixture->ca_pubs != NULL) {
                STACK_OF(X509) *ca_pubs = CMP_CTX_caPubs_get1(fixture->cmp_ctx);
                int ret = TEST_int_eq(0,
                        STACK_OF_X509_cmp(fixture->ca_pubs, ca_pubs));
                sk_X509_pop_free(ca_pubs, X509_free);
                return ret;
            }
            return 1;
        }
        return 0;
    }
    return TEST_ptr_null(res = fixture->exec_cert_ses_cb(fixture->cmp_ctx));
}

static int test_cmp_exec_rr_ses(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_cmp_exec_rr_ses_test, tear_down);
    return result;
}

static int test_cmp_exec_rr_ses_receive_error(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    CMP_SRV_CTX_set_statusInfo(fixture->srv_ctx, CMP_PKISTATUS_rejection,
                               CMP_CTX_FAILINFO_signerNotTrusted,
                               "test string");
    CMP_SRV_CTX_set_send_error(fixture->srv_ctx, 1);
    fixture->expected = 0;
    EXECUTE_TEST(execute_cmp_exec_rr_ses_test, tear_down);
    return result;
}

static int test_cmp_exec_ir_ses(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    fixture->exec_cert_ses_cb = CMP_exec_IR_ses;
    fixture->expected = 1;
    fixture->ca_pubs = sk_X509_new_null();
    sk_X509_push(fixture->ca_pubs, cert);
    sk_X509_push(fixture->ca_pubs, cert);
    CMP_SRV_CTX_set1_caPubsOut(fixture->srv_ctx, fixture->ca_pubs);
    EXECUTE_TEST(execute_cmp_exec_certrequest_ses_test, tear_down);
    /* TODO: check also capubs returned */
    return result;
}

static int test_cmp_exec_ir_ses_poll(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    const int pollCount = 2;
    const int checkAfter = 1;
    fixture->exec_cert_ses_cb = CMP_exec_IR_ses;
    fixture->expected = 1;

    CMP_SRV_CTX_set_pollCount(fixture->srv_ctx, pollCount);
    /* TODO: better use 1 second and check that session takes 2..3 seconds */
    CMP_SRV_CTX_set_checkAfterTime(fixture->srv_ctx, checkAfter);
    EXECUTE_TEST(execute_cmp_exec_certrequest_ses_test, tear_down);
    return result;
}

static int test_cmp_exec_ir_ses_poll_timeout(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    const int pollCount = 3;
    const int checkAfter = 4;
    const int pollTime = 1;
    fixture->exec_cert_ses_cb = CMP_exec_IR_ses;
    fixture->expected = 0;
    CMP_SRV_CTX_set_pollCount(fixture->srv_ctx, pollCount);
    CMP_SRV_CTX_set_checkAfterTime(fixture->srv_ctx, checkAfter);
    CMP_CTX_set_option(fixture->cmp_ctx, CMP_CTX_OPT_MAXPOLLTIME, pollTime);
    EXECUTE_TEST(execute_cmp_exec_certrequest_ses_test, tear_down);
    return result;
}


static int test_cmp_exec_cr_ses(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    fixture->exec_cert_ses_cb = CMP_exec_CR_ses;
    fixture->expected = 1;
    EXECUTE_TEST(execute_cmp_exec_certrequest_ses_test, tear_down);
    return result;
}

static int test_cmp_exec_cr_ses_implicit_confirm(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    fixture->exec_cert_ses_cb = CMP_exec_CR_ses;
    fixture->expected = 1;
    CMP_CTX_set_option(fixture->cmp_ctx, CMP_CTX_OPT_IMPLICITCONFIRM, 1);
    CMP_SRV_CTX_set_grant_implicit_confirm(fixture->srv_ctx, 1);
    EXECUTE_TEST(execute_cmp_exec_certrequest_ses_test, tear_down);
    return result;
}

static int test_cmp_exec_kur_ses(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    fixture->exec_cert_ses_cb = CMP_exec_KUR_ses;
    fixture->expected = 1;
    EXECUTE_TEST(execute_cmp_exec_certrequest_ses_test, tear_down);
    return result;
}

static int test_cmp_exec_p10cr_ses(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    X509_REQ *req = NULL;
    fixture->exec_cert_ses_cb = CMP_exec_P10CR_ses;
    fixture->expected = 1;
    if (!TEST_ptr(req = load_csr("../cmp-test/pkcs10.der")) ||
        !TEST_true(CMP_CTX_set1_p10CSR(fixture->cmp_ctx, req))) {
        tear_down(fixture);
        fixture = NULL;
    }
    X509_REQ_free(req);
    EXECUTE_TEST(execute_cmp_exec_certrequest_ses_test, tear_down);
    return result;
}

static int test_cmp_exec_genm_ses(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_cmp_exec_genm_ses_test, tear_down);
    return result;
}

# include <crypto/cmp/cmp_int.h>
static int execute_exchange_certconf_test(CMP_SES_TEST_FIXTURE *fixture)
{
    return TEST_int_eq(fixture->expected,
                       exchange_certConf(fixture->cmp_ctx,
                                         CMP_PKIFAILUREINFO_addInfoNotAvailable,
                                         "abcdefg"));
}

static int execute_exchange_errors_test(CMP_SES_TEST_FIXTURE *fixture)
{
    return TEST_int_eq(fixture->expected,
                    exchange_error(fixture->cmp_ctx, CMP_PKISTATUS_rejection,
                                   CMP_PKIFAILUREINFO_unsupportedVersion,
                                   "foobar"));
}

static int test_exchange_certconf(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    if (!TEST_true(CMP_CTX_set1_newClCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_exchange_certconf_test, tear_down);
    return result;
}

static int test_exchange_error(void)
{
    SETUP_TEST_FIXTURE(CMP_SES_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_exchange_errors_test, tear_down);
    return result;
}

void cleanup_tests(void)
{
    X509_free(cert);
    EVP_PKEY_free(key);
    return;
}

int setup_tests(void)
{
    if (!TEST_ptr(key = load_pem_key("../cmp-test/server.pem")) ||
        !TEST_ptr(cert =
                  load_pem_cert("../cmp-test/openssl_cmp_test_server.crt")))
        return 0;
    ADD_TEST(test_cmp_exec_rr_ses);
    ADD_TEST(test_cmp_exec_rr_ses_receive_error);
    ADD_TEST(test_cmp_exec_cr_ses);
    ADD_TEST(test_cmp_exec_cr_ses_implicit_confirm);
    ADD_TEST(test_cmp_exec_ir_ses);
    ADD_TEST(test_cmp_exec_ir_ses_poll);
    ADD_TEST(test_cmp_exec_ir_ses_poll_timeout);
    ADD_TEST(test_cmp_exec_kur_ses);
    ADD_TEST(test_cmp_exec_p10cr_ses);
    ADD_TEST(test_cmp_exec_genm_ses);
    ADD_TEST(test_exchange_certconf);
    ADD_TEST(test_exchange_error);
    return 1;
}

#else  /* !defined (NDEBUG) */

int setup_tests(void)
{
    TEST_note("CMP session tests are disabled in this build.");
    return 1;
}

#endif
