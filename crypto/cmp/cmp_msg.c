/* crypto/cmp/cmp_msg.c
 * Functions for creating CMP (RFC 4210) messages for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2014 Miikka Viljanen <mviljane@users.sourceforge.net>
 */
/* ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in
 *        the documentation and/or other materials provided with the
 *        distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *        software must display the following acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *        endorse or promote products derived from this software without
 *        prior written permission. For written permission, please contact
 *        openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *        nor may "OpenSSL" appear in their names without prior written
 *        permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *        acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.      IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by
 * Nokia for contribution to the OpenSSL project.
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/safestack.h>
#include <openssl/err.h>

#include <string.h>

#include "cmp_int.h"

/* ############################################################################
 * Takes a stack of GENERAL_NAMEs and adds them to the given extension stack.
 * this is used to setting subject alternate names to a certTemplate
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
static int add_altname_extensions(X509_EXTENSIONS ** extensions,
                                  STACK_OF (GENERAL_NAME) * altnames,
                                  int critical)
{
    X509_EXTENSION *ext = NULL;
    unsigned char *der = NULL;
    ASN1_OCTET_STRING *str = NULL;;

    if (!extensions)
        goto err;
    if (!altnames)
        goto err;

    if (!(str = ASN1_OCTET_STRING_new()))
        goto err;

    int derLen = i2d_GENERAL_NAMES(altnames, &der);
    if (derLen == 0 || der == NULL)
        goto err;

    if (!ASN1_STRING_set(str, der, derLen))
        goto err;
    if (!X509_EXTENSION_create_by_NID
        (&ext, NID_subject_alt_name, critical, str))
        goto err;

    ASN1_OCTET_STRING_free(str);
    OPENSSL_free(der);

    if (!X509v3_add_ext(extensions, ext, 0))
        goto err;

    X509_EXTENSION_free(ext);

    return 1;
 err:
    if (ext)
        X509_EXTENSION_free(ext);
    return 0;
}

/* ############################################################################
 * Takes a CERTIFICATEPOLICIES structure and adds it to the given extension stack.
 * this is used to setting certificate policy OIDs to a certTemplate
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
static int add_policy_extensions(X509_EXTENSIONS ** extensions,
                                 CERTIFICATEPOLICIES *policies)
{
    X509_EXTENSION *ext = NULL;
    unsigned char *der = NULL;
    int derlen = 0;
    ASN1_OCTET_STRING *str = NULL;

    if (!extensions || !policies)
        goto err;

    if (!(str = ASN1_OCTET_STRING_new()))
        goto err;

    derlen = i2d_CERTIFICATEPOLICIES(policies, &der);
    if (!ASN1_STRING_set(str, der, derlen))
        goto err;
    if (!X509_EXTENSION_create_by_NID(&ext, NID_certificate_policies, 1, str))
        goto err;

    ASN1_OCTET_STRING_free(str);
    OPENSSL_free(der);

    if (!X509v3_add_ext(extensions, ext, 0))
        goto err;

    X509_EXTENSION_free(ext);

    return 1;
 err:
    if (ext)
        X509_EXTENSION_free(ext);
    return 0;
}

/* ############################################################################ *
 * Creates a new polling request PKIMessage for the given request ID
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_pollReq_new(CMP_CTX *ctx, int reqId)
{
    CMP_PKIMESSAGE *msg = NULL;
    CMP_POLLREQ *preq = NULL;

    if (!ctx)
        goto err;

    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_POLLREQ);

    if (!(preq = CMP_POLLREQ_new()))
        goto err;
    /* TODO support multiple cert request ids to poll */
    ASN1_INTEGER_set(preq->certReqId, reqId);
    if (!(msg->body->value.pollReq = sk_CMP_POLLREQ_new_null()))
        goto err;

    sk_CMP_POLLREQ_push(msg->body->value.pollReq, preq);

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;
 err:
    CMPerr(CMP_F_CMP_POLLREQ_NEW, CMP_R_ERROR_CREATING_POLLREQ);
    if (msg)
        CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/* ############################################################################ *
 * internal function
 *
 * performs the generic generation of certificate requests for IR/CR/KUR
 * ############################################################################ */
static CMP_PKIMESSAGE *certreq_new(CMP_CTX *ctx, int bodytype)
{
    CMP_PKIMESSAGE *msg = NULL;
    CRMF_CERTREQMSG *certReq0 = NULL;
    X509_EXTENSIONS *extensions = NULL;
    X509_NAME *subject = NULL;
    EVP_PKEY *requestKey = NULL;

    if (!ctx || (!ctx->pkey && !ctx->newPkey) ) {
        CMPerr(CMP_F_CERTREQ_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if (ctx->reqExtensions) { /* copy them to prevent double free while allowing reuse */
        int i;
        if (!(extensions = sk_X509_EXTENSION_new_null()))
            goto err;
        for (i = 0; i < sk_X509_EXTENSION_num(ctx->reqExtensions); i++)
            if (!sk_X509_EXTENSION_push(extensions, X509_EXTENSION_dup(
                    sk_X509_EXTENSION_value(ctx->reqExtensions, i))))
                goto err;
    }

    (void)CMP_CTX_set1_transactionID(ctx, NULL); // start new transaction
    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;

    CMP_PKIMESSAGE_set_bodytype(msg, bodytype);

    if (ctx->implicitConfirm)
        if (!CMP_PKIMESSAGE_set_implicitConfirm(msg))
            goto err;

    if (ctx->geninfo_itavs)
        if (!CMP_PKIMESSAGE_generalInfo_items_push1(msg, ctx->geninfo_itavs))
			goto err;

    X509 *oldcert = ctx->oldClCert ? ctx->oldClCert : ctx->clCert;
    if (ctx->subjectName)
        subject = ctx->subjectName;
    else if (oldcert && (bodytype == V_CMP_PKIBODY_KUR ||
                         sk_GENERAL_NAME_num(ctx->subjectAltNames) <= 0))
        /* For KUR, copy subjectName from the previous certificate in any case, */
        /* for IR or CR, get subject name from any previous certificate, but only if there's no subjectAltName. */
        /* This is the explicitly given oldClCert, if present, or else the clCert as used for message protection. */
        subject = X509_get_subject_name(oldcert);

    if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0)
        /* TODO: for KUR, if <= 0, maybe copy any existing SANs from cert to be renewed; clCert or oldClCert? */
        /* According to RFC5280, subjectAltName MUST be critical if subject is null */
        add_altname_extensions(&extensions, ctx->subjectAltNames,
                               ctx->setSubjectAltNameCritical
                               || subject == NULL);

    if (ctx->policies)
        add_policy_extensions(&extensions, ctx->policies);

    if (!(msg->body->value.ir = sk_CRMF_CERTREQMSG_new_null()))
        goto err;
    requestKey = ctx->newPkey ? ctx->newPkey : ctx->pkey; // default is current client key
    if (!(certReq0 = CRMF_certreq_new(0L, requestKey, subject, ctx->issuer, 0, 0, extensions)))
        goto err;
    sk_CRMF_CERTREQMSG_push(msg->body->value.ir, certReq0);
    /* TODO: here also the optional 2nd certreqmsg could be pushed to the stack */

    /* sets the id-regCtrl-regToken to regInfo (not described in RFC, but EJBCA
     * in CA mode might insist on that) */
    if (bodytype == V_CMP_PKIBODY_IR && ctx->regToken)
        if (!CRMF_CERTREQMSG_set1_regInfo_regToken(certReq0, ctx->regToken))
            goto err;

    /* for KUR, setting OldCertId according to D.6:
       7.  regCtrl OldCertId SHOULD be used */
    if (bodytype == V_CMP_PKIBODY_KUR)
        if (!CRMF_CERTREQMSG_set1_control_oldCertId(certReq0, oldcert))
            goto err;

    if (!CRMF_CERTREQMSG_calc_and_set_popo(certReq0, requestKey, ctx->digest, ctx->popoMethod))
        goto err;

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    /* cleanup */
    if (extensions)
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

    return msg;

 err:
    CMPerr(CMP_F_CERTREQ_NEW, CMP_R_ERROR_CREATING_REQUEST_MESSAGE);
    if (extensions)
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    if (msg)
        CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/* ############################################################################ *
 * Create a new Initial Request PKIMessage based on the settings in given ctx
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_ir_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;
    if (!(msg = certreq_new(ctx, V_CMP_PKIBODY_IR)))
        CMPerr(CMP_F_CMP_IR_NEW, CMP_R_ERROR_CREATING_IR);
    return msg;
}

/* ############################################################################ *
 * Creates a new Certificate Request PKIMessage based on the settings in ctx
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_cr_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;
    if (!(msg = certreq_new(ctx, V_CMP_PKIBODY_CR)))
        CMPerr(CMP_F_CMP_CR_NEW, CMP_R_ERROR_CREATING_CR);
    return msg;
}

/* ############################################################################ *
 * Creates a new Key Update Request PKIMessage based on the settings in ctx
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_kur_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;
    if (!(msg = certreq_new(ctx, V_CMP_PKIBODY_KUR)))
        CMPerr(CMP_F_CMP_KUR_NEW, CMP_R_ERROR_CREATING_KUR);
    return msg;
}

/* ############################################################################ *
 * Creates a new Revocation Request PKIMessage for ctx->oldClCert based on
 * the settings in ctx.
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_rr_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;
    CRMF_CERTTEMPLATE *certTpl = NULL;
    X509_NAME *subject = NULL;
    EVP_PKEY *pubkey = NULL;
    CMP_REVDETAILS *rd = NULL;

    if (!ctx || !ctx->oldClCert) {
        CMPerr(CMP_F_CMP_RR_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    (void)CMP_CTX_set1_transactionID(ctx, NULL); // start new transaction
    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    if (!ctx->srvCert && !ctx->recipient && !ctx->issuer) // set default recipient
        if (!CMP_PKIHEADER_set1_recipient(msg->header, X509_get_issuer_name(ctx->oldClCert)))
            goto err;
    CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_RR);

    if (ctx->geninfo_itavs)
        if (!CMP_PKIMESSAGE_generalInfo_items_push1(msg, ctx->geninfo_itavs))
			goto err;

    if (!(msg->body->value.rr = sk_CMP_REVDETAILS_new_null()))
        goto err;
    if (!(rd = CMP_REVDETAILS_new()))
        goto err;
    sk_CMP_REVDETAILS_push(msg->body->value.rr, rd);

    /* Fill the template from the contents of the certificate to be revoked; TODO: maybe add further fields */
    certTpl = rd->certDetails;
    if (!(subject = X509_get_subject_name(ctx->oldClCert)))
        goto err;
    X509_NAME_set(&certTpl->subject, subject);

    if (!(pubkey = X509_get_pubkey(ctx->oldClCert)))
        goto err;
    X509_PUBKEY_set(&certTpl->publicKey, pubkey);
    EVP_PKEY_free(pubkey);

    if (!(certTpl->serialNumber =
          ASN1_INTEGER_dup(X509_get_serialNumber(ctx->oldClCert))))
        goto err;
    X509_NAME_set(&certTpl->issuer, X509_get_issuer_name(ctx->oldClCert));

    /* revocation reason code is optional */
    if (ctx->revocationReason != CRL_REASON_NONE) {
        ASN1_ENUMERATED *val = ASN1_ENUMERATED_new();
        if (!val || !ASN1_ENUMERATED_set(val, ctx->revocationReason))
            goto err;
        X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(NULL, NID_crl_reason, 0, val);
        if (!ext || !X509v3_add_ext(&rd->crlEntryDetails, ext, -1))
            goto err;
        X509_EXTENSION_free(ext);
        ASN1_ENUMERATED_free(val);
    }

    /* TODO: the Revocation Passphrase according to section 5.3.19.9 could be set here if set in ctx */

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_RR_NEW, CMP_R_ERROR_CREATING_RR);
    if (msg)
        CMP_PKIMESSAGE_free(msg);

    return NULL;
}

/* ############################################################################ *
 * Creates a new Certificate Confirmation PKIMessage
 * returns a pointer to the PKIMessage on success, NULL on error
 * TODO: handle both possible certificates when signing and encrypting
 * certificates have been requested/received
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_certConf_new(CMP_CTX *ctx, int failure, const char *text)
{
    CMP_PKIMESSAGE *msg = NULL;
    CMP_CERTSTATUS *certStatus = NULL;

    if (!ctx || !ctx->newClCert) {
        CMPerr(CMP_F_CMP_CERTCONF_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_CERTCONF);
    if (!(msg->body->value.certConf = sk_CMP_CERTSTATUS_new_null()))
        goto err;

    if (!(certStatus = CMP_CERTSTATUS_new()))
        goto err;
    if (!sk_CMP_CERTSTATUS_push(msg->body->value.certConf, certStatus))
        goto err;
    /* set the # of the certReq */
    ASN1_INTEGER_set(certStatus->certReqId, 0L);
    /* -- the hash of the certificate, using the same hash algorithm
     * -- as is used to create and verify the certificate signature */
    if (!CMP_CERTSTATUS_set_certHash(certStatus, ctx->newClCert))
        goto err;
    /*
       For any particular CertStatus, omission of the statusInfo field
       indicates ACCEPTANCE of the specified certificate.  Alternatively,
       explicit status details (with respect to acceptance or rejection) MAY
       be provided in the statusInfo field, perhaps for auditing purposes at
       the CA/RA.
    */
    if (failure >= 0) {
        CMP_PKISTATUSINFO *status_info = CMP_statusInfo_new(CMP_PKISTATUS_rejection, failure, text);
        if (status_info == NULL)
            goto err;
        certStatus->statusInfo = status_info;
        CMP_printf(ctx, "INFO: rejecting certificate.");
    }

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_CERTCONF_NEW, CMP_R_ERROR_CREATING_CERTCONF);
    if (msg)
        CMP_PKIMESSAGE_free(msg);

    return NULL;
}

/* ############################################################################ *
 * Creates a new General Message with an empty itav stack
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_genm_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;

    if (!ctx) {
        CMPerr(CMP_F_CMP_GENM_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    (void)CMP_CTX_set1_transactionID(ctx, NULL); // start new transaction
    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_GENM);

    if (ctx->geninfo_itavs)
        if (!CMP_PKIMESSAGE_generalInfo_items_push1(msg, ctx->geninfo_itavs))
			goto err;

    if (!(msg->body->value.genm = sk_CMP_INFOTYPEANDVALUE_new_null()))
        goto err;               /* initialize with empty stack */

    /* TODO: here the body needs to be set */

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_GENM_NEW, CMP_R_ERROR_CREATING_GENM);
    if (msg)
        CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/* ############################################################################ *
 * Creates a new Error Message with the given contents
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_error_new(CMP_CTX *ctx, CMP_PKISTATUSINFO *si,
                              int errorCode, STACK_OF (ASN1_UTF8STRING) *errorDetails)
{
    CMP_PKIMESSAGE *msg = NULL;

    if (!ctx || !si) {
        CMPerr(CMP_F_CMP_ERROR_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_ERROR);
    if (!(msg->body->value.error = CMP_ERRORMSGCONTENT_new()))
        goto err;

    CMP_PKISTATUSINFO_free(msg->body->value.error->pKIStatusInfo);
    msg->body->value.error->pKIStatusInfo = si;
    if (errorCode >= 0) {
        msg->body->value.error->errorCode = ASN1_INTEGER_new();
        if (!ASN1_INTEGER_set(msg->body->value.error->errorCode, errorCode))
            goto err;
    }
    msg->body->value.error->errorDetails = errorDetails;

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;
    return msg;

 err:
    CMPerr(CMP_F_CMP_ERROR_NEW, CMP_R_ERROR_CREATING_ERROR);
    CMP_PKIMESSAGE_free(msg);
    return NULL;
}
