/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CMPERR_H
# define HEADER_CMPERR_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CMP

#  ifdef  __cplusplus
extern "C"
#  endif
int ERR_load_CMP_strings(void);

/*
 * CMP function codes.
 */
#  define CMP_F_CMP_CALC_PROTECTION                        100
#  define CMP_F_CMP_CERTCONF_NEW                           202
#  define CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0       101
#  define CMP_F_CMP_CERTREQ_NEW                            203
#  define CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE           102
#  define CMP_F_CMP_CERTSTATUS_SET_CERTHASH                103
#  define CMP_F_CMP_ERROR_NEW                              204
#  define CMP_F_CMP_GENM_NEW                               205
#  define CMP_F_CMP_GEN_NEW                                104
#  define CMP_F_CMP_PKIFREETEXT_PUSH_STR                   105
#  define CMP_F_CMP_PKISI_PKISTATUS_GET_STRING             106
#  define CMP_F_CMP_POLLREPCONTENT_POLLREP_GET0            107
#  define CMP_F_CMP_POLLREQ_NEW                            206
#  define CMP_F_CMP_PROCESS_CERT_REQUEST                   108
#  define CMP_F_CMP_REVREPCONTENT_PKISTATUSINFO_GET        109
#  define CMP_F_CMP_RR_NEW                                 207
#  define CMP_F_CMP_VERIFY_PBMAC                           110
#  define CMP_F_CMP_VERIFY_POPO                            111
#  define CMP_F_CMP_VERIFY_SIGNATURE                       112
#  define CMP_F_CRM_NEW                                    113
#  define CMP_F_FIND_SRVCERT                               114
#  define CMP_F_GET_CERT_STATUS                            115
#  define CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1            116
#  define CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES      117
#  define CMP_F_OSSL_CMP_CERTCONF_NEW                      118
#  define CMP_F_OSSL_CMP_CERTREP_NEW                       119
#  define CMP_F_OSSL_CMP_CERTREQ_NEW                       120
#  define CMP_F_OSSL_CMP_CTX_CAPUBS_GET1                   121
#  define CMP_F_OSSL_CMP_CTX_CAPUBS_NUM                    122
#  define CMP_F_OSSL_CMP_CTX_CAPUBS_POP                    123
#  define CMP_F_OSSL_CMP_CTX_CREATE                        124
#  define CMP_F_OSSL_CMP_CTX_EXTRACERTSIN_GET1             125
#  define CMP_F_OSSL_CMP_CTX_EXTRACERTSIN_NUM              126
#  define CMP_F_OSSL_CMP_CTX_EXTRACERTSIN_POP              127
#  define CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_NUM             128
#  define CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_PUSH1           129
#  define CMP_F_OSSL_CMP_CTX_INIT                          130
#  define CMP_F_OSSL_CMP_CTX_PUSH_FREETEXT                 131
#  define CMP_F_OSSL_CMP_CTX_SET0_NEWPKEY                  132
#  define CMP_F_OSSL_CMP_CTX_SET0_PKEY                     133
#  define CMP_F_OSSL_CMP_CTX_SET0_REQEXTENSIONS            134
#  define CMP_F_OSSL_CMP_CTX_SET1_CAPUBS                   135
#  define CMP_F_OSSL_CMP_CTX_SET1_CLCERT                   136
#  define CMP_F_OSSL_CMP_CTX_SET1_EXPECTED_SENDER          137
#  define CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSIN             138
#  define CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSOUT            139
#  define CMP_F_OSSL_CMP_CTX_SET1_ISSUER                   140
#  define CMP_F_OSSL_CMP_CTX_SET1_LAST_SENDERNONCE         141
#  define CMP_F_OSSL_CMP_CTX_SET1_NEWCLCERT                142
#  define CMP_F_OSSL_CMP_CTX_SET1_NEWPKEY                  143
#  define CMP_F_OSSL_CMP_CTX_SET1_OLDCLCERT                144
#  define CMP_F_OSSL_CMP_CTX_SET1_P10CSR                   145
#  define CMP_F_OSSL_CMP_CTX_SET1_PKEY                     146
#  define CMP_F_OSSL_CMP_CTX_SET1_PROXYNAME                147
#  define CMP_F_OSSL_CMP_CTX_SET1_RECIPIENT                148
#  define CMP_F_OSSL_CMP_CTX_SET1_RECIPNONCE               149
#  define CMP_F_OSSL_CMP_CTX_SET1_REFERENCEVALUE           150
#  define CMP_F_OSSL_CMP_CTX_SET1_SECRETVALUE              151
#  define CMP_F_OSSL_CMP_CTX_SET1_SERVERNAME               152
#  define CMP_F_OSSL_CMP_CTX_SET1_SERVERPATH               153
#  define CMP_F_OSSL_CMP_CTX_SET1_SRVCERT                  154
#  define CMP_F_OSSL_CMP_CTX_SET1_SUBJECTNAME              155
#  define CMP_F_OSSL_CMP_CTX_SET1_TRANSACTIONID            156
#  define CMP_F_OSSL_CMP_CTX_SET_PROXYPORT                 157
#  define CMP_F_OSSL_CMP_CTX_SET_SERVERPORT                158
#  define CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1          159
#  define CMP_F_OSSL_CMP_ERROR_NEW                         160
#  define CMP_F_OSSL_CMP_EXCHANGE_CERTCONF                 161
#  define CMP_F_OSSL_CMP_EXCHANGE_ERROR                    162
#  define CMP_F_OSSL_CMP_EXEC_CR_SES                       163
#  define CMP_F_OSSL_CMP_EXEC_GENM_SES                     164
#  define CMP_F_OSSL_CMP_EXEC_IR_SES                       165
#  define CMP_F_OSSL_CMP_EXEC_KUR_SES                      166
#  define CMP_F_OSSL_CMP_EXEC_P10CR_SES                    167
#  define CMP_F_OSSL_CMP_EXEC_RR_SES                       168
#  define CMP_F_OSSL_CMP_HDR_GENERALINFO_ITEM_PUSH0        169
#  define CMP_F_OSSL_CMP_HDR_INIT                          170
#  define CMP_F_OSSL_CMP_HDR_PUSH0_FREETEXT                171
#  define CMP_F_OSSL_CMP_HDR_PUSH1_FREETEXT                172
#  define CMP_F_OSSL_CMP_HDR_SET_MESSAGETIME               173
#  define CMP_F_OSSL_CMP_HDR_SET_VERSION                   174
#  define CMP_F_OSSL_CMP_MSG_CHECK_RECEIVED                175
#  define CMP_F_OSSL_CMP_MSG_CREATE                        176
#  define CMP_F_OSSL_CMP_MSG_GENERALINFO_ITEMS_PUSH1       177
#  define CMP_F_OSSL_CMP_MSG_GENM_ITEMS_PUSH1              178
#  define CMP_F_OSSL_CMP_MSG_GENM_ITEM_PUSH0               179
#  define CMP_F_OSSL_CMP_MSG_HTTP_PERFORM                  180
#  define CMP_F_OSSL_CMP_MSG_PROTECT                       181
#  define CMP_F_OSSL_CMP_PKICONF_NEW                       182
#  define CMP_F_OSSL_CMP_PKISI_PKIFAILUREINFO_GET          183
#  define CMP_F_OSSL_CMP_PKISI_PKISTATUS_GET               184
#  define CMP_F_OSSL_CMP_POLLREP_NEW                       185
#  define CMP_F_OSSL_CMP_POLLREQ_NEW                       186
#  define CMP_F_OSSL_CMP_RP_NEW                            187
#  define CMP_F_OSSL_CMP_RR_NEW                            188
#  define CMP_F_OSSL_CMP_SRV_CTX_CREATE                    189
#  define CMP_F_OSSL_CMP_VALIDATE_CERT_PATH                190
#  define CMP_F_OSSL_CMP_VALIDATE_MSG                      191
#  define CMP_F_POLLFORRESPONSE                            192
#  define CMP_F_PROCESS_CERTCONF                           193
#  define CMP_F_PROCESS_ERROR                              194
#  define CMP_F_PROCESS_GENM                               195
#  define CMP_F_PROCESS_POLLREQ                            196
#  define CMP_F_PROCESS_REQUEST                            197
#  define CMP_F_PROCESS_RR                                 198
#  define CMP_F_SEND_RECEIVE_CHECK                         199
#  define CMP_F_SET1_AOSTR_ELSE_RANDOM                     200
#  define CMP_F_SET1_GENERAL_NAME                          201

/*
 * CMP reason codes.
 */
#  define CMP_R_ALGORITHM_NOT_SUPPORTED                    100
#  define CMP_R_CERTIFICATE_NOT_ACCEPTED                   101
#  define CMP_R_CERTIFICATE_NOT_FOUND                      102
#  define CMP_R_CERTREQMSG_NOT_FOUND                       103
#  define CMP_R_CERTRESPONSE_NOT_FOUND                     104
#  define CMP_R_CERT_AND_KEY_DO_NOT_MATCH                  105
#  define CMP_R_CONNECT_TIMEOUT                            106
#  define CMP_R_CP_NOT_RECEIVED                            107
#  define CMP_R_ENCOUNTERED_KEYUPDATEWARNING               108
#  define CMP_R_ENCOUNTERED_UNSUPPORTED_PKISTATUS          109
#  define CMP_R_ENCOUNTERED_WAITING                        110
#  define CMP_R_ERROR_CALCULATING_PROTECTION               111
#  define CMP_R_ERROR_CONNECTING                           112
#  define CMP_R_ERROR_CREATING_CERTCONF                    113
#  define CMP_R_ERROR_CREATING_CERTREP                     114
#  define CMP_R_ERROR_CREATING_CR                          115
#  define CMP_R_ERROR_CREATING_ERROR                       116
#  define CMP_R_ERROR_CREATING_GENM                        117
#  define CMP_R_ERROR_CREATING_GENP                        118
#  define CMP_R_ERROR_CREATING_IR                          119
#  define CMP_R_ERROR_CREATING_KUR                         120
#  define CMP_R_ERROR_CREATING_P10CR                       121
#  define CMP_R_ERROR_CREATING_PKICONF                     122
#  define CMP_R_ERROR_CREATING_POLLREP                     123
#  define CMP_R_ERROR_CREATING_POLLREQ                     124
#  define CMP_R_ERROR_CREATING_RP                          125
#  define CMP_R_ERROR_CREATING_RR                          126
#  define CMP_R_ERROR_DECODING_MESSAGE                     127
#  define CMP_R_ERROR_PARSING_PKISTATUS                    128
#  define CMP_R_ERROR_PROCESSING_CERTREQ                   129
#  define CMP_R_ERROR_PROCESSING_MSG                       130
#  define CMP_R_ERROR_PROTECTING_MESSAGE                   131
#  define CMP_R_ERROR_PUSHING_GENERALINFO_ITEM             132
#  define CMP_R_ERROR_PUSHING_GENERALINFO_ITEMS            133
#  define CMP_R_ERROR_PUSHING_GENM_ITEMS                   134
#  define CMP_R_ERROR_SENDING_REQUEST                      135
#  define CMP_R_ERROR_SETTING_CERTHASH                     136
#  define CMP_R_ERROR_TRANSFERRING_IN                      137
#  define CMP_R_ERROR_TRANSFERRING_OUT                     138
#  define CMP_R_ERROR_VALIDATING_PROTECTION                139
#  define CMP_R_FAILED_EXTRACTING_PUBKEY                   140
#  define CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE               141
#  define CMP_R_FAILED_TO_SEND_REQUEST                     142
#  define CMP_R_FAILURE_OBTAINING_RANDOM                   143
#  define CMP_R_GENP_NOT_RECEIVED                          144
#  define CMP_R_INVALID_ARGS                               145
#  define CMP_R_INVALID_CONTEXT                            146
#  define CMP_R_INVALID_PARAMETERS                         147
#  define CMP_R_IP_NOT_RECEIVED                            148
#  define CMP_R_KUP_NOT_RECEIVED                           149
#  define CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION  150
#  define CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE         151
#  define CMP_R_MISSING_PROTECTION                         152
#  define CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED           188
#  define CMP_R_MULTIPLE_SAN_SOURCES                       153
#  define CMP_R_NO_SENDER_NO_REFERENCE                     154
#  define CMP_R_NO_SUITABLE_SERVER_CERT                    155
#  define CMP_R_NO_VALID_SERVER_CERT_FOUND                 156
#  define CMP_R_NULL_ARGUMENT                              157
#  define CMP_R_OUT_OF_MEMORY                              158
#  define CMP_R_PKIBODY_ERROR                              159
#  define CMP_R_PKICONF_NOT_RECEIVED                       160
#  define CMP_R_PKISTATUSINFO_NOT_FOUND                    161
#  define CMP_R_POLLREP_NOT_RECEIVED                       162
#  define CMP_R_POTENTIALLY_INVALID_CERTIFICATE            163
#  define CMP_R_READ_TIMEOUT                               164
#  define CMP_R_RECEIVED_ERROR                             165
#  define CMP_R_RECEIVED_NEGATIVE_CHECKAFTER_IN_POLLREP    166
#  define CMP_R_RECIPNONCE_UNMATCHED                       167
#  define CMP_R_REQUEST_NOT_ACCEPTED                       168
#  define CMP_R_REQUEST_REJECTED_BY_CA                     169
#  define CMP_R_RP_NOT_RECEIVED                            170
#  define CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED      171
#  define CMP_R_TLS_ERROR                                  172
#  define CMP_R_TOTAL_TIMEOUT                              173
#  define CMP_R_TRANSACTIONID_UNMATCHED                    174
#  define CMP_R_UNEXPECTED_PKIBODY                         175
#  define CMP_R_UNEXPECTED_PKISTATUS                       176
#  define CMP_R_UNEXPECTED_REQUEST_ID                      177
#  define CMP_R_UNEXPECTED_SENDER                          178
#  define CMP_R_UNKNOWN_ALGORITHM_ID                       179
#  define CMP_R_UNKNOWN_CERT_TYPE                          180
#  define CMP_R_UNKNOWN_PKISTATUS                          181
#  define CMP_R_UNSUPPORTED_ALGORITHM                      182
#  define CMP_R_UNSUPPORTED_KEY_TYPE                       183
#  define CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC      184
#  define CMP_R_WRONG_ALGORITHM_OID                        185
#  define CMP_R_WRONG_CERT_HASH                            186
#  define CMP_R_WRONG_PBM_VALUE                            187

# endif
#endif