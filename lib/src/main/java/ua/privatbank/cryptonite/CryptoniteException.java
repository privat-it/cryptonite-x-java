/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

public class CryptoniteException extends Exception {

    private static final long serialVersionUID = -5973988789342276336L;

    private final int code;

    /** Cryptonite */
    public final static int RET_OK                                            = 0;

    public final static int RET_MEMORY_ALLOC_ERROR                            = 1;
    public final static int RET_INVALID_PARAM                                 = 2;
    public final static int RET_VERIFY_FAILED                                 = 3;
    public final static int RET_CONTEXT_NOT_READY                             = 4;
    public final static int RET_INVALID_CTX                                   = 5;
    public final static int RET_INVALID_PRIVATE_KEY                           = 6;
    public final static int RET_INVALID_PUBLIC_KEY                            = 7;
    public final static int RET_DSTU_PRNG_LOOPED                              = 8;
    public final static int RET_INVALID_MODE                                  = 9;
    public final static int RET_UNSUPPORTED                                   = 10;
    public final static int RET_INVALID_KEY_SIZE                              = 11;
    public final static int RET_INVALID_IV_SIZE                               = 12;
    public final static int RET_RSA_DECRYPTION_ERROR                          = 13;
    public final static int RET_FILE_OPEN_ERROR                               = 14;
    public final static int RET_FILE_READ_ERROR                               = 15;
    public final static int RET_FILE_WRITE_ERROR                              = 16;
    public final static int RET_FILE_GET_SIZE_ERROR                           = 17;
    public final static int RET_DIR_OPEN_ERROR                                = 18;

    /** Cryptonite PKI */
    public final static int RET_ASN1_ERROR                                    = 100;
    public final static int RET_ASN1_ENCODE_ERROR                             = 101;
    public final static int RET_ASN1_DECODE_ERROR                             = 102;

    private final static int PKIX_ERROR_NAME_CODE                              = 0x0100;

    /** Невизначена помилка. */
    public final static int RET_PKIX_GENERAL_ERROR                            = (PKIX_ERROR_NAME_CODE + 0x00000001);
    /** Відсутній підпис в OCSP запиті. */
    public final static int RET_PKIX_OCSP_REQ_NO_SIGN                         = (PKIX_ERROR_NAME_CODE + 0x00000002);
    /** Відсутній атрибут. */
    public final static int RET_PKIX_ATTRIBUTE_NOT_FOUND                      = (PKIX_ERROR_NAME_CODE + 0x00000003);
    /** Вихід за межі масиву. */
    public final static int RET_PKIX_OUT_OF_BOUND_ERROR                       = (PKIX_ERROR_NAME_CODE + 0x00000004);
    /** Шуканий об'єкт не знайдений. */
    public final static int RET_PKIX_OBJ_NOT_FOUND                            = (PKIX_ERROR_NAME_CODE + 0x00000005);
    /** Помилка кріпто-менеджера. */
    public final static int RET_PKIX_CRYPTO_MANAGER_ERROR                     = (PKIX_ERROR_NAME_CODE + 0x00000006);
    /** Помилка ініціалізації. */
    public final static int RET_PKIX_INITIALIZATION_ERROR                     = (PKIX_ERROR_NAME_CODE + 0x00000007);
    /** Внутрішня помилка роботи. */
    public final static int RET_PKIX_INTERNAL_ERROR                           = (PKIX_ERROR_NAME_CODE + 0x00000008);
    /** Помилка шифрування. */
    public final static int RET_PKIX_CIPHER_ERROR                             = (PKIX_ERROR_NAME_CODE + 0x00000009);
    /** Помилка виробки підпису. */
    public final static int RET_PKIX_SIGN_ERROR                               = (PKIX_ERROR_NAME_CODE + 0x0000000a);
    /** Помилка перевірки підпису. */
    public final static int RET_PKIX_VERIFY_FAILED                            = (PKIX_ERROR_NAME_CODE + 0x0000000b);
    /** OID, який не підтримується. */
    public final static int RET_PKIX_UNSUPPORTED_OID                          = (PKIX_ERROR_NAME_CODE + 0x0000000c);
    /** Неправильний OID. */
    public final static int RET_PKIX_INCORRECT_OID                            = (PKIX_ERROR_NAME_CODE + 0x0000000d);
    /** PKIX об'єкт, який не підтримується. */
    public final static int RET_PKIX_UNSUPPORTED_PKIX_OBJ                     = (PKIX_ERROR_NAME_CODE + 0x0000000e);
    /** Неправильна структура сертифікату. */
    public final static int RET_PKIX_INCORRECT_CERT_STRUCTURE                 = (PKIX_ERROR_NAME_CODE + 0x0000000f);
    /** Відсутній сертифікат. */
    public final static int RET_PKIX_NO_CERTIFICATE                           = (PKIX_ERROR_NAME_CODE + 0x00000010);
    /** Адаптер не містить сертифікат. */
    public final static int RET_PKIX_OCSP_REQ_ADAPTER_HASNOT_CERT             = (PKIX_ERROR_NAME_CODE + 0x00000011);
    /** Не є OCSP ceртифікатом. */
    public final static int RET_PKIX_OCSP_REQ_ADAPTER_ISNOT_OCSP              = (PKIX_ERROR_NAME_CODE + 0x00000012);
    /** Кореневий сертифікат не є OCSP видавцем сертифікату. */
    public final static int RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_OCSPISSUER       = (PKIX_ERROR_NAME_CODE + 0x00000013);
    /** Кореневий сертифікат не є запитувачем видавця сертифікату. */
    public final static int RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_REQUESTORISSUER  = (PKIX_ERROR_NAME_CODE + 0x00000014);
    /** Кореневий сертифікат не є перевіреним сертифікатом видавця. */
    public final static int RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_CHECKED          = (PKIX_ERROR_NAME_CODE + 0x00000015);
    /** Помилка формування підпису. */
    public final static int RET_PKIX_OCSP_REQ_GENERATION_SIGN_ERROR           = (PKIX_ERROR_NAME_CODE + 0x00000016);
    /** Запит не був згенерований. */
    public final static int RET_PKIX_OCSP_REQ_REQUEST_HASNOT_BEEN_GENERATED   = (PKIX_ERROR_NAME_CODE + 0x00000017);
    /** Помилка декодування responseBytes. */
    public final static int RET_PKIX_OCSP_REQ_RESPONSE_DECODING_ERROR         = (PKIX_ERROR_NAME_CODE + 0x00000018);
    /** Помилка при отриманні основної відповіді. */
    public final static int RET_PKIX_OCSP_REQ_RESPONSE_BASIC_ERROR            = (PKIX_ERROR_NAME_CODE + 0x00000019);
    /** Помилка перевірки підпису відповіді. */
    public final static int RET_PKIX_OCSP_REQ_RESPONSE_VERIFY_ERROR           = (PKIX_ERROR_NAME_CODE + 0x0000001a);
    /** Попередження: OCSPResponse не містить nextUpdate інформацію. */
    public final static int RET_PKIX_OCSP_REQ_RESPONSE_NEXTUP_WARNING         = (PKIX_ERROR_NAME_CODE + 0x0000001b);
    /** Статус OCSPResponce не є успішним. */
    public final static int RET_PKIX_OCSP_RESP_NOT_SUCCESSFUL                 = (PKIX_ERROR_NAME_CODE + 0x0000001c);
    /** Вийшов час OCSPResponce. */
    public final static int RET_PKIX_OCSP_RESP_TIMEOUT                        = (PKIX_ERROR_NAME_CODE + 0x0000001d);
    /** OCSPResponce вийшов час nextUpdate. */
    public final static int RET_PKIX_OCSP_RESP_NEXT_UPDATE_TIMEOUT            = (PKIX_ERROR_NAME_CODE + 0x0000001e);
    /** OCSPResponce не містить responseBytes. */
    public final static int RET_PKIX_OCSP_RESP_NO_BYTES                       = (PKIX_ERROR_NAME_CODE + 0x0000001f);
    /** Неможливо об'єднати CRL списки. */
    public final static int RET_PKIX_CRL_CANT_MERGE                           = (PKIX_ERROR_NAME_CODE + 0x00000020);

    public final static int RET_PKIX_CERT_NO_QC_STATEMENT_LIMIT               = (PKIX_ERROR_NAME_CODE + 0x00000021);

    /** В списку розширень немає розширень. */
    public final static int RET_PKIX_EXT_NOT_FOUND                            = (PKIX_ERROR_NAME_CODE + 0x00000022);

    public final static int RET_PKIX_INVALID_CTX_MODE                         = (PKIX_ERROR_NAME_CODE + 0x00000023);
    public final static int RET_PKIX_CONTEXT_NOT_READY                        = (PKIX_ERROR_NAME_CODE + 0x00000024);
    public final static int RET_PKIX_INVALID_MAC                              = (PKIX_ERROR_NAME_CODE + 0x00000025);
    public final static int RET_PKIX_SA_NO_CERTIFICATE                        = (PKIX_ERROR_NAME_CODE + 0x00000026);
    public final static int RET_PKIX_VA_NO_CERTIFICATE                        = (PKIX_ERROR_NAME_CODE + 0x00000027);
    public final static int RET_PKIX_OCSP_RESP_INVALID_NAME_HASH              = (PKIX_ERROR_NAME_CODE + 0x00000028);
    public final static int RET_PKIX_OCSP_RESP_INVALID_KEY_HASH               = (PKIX_ERROR_NAME_CODE + 0x00000029);
    public final static int RET_PKIX_OCSP_REQ_NO_REQUESTOR_NAME               = (PKIX_ERROR_NAME_CODE + 0x0000002a);
    public final static int RET_PKIX_OCSP_REQ_VERIFY_FAILED                   = (PKIX_ERROR_NAME_CODE + 0x0000002b);
    public final static int RET_PKIX_UNSUPPORTED_RESPONDER_ID                 = (PKIX_ERROR_NAME_CODE + 0x0000002c);
    public final static int RET_PKIX_SA_NOT_OCSP_CERT                         = (PKIX_ERROR_NAME_CODE + 0x0000002d);
    public final static int RET_OCSP_REQ_NOSINGLE_REQ_EXTS                    = (PKIX_ERROR_NAME_CODE + 0x0000002e);
    public final static int RET_PKIX_OCSP_RESP_NO_CRL_REASON                  = (PKIX_ERROR_NAME_CODE + 0x0000002f);

    /** InternalErrorException */
    public final static int RET_PKIX_INTERNAL_ERROR_EXCEPTION                 = (PKIX_ERROR_NAME_CODE + 0x00000030);
    /** MalformedRequestException */
    public final static int RET_PKIX_MALFORMED_REQUEST_EXCEPTION              = (PKIX_ERROR_NAME_CODE + 0x00000031);
    /** SigRequiredException */
    public final static int RET_PKIX_SIG_REQUIRED_EXCEPTION                   = (PKIX_ERROR_NAME_CODE + 0x00000032);
    /** Не підтримуване ім'я суб'єкту типу елемента. */
    public final static int RET_PKIX_SUBJ_NAME_UNSUPPORTED                    = (PKIX_ERROR_NAME_CODE + 0x00000033);
    /** Одержувач не знайдений в контейнері EnvelopedData. */
    public final static int RET_PKIX_RECIPIENT_NOT_FOUND                      = (PKIX_ERROR_NAME_CODE + 0x00000034);
    /** Контейнерні підписи, які об'єднуються, обчислені від різних даних. */
    public final static int RET_PKIX_SDATA_WRONG_CONTENT_DATA                 = (PKIX_ERROR_NAME_CODE + 0x00000035);
    /** В контейнері SignedData дані не відповідають зовнішнім даним. */
    public final static int RET_PKIX_SDATA_WRONG_EXT_DATA                     = (PKIX_ERROR_NAME_CODE + 0x00000036);
    /** Помилкові дані в мітці часу. */
    public final static int RET_PKIX_WRONG_TSP_DATA                           = (PKIX_ERROR_NAME_CODE + 0x00000037);

    public final static int RET_PKIX_UNSUPPORTED_DSTU_ELLIPTIC_CURVE          = (PKIX_ERROR_NAME_CODE + 0x00000038);
    public final static int RET_PKIX_UNSUPPORTED_DSTU_POL_MEMBER              = (PKIX_ERROR_NAME_CODE + 0x00000039);
    public final static int RET_PKIX_UNSUPPORTED_DSTU_ELLIPTIC_CURVE_OID      = (PKIX_ERROR_NAME_CODE + 0x0000003a);
    public final static int RET_PKIX_GET_TIME_ERROR                           = (PKIX_ERROR_NAME_CODE + 0x0000003b);
    public final static int RET_PKIX_CERT_NOT_BEFORE_VALIDITY_ERROR           = (PKIX_ERROR_NAME_CODE + 0x0000003c);
    public final static int RET_PKIX_CERT_NOT_AFTER_VALIDITY_ERROR            = (PKIX_ERROR_NAME_CODE + 0x0000003d);
    public final static int RET_PKIX_UNSUPPORTED_PKIX_TIME                    = (PKIX_ERROR_NAME_CODE + 0x0000003e);
    public final static int RET_PKIX_CINFO_NOT_DATA                           = (PKIX_ERROR_NAME_CODE + 0x0000003f);
    public final static int RET_PKIX_CINFO_NOT_SIGNED_DATA                    = (PKIX_ERROR_NAME_CODE + 0x00000040);
    public final static int RET_PKIX_CINFO_NOT_DIGESTED_DATA                  = (PKIX_ERROR_NAME_CODE + 0x00000041);
    public final static int RET_PKIX_CINFO_NOT_ENCRYPTED_DATA                 = (PKIX_ERROR_NAME_CODE + 0x00000042);
    public final static int RET_PKIX_CINFO_NOT_ENVELOPED_DATA                 = (PKIX_ERROR_NAME_CODE + 0x00000043);
    public final static int RET_PKIX_NO_RESPONDER_ID                          = (PKIX_ERROR_NAME_CODE + 0x00000044);
    public final static int RET_PKIX_UNSUPPORTED_SIGN_ALG                     = (PKIX_ERROR_NAME_CODE + 0x00000045);
    public final static int RET_PKIX_INVALID_UTF8_STR                         = (PKIX_ERROR_NAME_CODE + 0x00000046);

    public final static int RET_PKIX_SDATA_CONTENT_NOT_DATA                   = (PKIX_ERROR_NAME_CODE + 0x00000047);
    public final static int RET_PKIX_SDATA_CONTENT_NOT_TST_INFO               = (PKIX_ERROR_NAME_CODE + 0x00000048);
    public final static int RET_PKIX_SDATA_NO_MESSAGE_DIGEST_ATTR             = (PKIX_ERROR_NAME_CODE + 0x00000049);
    public final static int RET_PKIX_SDATA_NO_SIGNERS                         = (PKIX_ERROR_NAME_CODE + 0x0000004a);
    public final static int RET_PKIX_SDATA_NO_CONTENT                         = (PKIX_ERROR_NAME_CODE + 0x0000004b);
    public final static int RET_PKIX_DIFFERENT_DIGEST_ALG                     = (PKIX_ERROR_NAME_CODE + 0x0000004c);
    public final static int RET_PKIX_DIFFERENT_SIGNER_IDENTIFIER              = (PKIX_ERROR_NAME_CODE + 0x0000004d);
    public final static int RET_PKIX_UNSUPPORTED_SPKI_ALG                     = (PKIX_ERROR_NAME_CODE + 0x0000004e);
    public final static int RET_PKIX_TSP_REQ_NO_REQ_POLICY                    = (PKIX_ERROR_NAME_CODE + 0x0000004f);
    public final static int RET_PKIX_TSP_REQ_NO_NONCE                         = (PKIX_ERROR_NAME_CODE + 0x00000050);
    public final static int RET_PKIX_TSP_RESP_NO_TS_TOKEN                     = (PKIX_ERROR_NAME_CODE + 0x00000050);
    public final static int RET_PKIX_UNSUPPORTED_DIGEST_ALG                   = (PKIX_ERROR_NAME_CODE + 0x00000051);
    public final static int RET_PKIX_UNSUPPORTED_CIPHER_ALG                   = (PKIX_ERROR_NAME_CODE + 0x00000052);
    public final static int RET_PKIX_OCSP_RESP_NO_NEXT_UPDATE                 = (PKIX_ERROR_NAME_CODE + 0x00000053);
    public final static int RET_PKIX_OCSP_RESP_NO_LAST_UPDATE                 = (PKIX_ERROR_NAME_CODE + 0x00000054);
    public final static int RET_PKIX_PUB_KEY_NOT_CORRESPOND_FOR_PRIV          = (PKIX_ERROR_NAME_CODE + 0x00000055);
    public final static int RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS       = (PKIX_ERROR_NAME_CODE + 0x00000056);
    public final static int RET_PKIX_UNSUPPORTED_FORM_OF_PUB_KEY              = (PKIX_ERROR_NAME_CODE + 0x00000057);
    public final static int RET_PKIX_SDATA_NO_CERT_V2                         = (PKIX_ERROR_NAME_CODE + 0x00000058);
    public final static int RET_PKIX_SDATA_VERIFY_CERT_V2_FAILED              = (PKIX_ERROR_NAME_CODE + 0x00000059);
    public final static int RET_PKIX_UNSUPPORTED_ISO4217_CURRENCY_CODE        = (PKIX_ERROR_NAME_CODE + 0x0000005a);
    public final static int RET_PKIX_PASSWORD_ATTEMPTS_ENDED                  = (PKIX_ERROR_NAME_CODE + 0x0000005b);
    public final static int RET_PKIX_ENVDATA_NO_CONTENT                       = (PKIX_ERROR_NAME_CODE + 0x0000005c);
    public final static int RET_PKIX_ENVDATA_NEED_ORIGINATOR_CERT             = (PKIX_ERROR_NAME_CODE + 0x0000005d);
    public final static int RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT            = (PKIX_ERROR_NAME_CODE + 0x0000005e);
    public final static int RET_PKIX_ENVDATA_WRONG_EXTERNAL_DATA              = (PKIX_ERROR_NAME_CODE + 0x0000005f);
    public final static int RET_PKIX_ENVDATA_NO_RECIPIENT                     = (PKIX_ERROR_NAME_CODE + 0x00000060);
    public final static int RET_PKIX_ENVDATA_NO_ENC_OID                       = (PKIX_ERROR_NAME_CODE + 0x00000061);
    public final static int RET_PKIX_ENVDATA_NO_PRNG                          = (PKIX_ERROR_NAME_CODE + 0x00000062);


    private final static int RET_STORAGE_ERROR_NAME_CODE          = 0x0200;

    public final static int RET_STORAGE_ERROR                                 = (RET_STORAGE_ERROR_NAME_CODE | 0x00000004);
    public final static int RET_STORAGE_INVALID_STORAGE                       = (RET_STORAGE_ERROR_NAME_CODE | 0x0000000a);
    public final static int RET_STORAGE_INVALID_PASSWORD                      = (RET_STORAGE_ERROR_NAME_CODE | 0x0000000b);
    public final static int RET_STORAGE_EMPTY_PASSWORD                        = (RET_STORAGE_ERROR_NAME_CODE | 0x0000000c);
    public final static int RET_STORAGE_CERT_NOT_FOUND                        = (RET_STORAGE_ERROR_NAME_CODE | 0x0000000d);

    public final static int RET_STORAGE_NOT_CORRESPOND_CERT_ERROR             = (RET_STORAGE_ERROR_NAME_CODE | 0x0000000f);
    public final static int RET_STORAGE_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG   = (RET_STORAGE_ERROR_NAME_CODE | 0x00000010);
    public final static int RET_STORAGE_UNSUPPORTED_CONTENT_ENC_ALG           = (RET_STORAGE_ERROR_NAME_CODE | 0x00000011);
    public final static int RET_STORAGE_UNSUPPORTED_TYPE                      = (RET_STORAGE_ERROR_NAME_CODE | 0x00000012);
    public final static int RET_STORAGE_UNSUPPORTED_CINFO_TYPE                = (RET_STORAGE_ERROR_NAME_CODE | 0x00000013);
    public final static int RET_STORAGE_UNSUPPORTED_SAFE_BAG_ALG              = (RET_STORAGE_ERROR_NAME_CODE | 0x00000014);
    public final static int RET_STORAGE_UNSUPPORTED_CERT_BAG_ALG              = (RET_STORAGE_ERROR_NAME_CODE | 0x00000015);
    public final static int RET_STORAGE_UNSUPPORTED_HMAC_ID                   = (RET_STORAGE_ERROR_NAME_CODE | 0x00000016);
    public final static int RET_STORAGE_UNSUPPORTED_ENC_PRIV_KEY_ALG          = (RET_STORAGE_ERROR_NAME_CODE | 0x00000017);
    public final static int RET_STORAGE_UNSUPPORTED_ENC_SCHEME_ALG            = (RET_STORAGE_ERROR_NAME_CODE | 0x00000018);
    public final static int RET_STORAGE_UNSUPPORTED_KDF_PARAMS_ALG            = (RET_STORAGE_ERROR_NAME_CODE | 0x00000019);
    public final static int RET_STORAGE_UNSUPPORTED_ENC_ALG                   = (RET_STORAGE_ERROR_NAME_CODE | 0x0000001a);
    public final static int RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE             = (RET_STORAGE_ERROR_NAME_CODE | 0x0000001b);
    public final static int RET_STORAGE_INVALID_KEP_KEY_ATTR                  = (RET_STORAGE_ERROR_NAME_CODE | 0x0000001c);

    public final static int RET_STORAGE_CMS_INVALID_DATA                      = (RET_STORAGE_ERROR_NAME_CODE | 0x000000c0);

    public final static int RET_STORAGE_KEY_NOT_FOUND                         = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a0);
    public final static int RET_STORAGE_BAD_KEY                               = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a1);
    public final static int RET_STORAGE_MAC_VERIFY_ERROR                      = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a2);
    public final static int RET_STORAGE_BAD_PARAMS                            = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a3);
    public final static int RET_STORAGE_INVALID_KEY_PASSWORD                  = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a4);

    public final static int RET_STORAGE_BAD_SUBJ_KEY_ID                       = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a4);
    public final static int RET_STORAGE_UNSUP_SEARCH_CERT_TYPE                = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a5);
    public final static int RET_STORAGE_INVALID_SEARCH_RESPONSE               = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a6);
    public final static int RET_STORAGE_NO_CERT_FOUND_RESPONSE                = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a7);
    public final static int RET_STORAGE_FILE_OPEN_ERROR                       = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a8);
    public final static int RET_STORAGE_FILE_READ_ERROR                       = (RET_STORAGE_ERROR_NAME_CODE | 0x000000a9);
    public final static int RET_STORAGE_FILE_WRITE_ERROR                      = (RET_STORAGE_ERROR_NAME_CODE | 0x000000aa);
    public final static int RET_STORAGE_FILE_GET_SIZE_ERROR                   = (RET_STORAGE_ERROR_NAME_CODE | 0x000000ab);
    public final static int RET_STORAGE_DIR_OPEN_ERROR                        = (RET_STORAGE_ERROR_NAME_CODE | 0x000000ac);
    public final static int RET_STORAGE_KEY_ALREADY_EXIST                     = (RET_STORAGE_ERROR_NAME_CODE | 0x000000ad);
    public final static int RET_STORAGE_UNSUPPORTED_MAC                       = (RET_STORAGE_ERROR_NAME_CODE | 0x000000ae);
    public final static int RET_STORAGE_KEY_NOT_SELECTED                      = (RET_STORAGE_ERROR_NAME_CODE | 0x000000af);

    public CryptoniteException(int code, final Exception e) {
        super(getCodeMessage(code), e);
        this.code = code;
    }

    public CryptoniteException(int code) {
        super(getCodeMessage(code));
        this.code = code;
    }

    public CryptoniteException(int code, String msg) {
        super(getCodeMessage(code) + msg);
        this.code = code;
    }

    public static String getCodeMessage(int code) {
        final String msg;

        switch(code) {
            case RET_MEMORY_ALLOC_ERROR:                               msg = "Memmory alloc error."; break;
            case RET_INVALID_PARAM:                                    msg = "Invalid argument."; break;
            case RET_VERIFY_FAILED:                                    msg = "Signature verify failed."; break;
            case RET_CONTEXT_NOT_READY:                                msg = "Context not ready."; break;
            case RET_INVALID_CTX:                                      msg = "Invalid context."; break;
            case RET_INVALID_PRIVATE_KEY:                              msg = "Invalid private key."; break;
            case RET_DSTU_PRNG_LOOPED:                                 msg = "DSTU prng looped."; break;
            case RET_INVALID_PUBLIC_KEY:                               msg = "Invalid public key."; break;
            case RET_INVALID_MODE:                                     msg = "Invalid mode."; break;
            case RET_UNSUPPORTED:                                      msg = "Unsupported."; break;
            case RET_INVALID_KEY_SIZE:                                 msg = "Invalid key size."; break;
            case RET_INVALID_IV_SIZE:                                  msg = "Invalid init vector size."; break;
            case RET_RSA_DECRYPTION_ERROR:                             msg = "Rsa decrypt error."; break;
            case RET_FILE_OPEN_ERROR:                                  msg = "Error open file."; break;
            case RET_FILE_READ_ERROR:                                  msg = "Error read file."; break;
            case RET_FILE_WRITE_ERROR:                                 msg = "Error write file."; break;
            case RET_FILE_GET_SIZE_ERROR:                              msg = "Error get file size."; break;
            case RET_DIR_OPEN_ERROR:                                   msg = "Error open dir."; break;
            case RET_ASN1_ERROR:                                       msg = "ASN1 error."; break;
            case RET_ASN1_ENCODE_ERROR:                                msg = "ASN1 encode error."; break;
            case RET_ASN1_DECODE_ERROR:                                msg = "ASN1 decode error."; break;
            case RET_PKIX_GENERAL_ERROR:                               msg = "PKIX general error."; break;
            case RET_PKIX_ATTRIBUTE_NOT_FOUND:                         msg = "Attribute not found."; break;
            case RET_PKIX_OUT_OF_BOUND_ERROR:                          msg = "Out bound array error."; break;
            case RET_PKIX_OBJ_NOT_FOUND:                               msg = "Object not found."; break;
            case RET_PKIX_CRYPTO_MANAGER_ERROR:                        msg = "Crypto-manager error."; break;
            case RET_PKIX_INITIALIZATION_ERROR:                        msg = "init error."; break;
            case RET_PKIX_INTERNAL_ERROR:                              msg = "Internal error."; break;
            case RET_PKIX_CIPHER_ERROR:                                msg = "Cipher error."; break;
            case RET_PKIX_SIGN_ERROR:                                  msg = "Sign error."; break;
            case RET_PKIX_VERIFY_FAILED:                               msg = "Verify signature failed."; break;
            case RET_PKIX_UNSUPPORTED_OID:                             msg = "Unsupported OID."; break;
            case RET_PKIX_INCORRECT_OID:                               msg = "Incorrect OID."; break;
            case RET_PKIX_UNSUPPORTED_PKIX_OBJ:                        msg = "Unsupported pkix object."; break;
            case RET_PKIX_INCORRECT_CERT_STRUCTURE:                    msg = "Certificate broken."; break;
            case RET_PKIX_NO_CERTIFICATE:                              msg = "No certificate."; break;
            case RET_PKIX_CRL_CANT_MERGE:                              msg = "Crl can not merge."; break;

            case RET_PKIX_SUBJ_NAME_UNSUPPORTED:                       msg = "Unsupported subject name element type."; break;
            case RET_PKIX_RECIPIENT_NOT_FOUND:                         msg = "Recipien not found in EnvelopedData container."; break;

            case RET_PKIX_SDATA_WRONG_CONTENT_DATA:                    msg = "Wrong content data."; break;
            case RET_PKIX_SDATA_WRONG_EXT_DATA:                        msg = "Wrong content data."; break;
            case RET_PKIX_WRONG_TSP_DATA:                              msg = "Wrong TSP data."; break;

            case RET_STORAGE_ERROR:                                    msg = "Storage error."; break;
            case RET_STORAGE_INVALID_STORAGE:                          msg = "Storage broken."; break;
            case RET_STORAGE_INVALID_PASSWORD:                         msg = "Invalid password."; break;
            case RET_STORAGE_CERT_NOT_FOUND:                           msg = "Certificate not found."; break;

//            case RET_STORAGE_NOT_CORRESPOND_CERT_ERROR:                msg = "RET_STORAGE_ERROR_NAME_CODE | 0x0000000f"; break;
//            case RET_STORAGE_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG:      msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000010"; break;
//            case RET_STORAGE_UNSUPPORTED_CONTENT_ENC_ALG:              msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000011"; break;
//            case RET_STORAGE_UNSUPPORTED_TYPE:                         msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000012"; break;
//            case RET_STORAGE_UNSUPPORTED_CINFO_TYPE:                   msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000013"; break;
//            case RET_STORAGE_UNSUPPORTED_SAFE_BAG_ALG:                 msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000014"; break;
//            case RET_STORAGE_UNSUPPORTED_CERT_BAG_ALG:                 msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000015"; break;
//            case RET_STORAGE_UNSUPPORTED_HMAC_ID:                      msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000016"; break;
//            case RET_STORAGE_UNSUPPORTED_ENC_PRIV_KEY_ALG:             msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000017"; break;
//            case RET_STORAGE_UNSUPPORTED_ENC_SCHEME_ALG:               msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000018"; break;
//            case RET_STORAGE_UNSUPPORTED_KDF_PARAMS_ALG:               msg = "RET_STORAGE_ERROR_NAME_CODE | 0x00000019"; break;
//            case RET_STORAGE_UNSUPPORTED_ENC_ALG:                      msg = "RET_STORAGE_ERROR_NAME_CODE | 0x0000001a"; break;
//            case RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE:                msg = "RET_STORAGE_ERROR_NAME_CODE | 0x0000001b"; break;
//            case RET_STORAGE_INVALID_KEP_KEY_ATTR:                     msg = "RET_STORAGE_ERROR_NAME_CODE | 0x0000001c"; break;


            case RET_STORAGE_KEY_NOT_FOUND:                              msg = "Key not found."; break;
//            case RET_STORAGE_BAD_KEY:                                  msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a1"; break;
//            case RET_STORAGE_MAC_VERIFY_ERROR:                         msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a2"; break;
//            case RET_STORAGE_BAD_PARAMS:                               msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a3"; break;
//            case RET_STORAGE_INVALID_KEY_PASSWORD:                     msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a4"; break;

         //   case RET_STORAGE_BAD_SUBJ_KEY_ID:                          msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a4"; break;
//            case RET_STORAGE_UNSUP_SEARCH_CERT_TYPE:                   msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a5"; break;
//            case RET_STORAGE_INVALID_SEARCH_RESPONSE:                  msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a6"; break;
//            case RET_STORAGE_NO_CERT_FOUND_RESPONSE:                   msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a7"; break;
//            case RET_STORAGE_FILE_OPEN_ERROR:                          msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a8"; break;
//            case RET_STORAGE_FILE_READ_ERROR:                          msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000a9"; break;
//            case RET_STORAGE_FILE_WRITE_ERROR:                         msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000aa"; break;
//            case RET_STORAGE_FILE_GET_SIZE_ERROR:                      msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000ab"; break;
//            case RET_STORAGE_DIR_OPEN_ERROR:                           msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000ac"; break;
//            case RET_STORAGE_KEY_ALREADY_EXIST:                        msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000ad"; break;
//            case RET_STORAGE_UNSUPPORTED_MAC:                          msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000ae"; break;
//            case RET_STORAGE_KEY_NOT_SELECTED:                         msg = "RET_STORAGE_ERROR_NAME_CODE | 0x000000af"; break;


            default:
                msg = "Unknown error.";
        }

        return msg + " Error(" + String.format("0x%03X", code) + ")";
    }

    public int getCode() {
        return code;
    }
}
