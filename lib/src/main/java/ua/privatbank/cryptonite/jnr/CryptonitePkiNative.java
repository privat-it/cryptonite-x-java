/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.types.size_t;
import jnr.ffi.types.u_int64_t;
import ua.privatbank.cryptonite.jnr.asn1.ANYPointer;
import ua.privatbank.cryptonite.jnr.asn1.Asn1DescriptorPointer;
import ua.privatbank.cryptonite.jnr.asn1.BIT_STRINGPointer;
import ua.privatbank.cryptonite.jnr.asn1.INTEGERPointer;
import ua.privatbank.cryptonite.jnr.asn1.OBJECT_IDENTIFIERPointer;
import ua.privatbank.cryptonite.jnr.asn1.OCTET_STRINGPointer;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.crypto.Dstu4145CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.EcdsaCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.EcdsaParamsId;
import ua.privatbank.cryptonite.jnr.crypto.Gost28147CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.OptLevelId;
import ua.privatbank.cryptonite.jnr.crypto.PrngCtxPointer;
import ua.privatbank.cryptonite.jnr.id.OidId;
import ua.privatbank.cryptonite.jnr.pkix.AdaptersMapPointer;
import ua.privatbank.cryptonite.jnr.pkix.AlgorithmIdentifierPointer;
import ua.privatbank.cryptonite.jnr.pkix.AttributePointer;
import ua.privatbank.cryptonite.jnr.pkix.AttributesPointer;
import ua.privatbank.cryptonite.jnr.pkix.BasicConstraintsPointer;
import ua.privatbank.cryptonite.jnr.pkix.CMSVersionPointer;
import ua.privatbank.cryptonite.jnr.pkix.CRLReason;
import ua.privatbank.cryptonite.jnr.pkix.CRLType;
import ua.privatbank.cryptonite.jnr.pkix.CertStorePointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificatePointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificateEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificateListPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificateListsPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificateRequestEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificateSetPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificatesPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificationRequestPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificationRequestInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.CinfoType;
import ua.privatbank.cryptonite.jnr.pkix.CipherAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.ContentInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.CrlEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.DhAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.DigestAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.DigestAlgorithmIdentifierPointer;
import ua.privatbank.cryptonite.jnr.pkix.DigestAlgorithmIdentifiersPointer;
import ua.privatbank.cryptonite.jnr.pkix.DigestedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.EncapsulatedContentInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.EncryptedContentInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.EncryptedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.EnvelopedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.EnvelopedDataEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.ExtensionPointer;
import ua.privatbank.cryptonite.jnr.pkix.ExtensionsPointer;
import ua.privatbank.cryptonite.jnr.pkix.GeneralName_PR;
import ua.privatbank.cryptonite.jnr.pkix.MessageImprintPointer;
import ua.privatbank.cryptonite.jnr.pkix.NameAttrPointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPRequestPointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPResponsePointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPResponseStatus;
import ua.privatbank.cryptonite.jnr.pkix.OcspCertStatusPointer;
import ua.privatbank.cryptonite.jnr.pkix.OcspRequestEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.OcspResponseEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.OidNumbersPointer;
import ua.privatbank.cryptonite.jnr.pkix.OriginatorInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.PKIStatusInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.Pkcs8PrivatekeyType;
import ua.privatbank.cryptonite.jnr.pkix.PrivateKeyInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.RecipientInfosPointer;
import ua.privatbank.cryptonite.jnr.pkix.ResponderIdType;
import ua.privatbank.cryptonite.jnr.pkix.ResponseBytesPointer;
import ua.privatbank.cryptonite.jnr.pkix.RevocationInfoChoicesPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignaturePointer;
import ua.privatbank.cryptonite.jnr.pkix.SignatureAlgorithmIdentifierPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignedDataEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.SignerIdentifierPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignerInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignerInfoEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.SignerInfosPointer;
import ua.privatbank.cryptonite.jnr.pkix.SubjectPublicKeyInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.TBSCertListPointer;
import ua.privatbank.cryptonite.jnr.pkix.TBSCertificatePointer;
import ua.privatbank.cryptonite.jnr.pkix.TBSRequestPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampReqPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampRespPointer;
import ua.privatbank.cryptonite.jnr.pkix.TspStatus;
import ua.privatbank.cryptonite.jnr.pkix.UnprotectedAttributesPointer;
import ua.privatbank.cryptonite.jnr.pkix.ValidityPointer;
import ua.privatbank.cryptonite.jnr.pkix.VerifyAdapterPointer;

/** interface native library. */
public interface CryptonitePkiNative {

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    AlgorithmIdentifierPointer aid_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param aid об'єкт, який видаляється, або NULL
     */
    void aid_free(AlgorithmIdentifierPointer aid);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param aid ідентифікатор параметрів алгоритму
     * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення
     *
     * @return код помилки
     */
    int aid_encode(final AlgorithmIdentifierPointer aid, PointerByReference out);

    /**
     * Ініціалізує aid з DER-представлення.
     *
     * @param aid ідентифікатор параметрів алгоритму
     * @param in  буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int aid_decode(AlgorithmIdentifierPointer aid, final ByteArrayPointer in);

    /**
     * Ініціалізує AlgorithmIdentifier з об'єктного ідентифікатора алгоритму та параметрів.
     *
     * @param aid    ідентифікатор параметрів алгоритму
     * @param oid    об'єктний ідентифікатор алгоритму
     * @param td     тип параметрів
     * @param params параметри
     *
     * @return код помилки
     */
    int aid_init(AlgorithmIdentifierPointer aid, final OBJECT_IDENTIFIERPointer oid,
        final Asn1DescriptorPointer td, Pointer params);

    /**
     * Ініціалізує AlgorithmIdentifier з об'єктного ідентифікатора алгоритму в int-ому представленні та без параметрів.
     *
     * @param aid     ідентифікатор параметрів алгоритму
     * @param oid     об'єктний ідентифікатор алгоритму в int-ому представленні
     *
     * @return код помилки
     */
    int aid_init_by_oid(AlgorithmIdentifierPointer aid, final OidNumbersPointer oid);

    /**
     * Формує AID для гешування по алгоритму ГОСТ 34311.
     *
     * @param aid AID для гешування по алгоритму ГОСТ 34311
     *
     * @return код помилки
     */
    int aid_create_gost3411(PointerByReference aid);

    /**
     * Формує AID для гешування по алгоритму ГОСТ 34311.
     * Параметри встановлюються в NULL.
     *
     * @param aid AID для гешування по алгоритму ГОСТ 34311
     *
     * @return код помилки
     */
    int aid_create_gost3411_with_null(PointerByReference aid);

    /**
     * Формує AID для гешування по алгоритму ГОСТ 34311.
     * Параметри встановлюються в NULL.
     *
     * @param aid AID для гешування по алгоритму ГОСТ 34311
     *
     * @return код помилки
     */
    int aid_create_hmac_gost3411(PointerByReference aid);

    /**
     * Формує AID для шифрування по алгоритму ГОСТ 28147.
     * Параметри встановлюються в NULL.
     *
     * @param aid AID для шифрування по алгоритму ГОСТ 28147
     *
     * @return код помилки
     */
    int aid_create_gost28147_wrap(PointerByReference aid);
    int aid_create_gost28147_cfb(PointerByReference aid);

    /**
     * Формує AID для виробки/перевірки підпису по алгоритму ДСТУ 4145.
     *
     * @param ec_params     контекст праметрів ДСТУ 4145
     * @param cipher_params котекст параметрів ГОСТ 28147
     * @param is_le         форма зберігання LE/BE
     * @param aid           AID виробки/перевірки підпису по алгоритму ДСТУ 4145
     *
     * @return код помилки
     */
    int aid_create_dstu4145(final Dstu4145CtxPointer ec_params, final Gost28147CtxPointer cipher_params, boolean is_le,
        PointerByReference aid);

    /**
     * Ініціалізує crypto параметри для ДСТУ 4145.
     *
     * @param aid ASN1 структура алгоритму
     * @param ctx буфер для crypto параметрів ДСТУ 4145
     *
     * @return код помилки
     */
    int aid_get_dstu4145_params(final AlgorithmIdentifierPointer aid, PointerByReference ctx);
    int aid_create_ecdsa_pubkey(final EcdsaParamsId param, PointerByReference aid);
    int aid_get_ecdsa_params(final AlgorithmIdentifierPointer aid, PointerByReference ctx);

    /**
     * Створює неініціалізоіваний об'єкт у випадку помилки.
     *
     * @return вказівник на створений об'єкт або NULL
     */
    CertificatePointer cert_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param cert об'єкт, який видаляється, або NULL
     */
    void cert_free(CertificatePointer cert);

    /**
     * Ініціалізує сертифікат на основі готових даних.
     *
     * @param cert сертифікат
     * @param tbs_cert інформація сертификата
     * @param aid алгоритм підпису
     * @param sign значення підпису
     *
     * @return код помилки
     */
    int cert_init_by_sign(CertificatePointer cert, final TBSCertificatePointer tbs_cert,
        final AlgorithmIdentifierPointer aid, final BIT_STRINGPointer sign);

    /**
     * Ініціалізує сертифікат з обчисленням підпису.
     *
     * @param cert сертифікат
     * @param tbs_cert інформація сертификата
     * @param adapter адаптер виробки підпису
     *
     * @return код помилки
     */
    int cert_init_by_adapter(CertificatePointer cert, final TBSCertificatePointer tbs_cert,
        final SignAdapterPointer adapter);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення
     *
     * @return код помилки
     */
    int cert_encode(final CertificatePointer cert, PointerByReference out);

    /**
     * Ініціалізує сертифікат з DER-представлення
     *
     * @param cert сертифікат
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int cert_decode(CertificatePointer cert, final ByteArrayPointer in);

    /**
     * Повертає наявність обов'язкових доповнень сертифіката, які не підтримуються.
     *
     * @param cert сертифікат
     * @param flag наявність доповнень, які не підтримуються
     *
     * @return код помилки
     */
    int cert_has_unsupported_critical_ext(final CertificatePointer cert, boolean flag);

    /**
     * Отримує перелік ідентифікаторів обов'язкових доповнень сертифіката.
     *
     * @param cert сертифікат
     * @param oids перелік ідентифікаторів або NULL
     * @param cnt кількість ідентифікаторів або NULL
     *
     * @return код помилки
     */
    int cert_get_critical_ext_oids(final CertificatePointer cert, PointerByReference oids, long cnt);

    /**
     * Отримує перелік ідентифікаторів необов'язкових доповнень сертифіката.
     *
     * @param cert сертифікат
     * @param oids перелік ідентифікаторів або NULL
     * @param cnt кількість ідентифікаторів або NULL
     *
     * @return код помилки
     */
    int cert_get_non_critical_ext_oids(final CertificatePointer cert, PointerByReference oids,
        long cnt);

    /**
     * Отримує байтове представлення доповнення по ідентифікатору.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param oid_numbers ідентифікатор
     * @param out вказівник на пам'ять, що виділяється
     *
     * @return код помилки
     */
    int cert_get_ext_value(final CertificatePointer cert, final OidNumbersPointer oid_numbers, PointerByReference out);

    /**
     * Перевіряє валідність сертифікату на поточний момент часу.
     *
     * @param cert сертифікат
     *
     * @return код помилки
     */
    int cert_check_validity(final CertificatePointer cert);

    /**
     * Перевіряє валідність сертифікату на заданий момент часу.
     *
     * @param cert сертифікат
     * @param date дата для валідації
     *
     * @return код помилки
     */
    int cert_check_validity_with_date(final CertificatePointer cert, long[] date);

    /**
     * Повертає версію сертифіката.
     *
     * @param cert сертифікат
     * @param version версія сертифіката
     *
     * @return код помилки
     */
    int cert_get_version(final CertificatePointer cert, long version);

    /**
     * Повертає 20 байтний серійний номер сертифіката.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param sn  вказівник на буфер для серійного номера
     *
     * @return код помилки
     */
    int cert_get_sn(final CertificatePointer cert, PointerByReference sn);

    /**
     * Повертає інформацію про сертифікат.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param tbs_cert інформація про сертифікат
     *
     * @return код помилки
     */
    int cert_get_tbs_cert(final CertificatePointer cert, PointerByReference tbs_cert);

    /**
     * Повертає байтове представлення в DER-кодуванні інформації про сертифікат.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int cert_get_tbs_info(final CertificatePointer cert, PointerByReference out);

    /**
     * Повертає ідентифікатор алгоритму виробки підпису.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param aid ідентифікатор алгоритму виробки підпису
     *
     * @return код помилки
     */
    int cert_get_aid(final CertificatePointer cert, PointerByReference aid);

    /**
     * Повертає байтове представлення в DER-кодуванні ЕЦП.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param sign вказівник на BIT_STRING, який містить ЕЦП.
     *
     * @return код помилки
     */
    int cert_get_sign(final CertificatePointer cert, PointerByReference sign);

    /**
     * Повертає атрибути доступу ключа.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param attr атрибути доступу ключа
     *
     * @return код помилки
     */
    int cert_get_key_usage(final CertificatePointer cert, PointerByReference attr);

    /**
     * Повертає кількість проміжних сертифікатів.
     *
     * @param cert сертифікат
     * @param cnt кількість проміжних сертифікатів, -1 якщо їх немає
     *
     * @return код помилки
     */
    int cert_get_basic_finalrains(final CertificatePointer cert, int cnt);

    /**
     * Перевіряє, чи належить даний сертифікат OCSP серверу.
     * Сертифікат OCSP сервера  повинен мати розширення ExtendedKeyUsage,
     * в якому міститься єдиний OID 1.3.6.1.5.5.7.3.9.
     *
     * @param cert сертифікат
     * @param flag true - якщо сертифікат належить OCSP серверу
     *
     * @return код помилки
     */
    int cert_is_ocsp_cert(final CertificatePointer cert, boolean flag);

    /**
     * Виконує перевірку сертифіката.
     *
     * @param cert сертифікат
     * @param adapter адаптер перевірки підпису
     *
     * @return код помилки
     */
    int cert_verify(final CertificatePointer cert, final VerifyAdapterPointer adapter);

    /**
     * Повертає SubjectPublicKeyInfo.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cert сертифікат
     * @param spki вказівник на структуру SubjectPublicKeyInfo
     *
     * @return код помилки
     */
    int cert_get_spki(final CertificatePointer cert, PointerByReference spki);
    boolean cert_check_sid(final CertificatePointer certificate, final SignerIdentifierPointer sid);
    int cert_get_subj_key_id(final CertificatePointer cert, PointerByReference subj_key_id);
    int cert_get_auth_key_id(final CertificatePointer cert, PointerByReference auth_key_id);
    int cert_get_qc_statement_limit(final CertificatePointer cert, PointerByReference currency_code, long amount,
        long exponent);
    boolean cert_check_validity_encode(final ByteArrayPointer cert);
    int cert_check_pubkey_and_usage(final CertificatePointer cert, final ByteArrayPointer pub_key, int key_usage,
        boolean flag);
    int cert_get_tsp_url(final CertificatePointer cert, PointerByReference data);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    CertificationRequestPointer creq_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param creq об'єкт, який видаляється, або NULL
     */
    void creq_free(CertificationRequestPointer creq);

    /**
     * Ініціалізує запит сертифіката з заданим підписом.
     *
     * @param creq запит сертифіката
     * @param info інформація на запит сертифіката
     * @param aid ідентифікатор алгоритму підпису
     * @param sign значення підпису
     *
     * @return код помилки
     */
    int creq_init_by_sign(CertificationRequestPointer creq, final CertificationRequestInfoPointer info,
        final AlgorithmIdentifierPointer aid, final BIT_STRINGPointer sign);

    /**
     * Ініціалізує запит сертифіката з обчисленням підпису.
     *
     * @param creq запит сертифіката
     * @param info інформація на запит сертифіката
     * @param adapter адаптер генерації підпису
     *
     * @return код помилки
     */
    int creq_init_by_adapter(CertificationRequestPointer creq, final CertificationRequestInfoPointer info,
        final SignAdapterPointer adapter);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять повинна бути вивільнена.
     *
     * @param creq запит сертифіката
     * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int creq_encode(final CertificationRequestPointer creq, PointerByReference out);

    /**
     * Ініціалізує запит сертифіката з DER-представлення.
     *
     * @param creq запит сертифіката
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int creq_decode(CertificationRequestPointer creq, final ByteArrayPointer in);

    /**
     * Повертає об'єкт інформації запиту сертифіката.
     * Виділена пам'ять повинна бути вивільнена.
     *
     * @param creq запит сертифіката
     * @param info об'єкт інформації запиту сертифіката, який створюється
     *
     * @return код помилки
     */
    int creq_get_info(final CertificationRequestPointer creq, PointerByReference info);

    /**
     * Повертає ідентифікатор алгоритму підпису під запитом сертифіката.
     * Виділена пам'ять повинна бути вивільнена.
     *
     * @param creq запит сертифіката
     * @param aid  об'єкт ідентифікатора алгоритма, який створюється
     *
     * @return код помилки
     */
    int creq_get_aid(final CertificationRequestPointer creq, PointerByReference aid);

    /**
     * Повертає значення підпису запиту сертифіката.
     * Виділена пам'ять повинна бути вивільнена.
     *
     * @param creq запит сертифіката
     * @param sign об'єкт підпису запиту сертифіката, який створюєтья
     *
     * @return код помилки
     */
    int creq_get_sign(final CertificationRequestPointer creq, PointerByReference sign);

    /**
     * Верифікує підпис запиту сертифіката.
     *
     * @param creq запит сертифіката
     * @param adapter адаптер для перевірки підпису
     *
     * @return код помилки
     */
    int creq_verify(final CertificationRequestPointer creq, VerifyAdapterPointer adapter);
    int creq_get_attributes(final CertificationRequestPointer req, PointerByReference ext);

    /**
     * Створює розширення атрибутів.
     *
     * @param req запит сертифікату
     * @param oid_numbers oid
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int creq_get_ext_by_oid(final CertificationRequestPointer req, final OidNumbersPointer oid_numbers,
        PointerByReference ext);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    ContentInfoPointer cinfo_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param cinfo об'єкт, який видаляється або NULL
     */
    void cinfo_free(ContentInfoPointer cinfo);

    /**
     * Ініціалізує контейнер контейнером підписаних даних.
     *
     * @param cinfo контейнер даних
     * @param sdata контейнер підписаних даних
     *
     * @return код помилки
     */
    int cinfo_init_by_signed_data(ContentInfoPointer cinfo, final SignedDataPointer sdata);

    /**
     * Ініціалізує контейнер контейнером гешованих даних.
     *
     * @param cinfo контейнер даних
     * @param ddata контейнер гешованих даних
     *
     * @return код помилки
     */
    int cinfo_init_by_digest_data(ContentInfoPointer cinfo, final DigestedDataPointer ddata);

    /**
     * Ініціалізує контейнер контейнером шифрованих даних.
     *
     * @param cinfo контейнер даних
     * @param encr_data контейнер шифрованих даних
     *
     * @return код помилки
     */
    int cinfo_init_by_encrypted_data(ContentInfoPointer cinfo, final EncryptedDataPointer encr_data);

    /**
     * Ініціалізує контейнер даних.
     *
     * @param cinfo контейнер даних
     * @param data дані
     *
     * @return код помилки
     */
    int cinfo_init_by_data(ContentInfoPointer cinfo, final ByteArrayPointer data);

    /**
     * Ініціалізує контейнер контейнером захищених даних.
     *
     * @param cinfo контейнер даних
     * @param env_data контейнер захищених даних
     *
     * @return код помилки
     */
    int cinfo_init_by_enveloped_data(ContentInfoPointer cinfo, final EnvelopedDataPointer env_data);

    /**
     * Ініціалізує контейнер з заданням типу контейнера.
     *
     * @param cinfo контейнер даних
     * @param ctype тип контейнера
     * @param content дані
     *
     * @return код помилки
     */
    int cinfo_init_by_any_content(ContentInfoPointer cinfo, final CinfoType ctype, final ANYPointer content);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cinfo контейнер даних
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int cinfo_encode(final ContentInfoPointer cinfo, PointerByReference out);

    /**
     * Ініціалізує  ContentInfo з DER-представлення.
     *
     * @param cinfo контейнер даних
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int cinfo_decode(ContentInfoPointer cinfo, final ByteArrayPointer in);

    /**
     * Перевіряє, чи наявні дані.
     *
     * @param cinfo контейнер даних
     * @param flag прапорець наявності даних в контейнері
     *
     * @return код помилки
     */
    int cinfo_has_content(final ContentInfoPointer cinfo, boolean flag);

    /**
     * Повертає контейнер даних.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cinfo контейнер даних
     * @param data створюваний об'єкт контейнера даних
     *
     * @return код помилки
     */
    int cinfo_get_data(final ContentInfoPointer cinfo, PointerByReference data);

    /**
     * Повертає контейнер підписаних даних.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cinfo контейнер даних
     * @param sdata створюваний об'єкт контейнера підписаних даних
     *
     * @return код помилки
     */
    int cinfo_get_signed_data(final ContentInfoPointer cinfo, PointerByReference sdata);

    /**
     * Повертає контейнер гешованих даних.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cinfo контейнер даних
     * @param ddata створюваний об'єкт контейнера гешованих даних
     *
     * @return код помилки
     */
    int cinfo_get_digested_data(final ContentInfoPointer cinfo, PointerByReference ddata);

    /**
     * Повертає контейнер шифрованих даних.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cinfo контейнер даних
     * @param encr_data створюваний об'єкт контейнера шифрованих даних
     *
     * @return код помилки
     */
    int cinfo_get_encrypted_data(final ContentInfoPointer cinfo, PointerByReference encr_data);

    /**
     * Повертає контейнер захищених даних.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cinfo контейнер даних
     * @param env_data створюваний об'єкт контейнера захищених даних
     *
     * @return код помилки
     */
    int cinfo_get_enveloped_data(final ContentInfoPointer cinfo, PointerByReference env_data);

    /**
     * Повертає контейнер даних та його тип.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param cinfo контейнер даних
     * @param ctype створюваний об'єкт типу контейнера
     * @param content створюваний об'єкт контейнера даних
     *
     * @return код помилки
     */
    int cinfo_get_any_content(final ContentInfoPointer cinfo, PointerByReference ctype, PointerByReference content);

    /**
     * Повертає тип контейнера.
     *
     * @param cinfo контейнер даних
     * @param type тип контейнера
     *
     * @return код помилки
     */
    int cinfo_get_type(final ContentInfoPointer cinfo, CinfoType type);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    CertificateListPointer crl_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param crl об'єкт, який видаляється, або NULL
     */
    void crl_free(CertificateListPointer crl);

    /**
     * Ініціалізує CRL з заданим підписом.
     *
     * @param crl CRL
     * @param tbs_crl інформація про CRL
     * @param aid ідентифікатор алгоритму підпису
     * @param sign значення підпису
     *
     * @return код помилки
     */
    int crl_init_by_sign(CertificateListPointer crl, final TBSCertListPointer tbs_crl,
        final AlgorithmIdentifierPointer aid, final BIT_STRINGPointer sign);

    /**
     * Ініціалізує CRL з обчисленням підпису.
     *
     * @param crl CRL
     * @param tbs_crl інформація о CRL
     * @param adapter адаптер генерації підпису
     *
     * @return код помилки
     */
    int crl_init_by_adapter(CertificateListPointer crl, final TBSCertListPointer tbs_crl,
        final SignAdapterPointer adapter);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param crl CRL
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int crl_encode(final CertificateListPointer crl, PointerByReference out);

    /**
     * Ініціалізує CRL з DER-представлення.
     *
     * @param crl CRL
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int crl_decode(CertificateListPointer crl, final ByteArrayPointer in);

    /**
     * Повертає інформацію про CRL.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param crl CRL
     * @param tbs_crl створюваний об'єкт інформації про CRL
     *
     * @return код помилки
     */
    int crl_get_tbs(final CertificateListPointer crl, PointerByReference tbs_crl);

    /**
     * Встановлює інформацію про CRL.
     *
     * @param crl CRL
     * @param tbs_crl інформація про CRL
     *
     * @return код помилки
     */
    int crl_set_tbs(CertificateListPointer crl, final TBSCertListPointer tbs_crl);

    /**
     * Повертає ідентифікатор алгоритму підпису.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param crl CRL
     * @param aid створюваний об'єкт алгоритму підпису
     *
     * @return код помилки
     */
    int crl_get_sign_aid(final CertificateListPointer crl, PointerByReference aid);

    /**
     * Встановлює алгоритм підпису контейнера.
     *
     * @param crl CRL
     * @param aid алгоритм підпису
     *
     * @return код помилки
     */
    int crl_set_sign_aid(CertificateListPointer crl, final AlgorithmIdentifierPointer aid);

    /**
     * Повертає значення підпису.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param crl CRL
     * @param sign створюваний об'єкт підпису CRL
     *
     * @return код помилки
     */
    int crl_get_sign(final CertificateListPointer crl, PointerByReference sign);

    /**
     * Встановлює алгоритм підпису контейнера.
     *
     * @param crl CRL
     * @param sign підпис CRL
     *
     * @return код помилки
     */
    int crl_set_sign(CertificateListPointer crl, final BIT_STRINGPointer sign);

    /**
     * Перевіряє, чи наявний даний сертифікат в переліку відкликаних сертифікатов.
     *
     * @param crl CRL
     * @param cert перевіряємий сертифікат
     * @param flag прапорець наявності сертифіката в CRL
     *
     * @return код помилки
     */
    int crl_check_cert(final CertificateListPointer crl, final CertificatePointer cert, boolean flag);

    /**
     * Повертає інформацію про відкликаний сертифікат по вихідному сертифікату.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param crl CRL
     * @param cert перевіряємий сертифікат
     * @param rc створюваний об'єкт інформації про відкликаний сертифікат
     *
     * @return код помилки
     */
    int crl_get_cert_info(final CertificateListPointer crl, final CertificatePointer cert,
        PointerByReference rc);

    /**
     * Повертає інформацію про відкликаний сертифікат по серійному номеру сертифіката.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param crl CRL
     * @param cert_sn серійный номер сертифіката
     * @param rc створюваний об'єкт інформації про відкликаний сертифікат або NULL
     *
     * @return код помилки
     */
    int crl_get_cert_info_by_sn(final CertificateListPointer crl, final INTEGERPointer cert_sn,
        PointerByReference rc);

    /**
     * Перевіряє, чи відноситься даний CRL до повних.
     *
     * @param crl CRL
     * @param flag правпорець приналежності CRL до повних
     *
     * @return код помилки
     */
    int crl_is_full(final CertificateListPointer crl, boolean flag);

    /**
     * Перевіряє, чи відноситься даний CRL до часткових.
     *
     * @param crl CRL
     * @param flag прапорець приналежності CRL до часткових
     *
     * @return код помилки
     */
    int crl_is_delta(final CertificateListPointer crl, boolean flag);

    /**
     * Верифікує підпис CRL.
     *
     * @param crl CRL
     * @param adapter адаптер для перевірки підпису
     *
     * @return код помилки
     */
    int crl_verify(final CertificateListPointer crl, final VerifyAdapterPointer adapter);
    int crl_get_crl_number(final CertificateListPointer crl, PointerByReference crl_number);
    int crl_get_distribution_points(final CertificateListPointer crl, PointerByReference url, long url_len);
    int crl_get_this_update(final CertificateListPointer crl, long[] this_update);

    /**
     * Створює неініціалізований контейнер.
     *
     * @return вказівник на створений контейнер підпису або NULL у випадку помилки
     */
    EnvelopedDataPointer env_data_alloc();

    /**
     * Вивільняє пам'ять, яку займає контейнер.
     *
     * @param env_data контейнер підпису, який видаляється, або NULL
     */
    void env_data_free(EnvelopedDataPointer env_data);

    /**
     * Ініціалізує контейнер на основі готових даних.
     *
     * @param env_data буфер для контейнера
     * @param version    версія контейнера
     * @param originator інформація про автора
     * @param recipient  інформація про отримувача
     * @param content    контент, який шифрується
     * @param attrs атрибути
     *
     * @return код помилки
     */
    int env_data_init(EnvelopedDataPointer env_data, final CMSVersionPointer version,
        final OriginatorInfoPointer originator, final RecipientInfosPointer recipient, final EncryptedContentInfoPointer content,
        final UnprotectedAttributesPointer attrs);

    /**
     * Повертає байтове представлення контейнера в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param env_data контейнер
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int env_data_encode(final EnvelopedDataPointer env_data, PointerByReference out);

    /**
     * Ініціалізує контейнер з DER-представлення.
     *
     * @param env_data контейнер
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int env_data_decode(EnvelopedDataPointer env_data, final ByteArrayPointer in);

    /**
     * Перевіряє наявність сертифіката автора контейнера.
     *
     * @param env_data контейнер
     * @param flag прапорець наявності сертифіката
     *
     * @return код помилки
     */
    int env_data_has_originator_cert(final EnvelopedDataPointer env_data, boolean flag);

    /**
     * Повертає сертифікат автора контейнера.
     *
     * @param env_data        контейнер
     * @param originator_cert сертифікат
     *
     * @return код помилки
     */
    int env_data_get_originator_cert(final EnvelopedDataPointer env_data, PointerByReference originator_cert);

    /**
     * Повертає відкритий ключ автора контейнера.
     *
     * @param env_data           контейнер
     * @param originator_cert    сертифікат
     * @param originator_pub_key відкритий ключ
     *
     * @return код помилки
     */
    int env_data_get_originator_public_key(final EnvelopedDataPointer env_data,
        final CertificatePointer originator_cert, PointerByReference originator_pub_key);

    /**
     * Повертає ідентифікатор алгоритму шифрування контейнера.
     *
     * @param env_data контейнер
     * @param encr_aid ідентифікатор алгоритму
     *
     * @return код помилки
     */
    int env_get_content_encryption_aid(final EnvelopedDataPointer env_data, PointerByReference encr_aid);

    int env_decrypt_data(final EnvelopedDataPointer env_data, final ByteArrayPointer enc_data_opt,
        final CertificatePointer originator_cert_opt, final DhAdapterPointer recipient_dha, final CertificatePointer recipient_cert,
        PointerByReference out);

    /**
     * Створює розширення по безпосередньому значенню.
     *
     * @param critical прапорець критичності розширення
     * @param oid OID розширення
     * @param value значення розширення
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_any(boolean critical, OidNumbersPointer oid, final ByteArrayPointer value, PointerByReference ext);

    /**
     * Створює розширення ідентифікатора ключа підписчика.
     *
     * @param critical прапорець критичності розширення
     * @param issuer_cert сертифікат підписчика
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_auth_key_id_from_cert(boolean critical, final CertificatePointer issuer_cert,
        PointerByReference ext);

    /**
     * Створює розширення ідентифікатора ключа підписчика.
     * Використовується для самопідписуємого сертифікату.
     *
     * @param critical прапорець критичності розширення
     * @param spki публічний ключ суб'єкта
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_auth_key_id_from_spki(boolean critical, final SubjectPublicKeyInfoPointer spki,
        PointerByReference ext);

    /**
     * Створює розширення про доступ до інформації про центри сертифікації.
     *
     * @param critical прапорець критичності розширення
     * @param oids масив OID'ов опису доступу
     * @param name_uris масив uri, які містять відомості про центри сертифікації
     * @param cnt кількість елементів в масивах oids, name_uris
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_auth_info_access(boolean critical, PointerByReference oids, final String name_uris, int cnt,
        PointerByReference ext);

    /**
     * Створює розширення основних обмежень.
     *
     * @param critical прапорець критичності розширення
     * @param issuer об'єкт розширення, який належить стороні, яка підписує, або NULL
     * @param ca прапорець УЦ, якщо true - публічний ключ сертифікату належить УЦ
     * @param path_len_finalraint максимальна кількість проміжних сертифікатів
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_basic_constraints(boolean critical, final BasicConstraintsPointer issuer, boolean ca,
        int path_len_finalraint, PointerByReference ext);

    /**
     * Створює розширення політики сертифікатів.
     *
     * @param critical прапорець критичності розширення
     * @param oids масив OID'ів, які визначають політики сертифікату
     * @param cnt кількість елементів в масиві oids
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_cert_policies(boolean critical, PointerByReference oids, int cnt, PointerByReference ext);

    /**
     * Створює розширення точок розповсюдження CRL.
     *
     * @param critical прапорець критичності розширення
     * @param point_uris масив uri для точок розповсюдження
     * @param cnt кількість елементів в масиві point_uris
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_crl_distr_points(boolean critical, final String point_uris, int cnt, PointerByReference ext);

    /**
     * Створює розширення ідентифікатору CRL(CrlID).
     *
     * @param critical прапорець критичності розширення
     * @param distr_url якщо != NULL, розміщує відповідний елемент в розширенні
     * @param crl_number якщо != NULL, розміщує відповідний елемент в розширенні
     * @param crl_time якщо != NULL, розміщує відповідний елемент в розширенні
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_crl_id(boolean critical, String distr_url, ByteArrayPointer crl_number, long[] crl_time,
        PointerByReference ext);

    /**
     * Створює розширення серійного номеру.
     *
     * @param critical прапорець критичності розширення
     * @param crl_sn серійний номер
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_crl_number(boolean critical, final ByteArrayPointer crl_sn, PointerByReference ext);

    /**
     * Створює розширення причини відклику сертифікату.
     *
     * @param critical прапорець критичності розширення
     * @param reason причина відклику, перерахування типу e_CRLReason
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_crl_reason(boolean critical, final CRLReason reason, PointerByReference ext);

    /**
     * Створює розширення серійного номеру повного CRL.
     *
     * @param critical прапорець критичності розширення
     * @param crl_number серійний номер батьківського CRL
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_delta_crl_indicator(boolean critical, final ByteArrayPointer crl_number, PointerByReference ext);

    /**
     * Створює розширення поліпшеного ключа.
     *
     * @param critical прапорець критичності розширення
     * @param oids масив OID'ів призначення ключа
     * @param cnt кількість елементів в масиві oids
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_ext_key_usage(boolean critical, PointerByReference oids, int cnt, PointerByReference ext);

    /**
     * Створює розширення новітнього CRL.
     *
     * @param critical прапорець критичності розширення
     * @param point_uris масив uri для точок розповсюдження
     * @param cnt кількість елеметів в масиві point_uris
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_freshest_crl(boolean critical, final String point_uris, int cnt, PointerByReference ext);

    /**
     * Створює розширення часу компрометації ключа.
     *
     * @param critical прапорець критичності розширення
     * @param date час компрометації ключа
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_invalidity_date(boolean critical, final long[] date, PointerByReference ext);

    /**
     * Створює розширення використання ключа.
     *
     * @param critical прапорець критичності розширення
     * @param usage_bits параметри використання ключа (бітова маска з перерахування типу key_usage_t)
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_key_usage(boolean critical, int usage_bits, PointerByReference ext);

    /**
     * Створює розширення періоду використання ключа.
     * Якщо вказаний термін дії сертифікату, то він має пріоритет над
     * часом початку та закінчення дії ключа.
     *
     * @param critical прапорець критичності розширення
     * @param validity термін дії сертифікату або NULL
     * @param not_before термін початку використання ключа або NULL
     * @param not_after термін закінчення використання ключа або NULL
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_private_key_usage(boolean critical, final ValidityPointer validity, final long[] not_before,
        final long[] not_after, PointerByReference ext);
    int ext_create_qc_statement_compliance(PointerByReference qc_statement);
    int ext_create_qc_statement_limit_value(final String currency_code, long amount, long exponent,
        PointerByReference out);

    /**
     * Створює розширення декларації перевірених сертифікатів.
     *
     * @param critical прапорець критичності розширення
     * @param qc_statements масив опціональних додаткових параметрів
     * @param cnt кількість елементів в масивах qc_statements та params
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_qc_statements(boolean critical, PointerByReference qc_statements, long cnt,
        PointerByReference ext);

    /**
     * Створює розширення альтернативного імені суб'єкта по безпосереднім значенням.
     *
     * @param critical прапорець критичності розширення
     * @param types типи імен
     * @param names масив рядків (імена)
     * @param cnt кількість елементів в масивах types та names
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_subj_alt_name_directly(boolean critical,  GeneralName_PR types, final String names,
        int cnt, PointerByReference ext);

    /**
     * Створює розширення атрибутів.
     *
     * @param critical прапорець критичності розширення
     * @param subject_attr розширення
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_subj_dir_attr_directly(boolean critical, final String subject_attr, PointerByReference ext);

    /**
     * Створює розширення "Отримувач сертифікату доступу до інформації".
     *
     * @param critical прапорець критичності розширення
     * @param oids масив OID'ів опису доступу
     * @param name_uris масив uri, які містять відомості про розташування доступу
     * @param cnt кількість елементів в масивах oids, name_uris
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_subj_info_access(boolean critical, PointerByReference oids, final String name_uris, int cnt,
        PointerByReference ext);

    /**
     * Створює розширення ідентифікатору ключа суб'єкта.
     *
     * @param critical прапорець критичності розширення
     * @param spki публічний ключ суб'єкта
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_subj_key_id(boolean critical, final SubjectPublicKeyInfoPointer spki, PointerByReference ext);

    /**
     * Створює розширення Nonce.
     *
     * @param critical прапорець критичності розширення
     * @param rnd_bts випадкові байти
     * @param ext вказівник на створюване розширення
     *
     * @return код помилки
     */
    int ext_create_nonce(boolean critical, final ByteArrayPointer rnd_bts, PointerByReference ext);
    int ext_get_value(final ExtensionPointer ext, PointerByReference value);

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param ext об'єкт, який видаляється, або NULL
     */
    void ext_free(ExtensionPointer ext);

    /**
     * Створює порожній список розширень.
     *
     * @return порожній список розширень
     */
    ExtensionsPointer exts_alloc();

    /**
     * Додає розширення в список розширень.
     *
     * @param exts список розширень
     * @param ext розширення, яке додається
     *
     * @return код помилки
     */
    int exts_add_extension(ExtensionsPointer exts, final ExtensionPointer ext);

    /**
     * Отримує розширення по заданому oid.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param exts вказівник на список розширень
     * @param oid oid-структура
     * @param ext шукане розширення
     *
     * @return код помилки
     */
    int exts_get_ext_by_oid(final ExtensionsPointer exts, final OidNumbersPointer oid, PointerByReference ext);

    /**
     * Отримує вказівник на значення шуканого розширення по заданому oid.
     *
     * @param exts вказівник на список розширень
     * @param oid oid-структура
     * @param value значення розширення по заданому oid або NULL
     *
     * @return код помилки або RET_EXT_NOT_FOUND, якщо шукане розширення не знайдено
     */
    int exts_get_ext_value_by_oid(final ExtensionsPointer exts, final OidNumbersPointer oid, PointerByReference value);

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param exts об'єкт, який видаляється, або NULL
     */
    void exts_free(ExtensionsPointer exts);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    OCSPRequestPointer ocspreq_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param ocspreq об'єкт, який видаляється, або NULL
     */
    void ocspreq_free(OCSPRequestPointer ocspreq);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ocspreq OCSP (запит)
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int ocspreq_encode(final OCSPRequestPointer ocspreq, PointerByReference out);

    /**
     * Ініціалізує OCSP запит з DER-представлення.
     *
     * @param ocspreq OCSP запит
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int ocspreq_decode(OCSPRequestPointer ocspreq, final ByteArrayPointer in);

    /**
     * Повертає інформацію запита.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ocspreq OCSP запит
     * @param tbsreq створюваний об'єкт запита TBS
     *
     * @return код помилки
     */
    int ocspreq_get_tbsreq(final OCSPRequestPointer ocspreq, PointerByReference tbsreq);

    /**
     * Встановлює інформацію запита.
     *
     * @param ocspreq OCSP запит
     * @param tbsreq запит TBS
     *
     * @return код помилки
     */
    int ocspreq_set_tbsreq(OCSPRequestPointer ocspreq, final TBSRequestPointer tbsreq);

    /**
     * Повертає опціональний підпис.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ocspreq OCSP запит
     * @param sign створюваний об'єкт підпису або NULL
     *
     * @return код помилки
     */
    int ocspreq_get_sign(final OCSPRequestPointer ocspreq, PointerByReference sign);

    /**
     * Встановлює опціональний підпис.
     *
     * @param ocspreq OCSP запит
     * @param sign опціональний підпис
     *
     * @return код помилки
     */
    int ocspreq_set_sign(OCSPRequestPointer ocspreq, final SignaturePointer sign);

    /**
     * Визначає наявність підпису запита.
     *
     * @param ocspreq OCSP запит
     * @param has_sign прапорець наявності підпису запита
     *
     * @return код помилки
     */
    int ocspreq_has_sign(final OCSPRequestPointer ocspreq, boolean has_sign);

    /**
     * Виконує перевірку підпису запита.
     *
     * @param ocspreq запит
     * @param adapter адаптер перевірки підпису
     *
     * @return код помилки
     */
    int ocspreq_verify(final OCSPRequestPointer ocspreq, final VerifyAdapterPointer adapter);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    OCSPResponsePointer ocspresp_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param ocspresp об'єкт, який видаляється, або NULL
     */
    void ocspresp_free(OCSPResponsePointer ocspresp);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ocspresp OCSP (відповідь)
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int ocspresp_encode(final OCSPResponsePointer ocspresp, PointerByReference out);

    /**
     * Ініціалізує OCSP (відповідь) з DER-представлення.
     *
     * @param ocspresp OCSP (відповідь)
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int ocspresp_decode(OCSPResponsePointer ocspresp, final ByteArrayPointer in);

    /**
     * Повертає статус відповіді.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ocspresp OCSP (відповідь)
     * @param status створюваний об'єкт статусу відповіді
     *
     * @return код помилки
     */
    int ocspresp_get_status(final OCSPResponsePointer ocspresp, PointerByReference status);

    /**
     * Встановлює статус відповіді.
     *
     * @param ocspresp OCSP (відповідь)
     * @param status статус відповіді
     *
     * @return код помилки
     */
    int ocspresp_set_status(OCSPResponsePointer ocspresp, final OCSPResponseStatus status);

    /**
     * Повертає інформацію відповіді.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ocspresp OCSP (відповідь)
     * @param resp_bytes створюваний об'єкт інформації відповіді
     *
     * @return код помилки
     */
    int ocspresp_get_response_bytes(final OCSPResponsePointer ocspresp, PointerByReference resp_bytes);

    /**
     * Встановлює інформацію відповіді.
     *
     * @param ocspresp OCSP (відповідь)
     * @param resp_bytes інформація відповіді
     *
     * @return код помилки
     */
    int ocspresp_set_response_bytes(OCSPResponsePointer ocspresp, final ResponseBytesPointer resp_bytes);
    int ocspresp_get_certs(final OCSPResponsePointer ocspresp, PointerByReference certs, int certs_len);
    int ocspresp_get_responder_id(final OCSPResponsePointer ocspresp, PointerByReference responderID);
    int ocspresp_get_certs_status(final OCSPResponsePointer ocspresp, PointerByReference ocsp_cert_statuses,
        int ocsp_cert_statuses_len);
    void ocspresp_certs_status_free(OcspCertStatusPointer ocsp_cert_statuses);

    /**
     * Виконує перевірку підпису відповіді.
     *
     * @param ocspresp відповідь
     * @param adapter адаптер перевірки підпису
     *
     * @return код помилки
     */
    int ocspresp_verify(final OCSPResponsePointer ocspresp, VerifyAdapterPointer adapter);

    OidNumbersPointer oids_get_supported_extention(int ind);
    NameAttrPointer oids_get_supported_name_attr(int ind);
    OidNumbersPointer oids_get_oid_numbers_by_id(OidId oid_id);
    OidNumbersPointer oids_get_oid_numbers_by_oid(final OBJECT_IDENTIFIERPointer oid);
    OidNumbersPointer oids_get_oid_numbers_by_str(final String oid);
    void oids_oid_numbers_free(OidNumbersPointer oid);
    OBJECT_IDENTIFIERPointer oids_get_oid_by_id(OidId oid_id);

    void certs_free(PointerByReference certs);
    int get_cert_set_from_cert_array(final PointerByReference certs, PointerByReference certs_set);
    int get_cert_by_sid_and_usage(final SignerIdentifierPointer sid, int key_usage,
        final CertificateSetPointer certs, PointerByReference cert);
    int get_cert_by_usage(int key_usage, final PointerByReference certs, PointerByReference cert);
    ByteArrayPointer get_encoded_tbs_from_tbs(TBSCertificatePointer tbs);

    /**
     * Обгортує підпис в BIT_STRING у форматі, який відповідає заданому алгоритму.
     *
     * @param sign значення підпису, отримане з адаптера
     * @param aid алгоритм підпису
     * @param sign_bitstring BIT_STRING підпису, який ініціалізується
     *
     * @return код помилки
     */
    int sign_ba_to_bs(final ByteArrayPointer sign, final AlgorithmIdentifierPointer aid,
        BIT_STRINGPointer sign_bitstring);

    /**
     * Обгортує підпис в OCTET_STRING у форматі, який відповідає заданому алгоритму.
     *
     * @param sign       значення підпису, отримане з адаптера
     * @param aid        алгоритм підпису
     * @param sign_octet OCTET_STRING підпису, який ініціалізується
     *
     * @return код помилки
     */
    int sign_ba_to_os(final ByteArrayPointer sign, final AlgorithmIdentifierPointer aid,
        PointerByReference sign_octet);

    /**
     * Розгортує підпис з BIT_STRING в байтовий масив.
     *
     * @param sign_bitstring BIT_STRING підпису
     * @param aid алгоритм підпису
     * @param sign значення підпису в байтовому представленні
     *
     * @return код помилки
     */
    int sign_bs_to_ba(final BIT_STRINGPointer sign_bitstring, final AlgorithmIdentifierPointer aid,
        PointerByReference sign);

    /**
     * Розгортує підпис з OCTET_STRING в байтовий масив.
     *
     * @param sign_os  OCTET_STRING підпису
     * @param aid      алгоритм підпису
     * @param sign     значення підпису в байтовому представленні
     *
     * @return код помилки
     */
    int sign_os_to_ba(final OCTET_STRINGPointer sign_os, final AlgorithmIdentifierPointer aid, PointerByReference sign);

    /**
     * Конвертує відкритий ключ з ASN1Bitstring в байтове little-endian представлення.
     * Підтримується ДСТУ 4145.
     *
     * @param signature_oid алгоритм підпису
     * @param pub_key_asn відкритий ключ у форматі BIT STRING з сертифіката
     * @param pub_key_ba буфер для зберігання байтового представлення відкритого ключа
     *
     * @return код помилки
     */
    int convert_pub_key_bs_to_ba(final OBJECT_IDENTIFIERPointer signature_oid,
        final BIT_STRINGPointer pub_key_asn, PointerByReference pub_key_ba);

    /**
     * Конвертує відкритий ключ з байтового little-endian представлення в ASN1Bitstring.
     *
     * (*out_pub_key_bs == NULL) - пам'ять під відповідь виділяється та потребує подальшого вивільнення.
     * (*out_pub_key_bs != NULL) - якщо пам'ять під повертаємий об'єкт вже виділена.
     *
     * @param signature_oid  алгоритм підпису
     * @param pub_key        байтове значення відкритого ключа в little-endian представленні
     * @param out_pub_key_bs представлення відкритого ключа
     *
     * @return код помилки
     */
    int convert_pubkey_bytes_to_bitstring(final OBJECT_IDENTIFIERPointer signature_oid,
        final ByteArrayPointer pub_key, PointerByReference out_pub_key_bs);

    /**
     * та повертає масиви строк зі значеннями ключів та значень.
     *
     * @param str строка
     * @param keys вказівник для ключів
     * @param values вказівник для значень
     * @param count кількість пар ключ-значення
     *
     * @return код помилки
     */
    int parse_key_value(final String str, PointerByReference keys, PointerByReference values, long count);

    /**
     * Створює об'єкт Attribute по заданим значенням.
     *
     * @param attr об'єкт атрибута
     * @param oid об'єктний ідентифікатор
     * @param descriptor дескриптор типу даних
     * @param value дані
     *
     * @return код помилки
     */
    int init_attr(PointerByReference attr, final OidNumbersPointer oid, Asn1DescriptorPointer descriptor, Pointer value);

    /**
     * Знаходить атрибут по OIDу.
     *
     * @param attrs набір атрибутів
     * @param oid ідентифікатор шуканого атрибута
     * @param attr буфер для знайденого атрибута
     *
     * @return код помилки
     */
    int get_attr_by_oid(final AttributesPointer attrs, final OBJECT_IDENTIFIERPointer oid, PointerByReference attr);

    /**
     * Перевіряє представлення параметрів ДСТУ 4145.
     *
     * @param oid           перевіряємий OID
     * @return true  - little-endian
     *         false - інше
     */
    boolean is_dstu_le_params(final OBJECT_IDENTIFIERPointer oid);

    /**
     * Перевіряє представлення параметрів ДСТУ 4145.
     *
     * @param oid           перевіряємий OID
     * @return true  - big-endian
     *         false - інше
     */
    boolean is_dstu_be_params(final OBJECT_IDENTIFIERPointer oid);
    int get_cert_set_by_sid(final CertificateSetPointer cert_set_in, final SignerIdentifierPointer sid, PointerByReference cert_set_out);
    int utf16be_to_utf8(final byte[] in, long in_len, PointerByReference out);
    int utf8_to_utf16be(final String in, PointerByReference out, long out_len);
    String dupstr(final String str);

    /**
     * Перевіряє входження заданого OID`а в інший (батьківський) OID.
     *
     * @param oid        перевіряємий OID
     * @param parent_oid int-представлення батьківського OID`а
     *
     * @return true  - OID входить в батьківський
     *         false - OID не входить в батьківський
     */
    boolean pkix_check_oid_parent(final OBJECT_IDENTIFIERPointer oid, final OidNumbersPointer parent_oid);
    int pkix_create_oid(final OidNumbersPointer oid, PointerByReference dst);

    /**
     * Порівнює два OID.
     *
     * @param oid         OID
     * @param oid_arr вказівник на буфер для int`ов
     *
     * @return чи рівні вони
     */
    boolean pkix_check_oid_equal(final OBJECT_IDENTIFIERPointer oid, final OidNumbersPointer oid_arr);

    /**
     * Встановлює OID по int`му представленню.
     *
     * @param oid  вказівник на буфер для int`ов
     * @param dst  OID
     *
     * @return код помилки
     */
    int pkix_set_oid(final OidNumbersPointer oid, OBJECT_IDENTIFIERPointer dst);
    int pkix_get_key_id_from_spki(final SubjectPublicKeyInfoPointer spki, PointerByReference key_id);

    /**
     * Створює неініціалізований контейнер підпису.
     *
     * @return вказівник на створений контейнер підпису або NULL у випадку помилки
     */
    SignedDataPointer sdata_alloc();

    /**
     * Вивільняє пам'ять, яку займає контейнер підпису.
     *
     * @param sdata контейнер підпису, який видаляється, або NULL
     */
    void sdata_free(SignedDataPointer sdata);

    /**
     * Ініціалізує контейнер підпису на основі готових даних.
     *
     * @param sdata        контейнер підпису
     * @param version      версія контейнера
     * @param digest_aid   алгоритми виробки геша від даних, які підписуються
     * @param content      контент, який підписується
     * @param signer       інформація про підписчиків
     *
     * @return код помилки
     */
    int sdata_init(SignedDataPointer sdata, int version, final DigestAlgorithmIdentifiersPointer digest_aid,
        final EncapsulatedContentInfoPointer content, final SignerInfosPointer signer);

    /**
     * Повертає байтове представлення контейнера підпису в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param out   вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int sdata_encode(final SignedDataPointer sdata, PointerByReference out);

    /**
     *Ініціалізує контейнер підпису з DER-представлення.
     *
     * @param sdata контейнер підпису
     * @param in    буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int sdata_decode(SignedDataPointer sdata, final ByteArrayPointer in);

    /**
     * Повертає версію контейнера підпису.
     *
     * @param sdata   контейнер підпису
     * @param version версія контейнера
     *
     * @return код помилки
     */
    int sdata_get_version(final SignedDataPointer sdata, int version);

    /**
     * Встановлює версію контейнера підпису.
     *
     * @param sdata   контейнер підпису
     * @param version версія контейнера
     *
     * @return код помилки
     */
    int sdata_set_version(SignedDataPointer sdata, int version);

    /**
     * Повертає ідентифікатор алгоритму виробки підпису.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param digest_aids ідентифікатор алгоритму виробки підпису
     *
     * @return код помилки
     */
    int sdata_get_digest_aids(final SignedDataPointer sdata, PointerByReference digest_aids);

    /**
     * Встановлює ідентифікатор алгоритму виробки підпису.
     *
     * @param sdata   контейнер підпису
     * @param digest_aids ідентифікатор алгоритму виробки підпису
     *
     * @return код помилки
     */
    int sdata_set_digest_aids(SignedDataPointer sdata, final DigestAlgorithmIdentifiersPointer digest_aids);

    /**
     * Повертає ідентифікатор алгоритму виробки підпису.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param index індекс
     * @param digest_aid ідентифікатор алгоритму виробки підпису або NULL
     *
     * @return код помилки
     */
    int sdata_get_digest_aid_by_idx(final SignedDataPointer sdata, int index,
        PointerByReference digest_aid);

    /**
     * Повертає контент, який підписується.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata   контейнер підпису
     * @param content створюваний об'єкт контейнера даних
     *
     * @return код помилки
     */
    int sdata_get_content(final SignedDataPointer sdata, PointerByReference content);

    /**
     * Встановлює контент, який підписується.
     *
     * @param sdata   контейнер підпису
     * @param content контент
     *
     * @return код помилки
     */
    int sdata_set_content(SignedDataPointer sdata, final EncapsulatedContentInfoPointer content);

    /**
     * Повертає дані.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param data  створюваний об'єкт підписаних даних
     *
     * @return код помилки
     */
    int sdata_get_data(final SignedDataPointer sdata, PointerByReference data);

    /**
     * Повертає мітку часу.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param info  створюваний об'єкт підписаних даних
     *
     * @return код помилки
     */
    int sdata_get_tst_info(final SignedDataPointer sdata, PointerByReference info);

    /**
     * Повертає множину сертифікатів для перевірки підпису.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param certs сертифікати для перевірки підпису
     *
     * @return код помилки
     */
    int sdata_get_certs(final SignedDataPointer sdata, PointerByReference certs);

    /**
     * Встановлює сертифікати для перевірки підпису.
     *
     * @param sdata контейнер підпису
     * @param certs сертифікати для перевірки підпису
     *
     * @return код помилки
     */
    int sdata_set_certs(SignedDataPointer sdata, final CertificateSetPointer certs);

    /**
     * Повертає прапорець наявності сертифікатов для перевірки підпису.
     *
     * @param sdata контейнер даних
     * @param flag  флаг наявності сертифікатов в контейнері
     *
     * @return код помилки
     */
    int sdata_has_certs(final SignedDataPointer sdata, boolean flag);

    /**
     * Повертає списки відкликаних сертифікатів для перевірки статусу сертифікатів.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param crls  списки відкликаних сертифікатов
     *
     * @return код помилки
     */
    int sdata_get_crls(final SignedDataPointer sdata, PointerByReference crls);

    /**
     * Встановлює списки відкликаних сертифікатів для перевірки статусу сертифікатів.
     *
     * @param sdata контейнер підпису
     * @param crls списки відкликаних сертифікатів
     *
     * @return код помилки
     */
    int sdata_set_crls(SignedDataPointer sdata, final RevocationInfoChoicesPointer crls);

    /**
     * Повертає прапорець наявності відкликаних сертифікатів в контейнері.
     *
     * @param sdata контейнер даних
     * @param flag  прапорець наявності CRL в контейнері
     *
     * @return код помилки
     */
    int sdata_has_crls(final SignedDataPointer sdata, boolean flag);

    /**
     * Повертає інформацію про підписчиків.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata  контейнер підпису
     * @param sinfos інформація про підписчиків
     *
     * @return код помилки
     */
    int sdata_get_signer_infos(final SignedDataPointer sdata, PointerByReference sinfos);

    /**
     * Встановлює інформацію про підписчиків.
     *
     * @param sdata  контейнер підпису
     * @param sinfos інформація про підписчиків
     *
     * @return код помилки
     */
    int sdata_set_signer_infos(SignedDataPointer sdata, final SignerInfosPointer sinfos);

    /**
     * Повертає по індексу сертифікат для перевірки підпису.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param index індекс
     * @param cert  сертифікат або NULL
     *
     * @return код помилки
     */
    int sdata_get_cert_by_idx(final SignedDataPointer sdata, int index, PointerByReference cert);

    /**
     * Повертає по індексу відкликаний сертифікат.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param index індекс
     * @param crl   відкликаний сертифікат або NULL
     *
     * @return код помилки
     */
    int sdata_get_crl_by_idx(final SignedDataPointer sdata, int index, PointerByReference crl);

    /**
     * Повертає по індексу відкликаний сертифікат.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sdata контейнер підпису
     * @param index індекс
     * @param sinfo інформація о подписчике або NULL
     *
     * @return код помилки
     */
    int sdata_get_signer_info_by_idx(final SignedDataPointer sdata, int index, PointerByReference sinfo);

    /**
     * Виконує перевірку контейнера без даних.
     *
     * @param sdata контейнер підпису
     * @param da    адаптер обчислення геша
     * @param va    адаптер перевірки підпису
     * @param index індекс
     *
     * @return код помилки
     */
    int sdata_verify_without_data_by_adapter(final SignedDataPointer sdata, final DigestAdapterPointer da,
        final VerifyAdapterPointer va, int index);
    int sdata_get_content_time_stamp(final SignedDataPointer sdata, int index, TspStatus status,
        long[] content_time_stamp, PointerByReference signer_identifier);
    int sdata_get_signing_time(final SignedDataPointer sdata, int index, long[] signing_time);

    /**
     * Виконує перевірку контейнера.
     *
     * @param sdata контейнер підпису
     * @param da    адаптер обчислення геша
     * @param va    адаптер перевірки підпису
     * @param data  дані
     * @param index індекс
     *
     * @return код помилки
     */
    int sdata_verify_external_data_by_adapter(final SignedDataPointer sdata, final DigestAdapterPointer da,
        final VerifyAdapterPointer va, final ByteArrayPointer data, int index);

    /**
     * Виконує перевірку контейнера внутрішніх даних.
     *
     * @param sdata контейнер підпису
     * @param da    адаптери обчислення геша
     * @param va    адаптери перевірки підпису
     * @param index індекс
     *
     * @return код помилки
     */
    int sdata_verify_internal_data_by_adapter(final SignedDataPointer sdata, final DigestAdapterPointer da,
        final VerifyAdapterPointer va, int index);

    /**
     * Виконує перевірку атрибуту SigningCerificateV2.
     *
     * @param sdata контейнер підпису
     * @param da адаптер обчислення геша
     * @param cert сертифікат
     * @param index індекс підпису
     *
     * @return код помилки
     */
    int sdata_verify_signing_cert_by_adapter(final SignedDataPointer sdata, final DigestAdapterPointer da,
        final CertificatePointer cert, int index);

    /**
     * Створює неініціалізований об'єкт SignInfo.
     *
     * @return вказівник на створений контейнер підпису або NULL у випадку помилки
     */
    SignerInfoPointer sinfo_alloc();

    /**
     * Вивільняє пам'ять, яку займає SignInfo.
     *
     * @param sinfo об'єкт, який видаляється, або NULL
     */
    void sinfo_free(SignerInfoPointer sinfo);

    /**
     * Ініціалізує SignerInfo на основі готових даних.
     *
     * @param sinfo             інформація про підписчика
     * @param version           версія контейнера
     * @param signer_id         ідентифікатор SignerInfo
     * @param digest_aid        ідентифікатор алгоритму геша
     * @param signed_attrs      підписані атрибути
     * @param signed_aid        алгоритм підпису
     * @param sign              підпис
     * @param unsigned_attrs    непідписані атрибути
     *
     * @return код помилки
     */
    int sinfo_init(SignerInfoPointer sinfo, int version, final SignerIdentifierPointer signer_id,
        final DigestAlgorithmIdentifierPointer digest_aid, final AttributesPointer signed_attrs,
        final SignatureAlgorithmIdentifierPointer signed_aid, final OCTET_STRINGPointer sign,
        final AttributesPointer unsigned_attrs);

    /**
     * Повертає байтове представлення об'єкта sinfo в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo об'єкт
     * @param out   вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int sinfo_encode(final SignerInfoPointer sinfo, PointerByReference out);

    /**
     * Ініціалізує об'єкт sinfo з DER-представлення.
     *
     * @param sinfo об'єкт
     * @param in    буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int sinfo_decode(SignerInfoPointer sinfo, final ByteArrayPointer in);

    /**
     * Повертає версію SignInfo.
     *
     * @param sinfo   інформація про підписчика
     * @param version версія
     *
     * @return код помилки
     */
    int sinfo_get_version(final SignerInfoPointer sinfo, int version);

    /**
     * Повертає ідентифікатор SignerInfo.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo інформація про підписчика
     * @param sid   ідентифікатор SignerInfo
     *
     * @return код помилки
     */
    int sinfo_get_signer_id(final SignerInfoPointer sinfo, PointerByReference sid);

    /**
     * Повертає атрибути, які підписуються.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo інформація про підписчика
     * @param attrs атрибути
     *
     * @return код помилки
     */
    int sinfo_get_signed_attrs(final SignerInfoPointer sinfo, PointerByReference attrs);

    /**
     * Повертає по індексу атрибут, який підписується.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo інформація про підписчика
     * @param index індекс
     * @param attr атрибут або NULL
     *
     * @return код помилки
     */
    int sinfo_get_signed_attr_by_idx(final SignerInfoPointer sinfo, int index, PointerByReference attr);

    /**
     * Повертає по ідентифікатору атрибут, який підписується.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo інформація про підписчика
     * @param oid   ідентифікатор
     * @param attr  атрибут
     *
     * @return код помилки
     */
    int sinfo_get_signed_attr_by_oid(final SignerInfoPointer sinfo, final OBJECT_IDENTIFIERPointer oid,
        PointerByReference attr);

    /**
     * Повертає прапорець наявності атрибутів, які підписуються.
     *
     * @param sinfo     інформація про підписчика
     * @param flag прапорець наявності атрибутів, які підписуються
     *
     * @return код помилки
     */
    int sinfo_has_signed_attrs(final SignerInfoPointer sinfo, boolean flag);

    /**
     * Повертає атрибути, які не підписуються.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo інформація про підписчика
     * @param attrs атрибути
     *
     * @return код помилки
     */
    int sinfo_get_unsigned_attrs(final SignerInfoPointer sinfo, PointerByReference attrs);

    /**
     * Повертає по індексу атрибут, який не підписується.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo інформація про підписчика
     * @param index індекс
     * @param attr  атрибут або NULL
     *
     * @return код помилки
     */
    int sinfo_get_unsigned_attr_by_idx(final SignerInfoPointer sinfo, int index, PointerByReference attr);

    /**
     * Повертає по ідентифікатору атрибут, який не підписується.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param sinfo     інформація про підписчика
     * @param oid       ідентифікатор
     * @param attr атрибут
     *
     * @return код помилки
     */
    int sinfo_get_unsigned_attr_by_oid(final SignerInfoPointer sinfo, final OBJECT_IDENTIFIERPointer oid,
        PointerByReference attr);

    /**
     * Додає атрибут, який не підписується.
     *
     * @param sinfo інформація про підписчика
     * @param attr  атрибут
     *
     * @return код помилки
     */
    int sinfo_add_unsigned_attr(SignerInfoPointer sinfo, final AttributePointer attr);

    /**
     * Повертає прапорець наявності атрибутів, які не підписуються.
     *
     * @param sinfo інформація про підписчика
     * @param flag  прапорець наявності атрибутів, які не підписуються
     *
     * @return код помилки
     */
    int sinfo_has_unsigned_attrs(final SignerInfoPointer sinfo, boolean flag);

    /**
     * Виконує перевірку наявності та значення атрибута SigningCertificateV2, який підписується.
     * Згідно з вимогами до формату даних, які підписуються, за п.4.6 и п. 5.3.1 адаптери
     * гешування даних з EncapsulatedContentInfo та обчислення SigningCertificateV2
     * повинні бути налаштовані на ДКЕ №1.
     *
     * @param sinfo інформація про підписчика
     * @param adapter адаптер гешування (для України на ДКЕ №1)
     * @param issuer_cert сертифікат
     *
     * @return код помилки
     */
    int sinfo_verify_signing_cert_v2(final SignerInfoPointer sinfo, final DigestAdapterPointer adapter,
        final CertificatePointer issuer_cert);

    /**
     * Виконує перевірку контейнера без перевірки відповідності даних.
     *
     * @param sinfo інформація про підписчика
     * @param da    адаптер обчислення геша
     * @param va    адаптер перевірки підпису
     *
     * @return код помилки
     */
    int verify_core_without_data(final SignerInfoPointer sinfo, final DigestAdapterPointer da,
        final VerifyAdapterPointer va);
    int sinfo_get_message_digest(final SignerInfoPointer sinfo, PointerByReference hash);

    /**
     * Виконує перевірку контейнера.
     *
     * @param sinfo інформація про підписчика
     * @param da    адаптер обчислення геша
     * @param va    адаптер перевірки підпису
     * @param data  дані
     *
     * @return код помилки
     */
    int verify_core(final SignerInfoPointer sinfo, final DigestAdapterPointer da, final VerifyAdapterPointer va,
        final ByteArrayPointer data);

    /**
     * Виконує перевірку контейнера без перевірки відповідності даних.
     *
     * @param sinfo інформація про підписчика
     * @param da    адаптер обчислення геша від даних (для України на ДКЕ №1)
     * @param va    адаптер перевірки підпису
     *
     * @return код помилки
     */
    int sinfo_verify_without_data(final SignerInfoPointer sinfo, final DigestAdapterPointer da,
        final VerifyAdapterPointer va);

    /**
     * Виконує перевірку контейнера.
     *
     * @param sinfo інформація про підписчика
     * @param da    адаптер обчислення геша від даних (для України на ДКЕ №1)
     * @param va    адаптер перевірки підпису
     * @param data  дані
     *
     * @return код помилки
     */
    int sinfo_verify(final SignerInfoPointer sinfo, final DigestAdapterPointer da, final VerifyAdapterPointer va,
        final ByteArrayPointer data);

    /**
     * Повертає відповідність набора атрибутів форматам підпису.
     *
     * @param sinfo інформація про підписчика
     * @param format список атрибутів, які підтримуються
     *               0-й біт - CADES_BES_FORMAT
     *               1-й біт - CADES_EPES_FORMAT
     *               2-й біт - CADES_C_FORMAT
     *               3-й біт - CADES_X_FORMAT
     *
     * @return код помилки
     */
    int sinfo_get_format(final SignerInfoPointer sinfo, int format);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    SubjectPublicKeyInfoPointer spki_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param spki об'єкт, який видаляється, або NULL
     */
    void spki_free(SubjectPublicKeyInfoPointer spki);

    /**
     * Повертає байтове представлення об'єкта в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param spki ідентифікатор параметрів алгоритму
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int spki_encode(final SubjectPublicKeyInfoPointer spki, PointerByReference out);

    /**
     * Ініціалізує aid из DER-представлення.
     *
     * @param spki ідентифікатор параметрів алгоритму
     * @param in  буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int spki_decode(SubjectPublicKeyInfoPointer spki, final ByteArrayPointer in);

    /**
     * Повертає відкритий ключ в байтовому little-endian представленні.
     * Підтримується ДСТУ 4145.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param spki        сертифікат
     * @param pub_key     буфер для зберігання байтового представлення відкритого ключа
     *
     * @return код помилки
     */
    int spki_get_pub_key(final SubjectPublicKeyInfoPointer spki, PointerByReference pub_key);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    TimeStampReqPointer tsreq_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param tsreq об'єкт, який видаляється, або NULL
     */
    void tsreq_free(TimeStampReqPointer tsreq);

    /**
     * Повертає байтове представлення об'єкта в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsreq мітка часу (запит)
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int tsreq_encode(final TimeStampReqPointer tsreq, PointerByReference out);

    /**
     * Ініціалізує мітку часу з DER-представлення.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsreq мітка часу (запит)
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int tsreq_decode(TimeStampReqPointer tsreq, final ByteArrayPointer in);

    /**
     * Повертає відбиток повідомлення.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsreq мітка часу (запит)
     * @param mess_impr створюваний об'єкт відбитка повідомлення
     *
     * @return код помилки
     */
    int tsreq_get_message(final TimeStampReqPointer tsreq, PointerByReference mess_impr);

    /**
     * Встановлює відбиток повідомлення.
     *
     * @param tsreq мітка часу (запит)
     * @param mess_impr відбиток повідомлення
     *
     * @return код помилки
     */
    int tsreq_set_message(TimeStampReqPointer tsreq, final MessageImprintPointer mess_impr);

    /**
     * Повертає ідентифікатор  політики формування мітки часу.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsreq мітка часу (запит)
     * @param req_policy створюваний об'єкт ідентифікатора політики
     *
     * @return код помилки
     */
    int tsreq_get_policy(final TimeStampReqPointer tsreq, PointerByReference req_policy);

    /**
     * Встановлює ідентифікатор  політики формування мітки часу.
     *
     * @param tsreq мітка часу (запит)
     * @param req_policy ідентифікатор політики
     *
     * @return код помилки
     */
    int tsreq_set_policy(TimeStampReqPointer tsreq, final OBJECT_IDENTIFIERPointer req_policy);

    /**
     * Повертає ідентифікатор запиту.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsreq мітка часу (запит)
     * @param nonce створюваний об'єкт ідентифікатора запита
     *
     * @return код помилки
     */
    int tsreq_get_nonce(final TimeStampReqPointer tsreq, PointerByReference nonce);

    /**
     * Встановлює ідентифікатор запиту.
     *
     * @param tsreq мітка часу (запит)
     * @param nonce ідентифікатор запиту
     *
     * @return код помилки
     */
    int tsreq_set_nonce(TimeStampReqPointer tsreq, final INTEGERPointer nonce);

    /**
     * Генерує унікальний ідентифікатор на основі системного часу.
     *
     * @param tsreq мітка часу (запит)
     *
     * @return код помилки
     */
    int tsreq_generate_nonce(TimeStampReqPointer tsreq);

    /**
     * Повертає прапорець вимоги сертифікату TSP у відповіді.
     *
     * @param tsreq мітка часу (запит)
     * @param cert_req прапорець вимоги сертифікату TSP
     *
     * @return код помилки
     */
    int tsreq_get_cert_req(final TimeStampReqPointer tsreq, boolean cert_req);

    /**
     * Встановлює прапорець вимоги сертифікату TSP у відповіді.
     *
     * @param tsreq мітка часу (запит)
     * @param cert_req прапорець вимоги сертифікату TSP
     *
     * @return код помилки
     */
    int tsreq_set_cert_req(TimeStampReqPointer tsreq, boolean cert_req);

    /**
     * Повертає версію синтаксиса.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsreq мітка часу (запит)
     * @param version створюваний об'єкт версії
     *
     * @return код помилки
     */
    int tsreq_get_version(final TimeStampReqPointer tsreq, PointerByReference version);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    TimeStampRespPointer tsresp_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param tsresp об'єкт, який видаляється, або NULL
     */
    void tsresp_free(TimeStampRespPointer tsresp);

    /**
     * Повертає байтове представлення об'єкта в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsresp мітка часу (відповідь)
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
    int tsresp_encode(final TimeStampRespPointer tsresp, PointerByReference out);

    /**
     * Ініціалізує мітку часу з DER-представлення.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsresp мітка часу (відповідь)
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int tsresp_decode(TimeStampRespPointer tsresp, final ByteArrayPointer in);

    /**
     * Повертає статус формування мітки.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsresp мітка часу (відповідь)
     * @param status створюємий об'єкт статуса формування мітки
     *
     * @return код помилки
     */
    int tsresp_get_status(final TimeStampRespPointer tsresp, PointerByReference status);

    /**
     * Встановлює статус формування мітки.
     *
     * @param tsresp мітка часу (відповідь)
     * @param status статус формування мітки
     *
     * @return код помилки
     */
    int tsresp_set_status(TimeStampRespPointer tsresp, final PKIStatusInfoPointer status);

    /**
     * Повертає сформовану мітку часу.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param tsresp мітка часу (відповідь)
     * @param ts_token створюємий об'єкт мітки часу
     *
     * @return код помилки
     */
    int tsresp_get_ts_token(final TimeStampRespPointer tsresp, PointerByReference ts_token);

    /**
     * Встановлює сформовану мітку часу.
     *
     * @param tsresp мітка часу (відповідь)
     * @param ts_token мітка часу
     *
     * @return код помилки
     */
    int tsresp_set_ts_token(TimeStampRespPointer tsresp, final ContentInfoPointer ts_token);

    /**
     * Виконує перевірку мітки часу.
     *
     * @param tsresp мітка часу (відповідь)
     * @param da адаптер обчислення геша
     * @param va адаптер перевірки підпису
     *
     * @return код помилки
     */
    int tsresp_verify(final TimeStampRespPointer tsresp, final DigestAdapterPointer da, final VerifyAdapterPointer va);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    AdaptersMapPointer adapters_map_alloc();

    /**
     * Очищує контекст adapters_map_t.
     *
     * @param adapters контекст
     */
    void adapters_map_free(AdaptersMapPointer adapters);

    /**
     * Очищує контекст adapters_map не чіпаючи контексты адаптерів.
     *
     * @param adapters контекст
     */
    void adapters_map_with_final_content_free(AdaptersMapPointer adapters);

    /**
     * Додає адаптери гешування та формування підпису в список адаптерів.
     *
     * @param adapters_map список адаптерів
     * @param digest адаптер гешування
     * @param sign адаптер підписування
     *
     * @return код помилки
     */
    int adapters_map_add(AdaptersMapPointer adapters_map, DigestAdapterPointer digest, SignAdapterPointer sign);

    /**
     * Ініціалізує алгоритм гешування параметрами за замовчуванням.
     *
     * @param da адаптер гешування
     *
     * @return код помилки
     */
    int digest_adapter_init_default(PointerByReference da);

    /**
     * Ініціалізує геш адаптер, використовуючи ідентифікатор алгоритму.
     *
     * @param aid ідентифікатор параметрів алгоритму
     * @param da геш адаптер
     *
     * @return код помилки
     */
    int digest_adapter_init_by_aid(final AlgorithmIdentifierPointer aid, PointerByReference da);

    /**
     * Ініціалізує геш адаптер, використовуючи Certificate.
     *
     * @param cert ASN1 стуктура Certificate
     * @param da геш адаптер
     *
     * @return код помилки
     */
    int digest_adapter_init_by_cert(final CertificatePointer cert, PointerByReference da);
    DigestAdapterPointer digest_adapter_copy_with_alloc(final DigestAdapterPointer da);

    /**
     * Очищує контекст digest_adapter_t.
     *
     * @param da контекст
     */
    void digest_adapter_free(DigestAdapterPointer da);

    /**
     * Ініціалізує адаптер шифрування на шифрування, використовуючи сертифікат.
     *
     * @param alg_id алгоритм шифрування
     * @param ca буфер для адаптера шифрування
     *
     * @return код помилки
     */
    int cipher_adapter_init(final AlgorithmIdentifierPointer alg_id, PointerByReference ca);
    CipherAdapterPointer cipher_adapter_copy_with_alloc(final CipherAdapterPointer ca);

    /**
     * Очищує контекст cipher_adapter_t.
     *
     * @param ca контекст
     */
    void cipher_adapter_free(CipherAdapterPointer ca);

    /**
     * Ініціалізує генерацію підпису за допомогою суб'єкта відкритого ключа.
     *
     * @param priv_key      закритий ключ
     * @param signature_aid ідентифікатор алгоритму підпису
     * @param alg           параметри ключа
     * @param sa            буфер для адаптера генерації підпису
     *
     * @return код помилки
     */
    int sign_adapter_init_by_aid(final ByteArrayPointer priv_key, final AlgorithmIdentifierPointer signature_aid,
        final AlgorithmIdentifierPointer alg, PointerByReference sa);

    /**
     * Ініціалізує генерацію підпису за допомогою сертифіката.
     *
     * @param private_key закритий ключ
     * @param cert сертифікат
     * @param sa буфер для адаптера генерації підпису
     *
     * @return код помилки
     */
    int sign_adapter_init_by_cert(final ByteArrayPointer private_key, final CertificatePointer cert,
        PointerByReference sa);
    SignAdapterPointer sign_adapter_copy_with_alloc(final SignAdapterPointer sa);
    int sign_adapter_set_opt_level(SignAdapterPointer sa, OptLevelId opt_level);

    /**
     * Очищує контекст sign_adapter_t.
     *
     * @param sa контекст
     */
    void sign_adapter_free(SignAdapterPointer sa);

    /**
     * Ініціалізує перевірку підпису за допомогою суб'єкта відкритого ключа.
     *
     * @param signature_aid алгоритм підпису
     * @param pkey суб'єкт відкритого ключа
     * @param va буфер для адаптера перевірки підпису
     *
     * @return код помилки
     */
    int verify_adapter_init_by_spki(final AlgorithmIdentifierPointer signature_aid,
        final SubjectPublicKeyInfoPointer pkey,
        PointerByReference va);

    /**
     * Ініціалізує перевірку підпису за допомогою сертифікату.
     *
     * @param cert сертифікат
     * @param va буфер для адаптера перевірки підпису
     *
     * @return код помилки
     */
    int verify_adapter_init_by_cert(final CertificatePointer cert, PointerByReference va);
    VerifyAdapterPointer verify_adapter_copy_with_alloc(final VerifyAdapterPointer va);
    int verify_adapter_set_opt_level(VerifyAdapterPointer va, OptLevelId opt_level);

    /**
     * Очищує контекст verify_adapter_t.
     *
     * @param va контекст
     */
    void verify_adapter_free(VerifyAdapterPointer va);

    /**
     * Ініціалізує dh adapter.
     *
     * @param priv_key закритий ключ
     * @param aid      ASN1-структура алгоритму підпису
     * @param dha      буфер для dh адаптера
     *
     * @return код помилки
     */
    int dh_adapter_init(final ByteArrayPointer priv_key, final AlgorithmIdentifierPointer aid, PointerByReference dha);
    DhAdapterPointer dh_adapter_copy_with_alloc(final DhAdapterPointer dha);

    /**
     * Очищує контекст dh adapter.
     *
     * @param dha контекст
     */
    void dh_adapter_free(DhAdapterPointer dha);
    int create_dstu4145_spki(final OBJECT_IDENTIFIERPointer signature_alg_oid, final Dstu4145CtxPointer ec_params,
        final Gost28147CtxPointer cipher_params, final ByteArrayPointer pub_key, PointerByReference dstu_spki);
    int create_ecdsa_spki(final OBJECT_IDENTIFIERPointer signature_alg_oid, final ANYPointer pub_key_params,
        final EcdsaCtxPointer ec_params, final ByteArrayPointer pub_key, PointerByReference ecdsa_spki);

    /**
     * Формує AID для шифрування по алгоритму ГОСТ 28147.
     * Підтримуються сертифікати з алгоритмом підпису ДСТУ 4145.
     *
     * @param prng          контекст PRNG
     * @param oid           алгоритм шифрування
     * @param cert_with_dke сертифікат с SBOX
     * @param aid_gost      AID для шифрування по алгоритму ГОСТ 28147
     *
     * @return код помилки
     */
    int get_gost28147_aid(PrngCtxPointer prng, final OBJECT_IDENTIFIERPointer oid,
        final CertificatePointer cert_with_dke, PointerByReference aid_gost);

    /**
     * Повертає ДКЕ.
     *
     * @param aid AID
     * @param dke ДКЕ
     *
     * @return код помилки
     */
    int get_gost28147_cipher_params(final AlgorithmIdentifierPointer aid, PointerByReference dke);
    int get_gost28147_params_by_os(final OCTET_STRINGPointer sbox_os, PointerByReference params);

    /**
     * Шифрує ключові дані ключем шифрування,
     * який отриманий на основі спільного секрету.
     *
     * @param dha         адаптер обчислення спільного секрету
     * @param pub_key     сертифікат видавця
     * @param session_key сесійний ключ
     * @param rnd_bytes   64-байтний масив випадкових чисел
     * @param wrapped_key зашифрований ключ
     *
     * @return код помилки
     */
    int wrap_session_key(final DhAdapterPointer dha, final ByteArrayPointer pub_key,
        final ByteArrayPointer session_key, final ByteArrayPointer rnd_bytes, PointerByReference wrapped_key);

    /**
     * Розшифровує ключові дані ключем шифрування,
     * який отриманий на основі спільного секрету.
     *
     * @param dha            адаптер обчислення спільного секрету
     * @param wrapped_key    закритий ключ
     * @param rnd_bytes      64-байтний масив випадкових чисел
     * @param issuer_pub_key відкритий ключ видавця
     * @param session_key    розшифрований ключ
     *
     * @return код помилки
     */
    int unwrap_session_key(final DhAdapterPointer dha, final ByteArrayPointer wrapped_key,
        final ByteArrayPointer rnd_bytes, final ByteArrayPointer issuer_pub_key, PointerByReference session_key);

    /**
     */

    /**
     * Ініціалізує контекст випуску запиту сертифікату.
     *
     * @param sa посилання на ініціалізований адаптер підпису видавця сертифікату, який випускається
     * @param ctx контекст випуску запиту сертифікату
     *
     * @return код помилки
     */
    int ecert_request_alloc(final SignAdapterPointer sa, PointerByReference ctx);

    /**
     * Ініціалізує контекст випуску запиту сертифікату.
     *
     * @param ctx контекст випуску запиту сертифікату
     * @param subject_name  ім'я суб'єкта у вигляді форматованого рядка, кожен атрибут імені
     *                      кожного атрибуту імені розділяється через <code>=</code>
     * @return код помилки
     */
    int ecert_request_set_subj_name(CertificateRequestEnginePointer ctx, final String subject_name);

    /**
     * Ініціалізує контекст випуску запиту сертифікату.
     *
     * @param ctx контекст випуску запиту сертифікату
     * @param dns dns для розширення альтернативного імені суб'єкта
     * @param email email для розширення альтернативного імені суб'єкта
     * @return код помилки
     */
    int ecert_request_set_subj_alt_name(CertificateRequestEnginePointer ctx, final String dns,
        final String email);

    /**
     * Ініціалізує контекст випуску запиту сертифікату.
     *
     * @param ctx контекст випуску запиту сертифікату
     * @param subject_attr  атрибути суб'єкту у вигляді форматованого рядка, кожен атрибут
     *                      кожного атрибуту імені розділяється через <code>=</code>
     * @return код помилки
     */
    int ecert_request_set_subj_dir_attr(CertificateRequestEnginePointer ctx, final String subject_attr);

    /**
     * Ініціалізує контекст випуску запиту сертифікату.
     *
     * @param ctx контекст випуску запиту сертифікату
     * @param ext розширення
     * @return код помилки
     */
    int ecert_request_add_ext(CertificateRequestEnginePointer ctx, final ExtensionPointer ext);

    /**
     * Генерує запит сертифікації з переданих даних.
     *
     * @param ctx контекст випуску запиту сертифікату
     * @param cert_req      запит сертифікації
     * @return код помилки
     */
    int ecert_request_generate(CertificateRequestEnginePointer ctx, PointerByReference cert_req);

    /**
     * Очищує контекст випуску запиту сертифікату
     *
     * @param ctx контекст випуску запиту сертифікату
     */
    void ecert_request_free(CertificateRequestEnginePointer ctx);

    /**
     * Ініціалізує контекст випуску сертифікатів.
     *
     * @param sa посилання на ініціалізований адаптер підпису видавця сертифікату, який випускається
     * @param da посилання на ініціалізований адаптер гешування для обчислення ідентифікаторів ключів
     * @param is_self_signed ознака самопідписанного сертифікату
     * @param ctx контекст випуску сертифікатів
     *
     * @return код помилки
     */
    int ecert_alloc(final SignAdapterPointer sa, final DigestAdapterPointer da, boolean is_self_signed,
        PointerByReference ctx);

    /**
     * Очищує контекст випуску сертифікатів.
     *
     * @param ctx контекст випуску сертифікатів
     */
    void ecert_free(CertificateEnginePointer ctx);

    /**
     * Генерує сертифікат.
     *
     * @param ctx контекст випуску сертифікатів
     * @param req запит на сертифікацію
     * @param ver версія сертифікату, який випускається
     * @param cert_sn серійний номер сертифікату, який випускається
     * @param not_before термін початку використання ключа
     * @param not_after термін закінчення використання ключа
     * @param exts список розширень сертифікату
     * @param cert випущений сертифікат
     *
     * @return код помилки
     */
    int ecert_generate(final CertificateEnginePointer ctx, final CertificationRequestPointer req, int ver,
        final ByteArrayPointer cert_sn, final long[] not_before, final long[] not_after, final ExtensionsPointer exts,
        PointerByReference cert);

    /**
     * Ініціалізує контекст випуску CRL.
     *
     * @param crl попередній CRL, використовується для оновлення списків
     * @param sa посилання на ініціалізований адаптер підпису для CRL
     * @param va посилання на ініціалізований адаптер перевірки підпису для CRL
     * @param crl_exts набір розширень CRL, який випускаєтся
     * @param crl_templ_name ім'я шаблона CRL
     * @param type тип CRL
     * @param crl_desc опис CRL
     * @param ctx контекст випуску CRL
     *
     * @return код помилки
     */
    int ecrl_alloc(final CertificateListPointer crl, final SignAdapterPointer sa, final VerifyAdapterPointer va,
        final ExtensionsPointer crl_exts, final String crl_templ_name, CRLType type, final String crl_desc, PointerByReference ctx);

    /**
     * Очищує контекст випуску CRL.
     *
     * @param ctx контекст випуску CRL
     */
    void ecrl_free(CrlEnginePointer ctx);

    /**
     * Повертає ідентифікатор шаблона.
     *
     * @param ctx контекст випуску CRL
     * @param crl_templ_name ідентифікатор шаблону
     *
     * @return код помилки
     */
    int ecrl_get_template_name(final CrlEnginePointer ctx, PointerByReference crl_templ_name);

    /**
     * Повертає тип CRL.
     *
     * @param ctx контекст випуску CRL
     * @param type тип CRL
     *
     * @return код помилки
     */
    int ecrl_get_type(final CrlEnginePointer ctx, CRLType type);

    /**
     * Повертає опис шаблону.
     *
     * @param ctx контекст випуску CRL
     * @param crl_desc опис шаблону
     *
     * @return код помилки
     */
    int ecrl_get_description(final CrlEnginePointer ctx, PointerByReference crl_desc);

    /**
     * Додає запис відкликаного сертифікату в список. Якщо движок проініціалізований
     * попереднім CRL, то його список доповнюється, інакше - створюєтья новий список. Перевіряється
     * підпис сертифікату, який додається. Видавець у сертифікату, який додається, повинен
     * збігатися з видавцем CRL.
     *
     * @param ctx контекст выпуску CRL
     * @param cert відкликаний сертифікат
     * @param reason причина відклику або null
     * @param inv_date час компрометації ключа або null
     *
     * @return код помилки
     */
    int ecrl_add_revoked_cert(CrlEnginePointer ctx, final CertificatePointer cert, CRLReason reason,
        final long[] inv_date);

    /**
     * Додає запис відкликаного сертифікату. Якщо движок проініціалізований
     * попереднім CRL, то його список доповнюється, інакше - створюєтья новий список.
     *
     * @param ctx контекст випуску CRL
     * @param cert_sn серійний номер сертифікату, який додається
     * @param reason причина відклику або null
     * @param inv_date час компрометації ключа або null
     *
     * @return код помилки
     */
    int ecrl_add_revoked_cert_by_sn(CrlEnginePointer ctx, final ByteArrayPointer cert_sn, CRLReason reason,
        final long[] inv_date);

    /**
     * Зливає повний або частковий CRL та оновлює повний CRL.
     * Для злиття движок повинен бути проініціалізований попередніми частковими CRL.
     *
     * @param ctx контекст випуску CRL
     * @param full попередній повний CRL
     *
     * @return код помилки
     */
    int ecrl_merge_delta(CrlEnginePointer ctx, final CertificateListPointer full);

    /**
     * Генерує CRL.
     *
     * @param ctx контекст випуску CRL
     * @param diff_next_update кількість мілісекунд до наступного оновлення
     * @param crl випущений CRL
     *
     * @return код помилки
     */
    int ecrl_generate_diff_next_update(CrlEnginePointer ctx, long[] diff_next_update, PointerByReference crl);

    /**
     * Генерує CRL.
     *
     * @param ctx контекст випуску CRL
     * @param next_update час наступного оновлення
     * @param crl випущений CRL
     *
     * @return код помилки
     */
    int ecrl_generate_next_update(CrlEnginePointer ctx, long[] next_update, PointerByReference crl);

    /**
     * Генерує CRL.
     *
     * @param ctx контекст випуску CRL
     * @param crl випущений CRL
     *
     * @return код помилки
     */
    int ecrl_generate(CrlEnginePointer ctx, PointerByReference crl);

    /**
     * @defgroup cryptos_pkix_envel_data_engine Генератор контейнеру захищених даних
     */

    /**
     * Ініціалізує контекст .
     *
     * @param ctx контекст
     * @param dha посилання на ініціалізований адаптер виробки спільного секрету
     *
     * @return код помилки
     */
    int eenvel_data_alloc(final DhAdapterPointer dha, PointerByReference ctx);

    /**
     * Очищує контекст .
     *
     * @param ctx контекст
     */
    void eenvel_data_free(EnvelopedDataEnginePointer ctx);

    /**
     * Встановлює сертифікат підписчика.
     *
     * @param ctx контекст
     * @param cert сертифікат підписчика
     *
     * @return код помилки
     */
    int eenvel_data_set_originator_cert(EnvelopedDataEnginePointer ctx, final CertificatePointer cert);

    /**
     * Встановлює атрибути.
     *
     * @param ctx контекст
     * @param attrs атрибути
     *
     * @return код помилки
     */
    int eenvel_data_set_unprotected_attrs(EnvelopedDataEnginePointer ctx, final UnprotectedAttributesPointer attrs);

    /**
     * Встановлює дані для контейнера захищених даних.
     *
     * @param ctx контекст
     * @param oid ідентифікатор даних
     * @param data дані для формування контейнеру
     *
     * @return код помилки
     */
    int eenvel_data_set_data(EnvelopedDataEnginePointer ctx, final OBJECT_IDENTIFIERPointer oid,
        final ByteArrayPointer data);

    /**
     * Встановлює ідентифікатори алгоритму шифрування.
     *
     * @param ctx контекст
     * @param oid ідентифікатор алгоритму шифрування
     *
     * @return код помилки
     */
    int eenvel_data_set_encription_oid(EnvelopedDataEnginePointer ctx, final OBJECT_IDENTIFIERPointer oid);

    /**
     * Чи зберігати сертифікати в контейнері?
     *
     * @param ctx контекст
     * @param is_save_cert прапорець зберігання сертифікатів
     *
     * @return код помилки
     */
    int eenvel_data_set_save_cert_optional(EnvelopedDataEnginePointer ctx, boolean is_save_cert);

    /**
     * Чи зберігати дані в контейнері?
     *
     * @param ctx контекст
     * @param is_save_data прапорець зберігання даних
     *
     * @return код ошибки
     */
    int eenvel_data_set_save_data_optional(EnvelopedDataEnginePointer ctx, boolean is_save_data);

    /**
     * Встановлює ГПВЧ.
     *
     * @param ctx контекст
     * @param prng ГПВЧ
     *
     * @return код ошибки
     */
    int eenvel_data_set_prng(EnvelopedDataEnginePointer ctx, PrngCtxPointer prng);

    /**
     * Дадає ще одного отримувача захищеного контейнеру.
     *
     * @param ctx контекст
     * @param cert сертифікат отримувача
     *
     * @return код помилки
     */
    int eenvel_data_add_recipient(EnvelopedDataEnginePointer ctx, final CertificatePointer cert);

    /**
     * Генерація контейнера захищених даних.
     *
     * @param ctx      контекст
     * @param env_data контейнер захищених даних
     * @param enc_data шифровані данні
     *
     * @return код помилки
     */
    int eenvel_data_generate(EnvelopedDataEnginePointer ctx, PointerByReference env_data, PointerByReference enc_data);

    /**
     * @defgroup cryptos_pkix_ocsp_req_engine Генератор запиту статусу сертифіката
     */

    /**
     * Створює та ініціалізує контекст .
     *
     * @param ctx вказівник на створюваний контекст
     * @param is_nonce_present прапорець наявності мітки
     * @param root_va посилання на кореневий адаптер перевірки підпису
     * @param ocsp_va посилання на адаптер перевірки підпису OCSP сертифікату
     * @param subject_sa посилання на адаптер підпису суб'єкту, який формує запит
     * @param da адаптер гешування
     *
     * @return код помилки
     */
    int eocspreq_alloc(boolean is_nonce_present, final VerifyAdapterPointer root_va, final VerifyAdapterPointer ocsp_va,
        final SignAdapterPointer subject_sa, final DigestAdapterPointer da, PointerByReference ctx);

    /**
     * Очищує контекст.
     *
     * @param ctx контекст
     */
    void eocspreq_free(OcspRequestEnginePointer ctx);

    /**
     * Додає ідентифікатор сертифікату для перевірки статусу.
     *
     * @param ctx контекст
     * @param sn серійний номер сертифікату, який перевіряється
     *
     * @return код помилки
     */
    int eocspreq_add_sn(OcspRequestEnginePointer ctx, final INTEGERPointer sn);

    /**
     * Додає ідентифікатор сертифікату.
     *
     * @param ctx контекст
     * @param cert сертифікат, який перевіряється
     *
     * @return код помилки
     */
    int eocspreq_add_cert(OcspRequestEnginePointer ctx, final CertificatePointer cert);

    /**
     * Генерує запит для відправки OCSP сервісу.
     *
     * @param ctx контекст
     * @param rnd випадкові байти
     * @param req вказівник на створюваний запит
     *
     * @return код помилки
     */
    int eocspreq_generate(OcspRequestEnginePointer ctx, ByteArrayPointer rnd, PointerByReference req);

    /**
     * Перевіряє відповідь OCSP сервісу.
     *
     * @param ocsp_resp декодована відповідь
     * @param current_time поточний час (GMT)
     * @param timeout максимальний час таймаута у хвилинах
     *
     * @return код помилки
     *         RET_EOCSPRESP_NOT_SUCCESSFUL статус відповіді відмінний від SUCCESSFUL
     *         RET_EOCSPREQ_ADAPTER_ISNOT_OCSP у відповіді не заданий nextUpdate
     */
    int eocspreq_validate_resp(final OCSPResponsePointer ocsp_resp, @u_int64_t long current_time, int timeout);

    /**
     * Створює запит для OCSP сервісу на основі сертифікату користувача та корневого сертифікату.
     *
     * @param root_cert кореневий сертифікат
     * @param user_cert користувацький сертифікат
     * @param ocsp_req сгенерований OCSP запит
     *
     * @return код помилки
     */
    int eocspreq_generate_from_cert(final CertificatePointer root_cert, final CertificatePointer user_cert,
        PointerByReference ocsp_req);

    /**
     * Ініціалізує генератор OCSP відповідей.
     *
     * @param ctx вказівник на створюваний контекст генератору відповіді
     * @param root_va кореневий адаптер перевірки підпису
     * @param ocsp_sign адаптер підпису OCSP відповіді
     * @param crls списки відкликаних сертифікатів для перевірки статусу
     * @param da адаптер гешування для перевірки ідентифікатора сертифікату
     * @param next_up_req прапорець зазначення часу наступного оновлення
     * @param crl_reason_req прапорець зазначення причини відклику сертифікату
     * @param id_type тип ідентифікатора
     *
     * @return код помилки
     */
    int eocspresp_alloc(final VerifyAdapterPointer root_va, final SignAdapterPointer ocsp_sign,
        final CertificateListsPointer crls, final DigestAdapterPointer da, boolean next_up_req, boolean crl_reason_req, ResponderIdType id_type,
        PointerByReference ctx);

    /**
     * Встановлює прапорець необхідності перевірки підпису в запиті.
     *
     * @param ctx контекст генератора відповіді
     * @param sign_required прапорець перевірки підпису в запиті
     */
    void eocspresp_set_sign_required(OcspResponseEnginePointer ctx, boolean sign_required);

    /**
     * Встановлює нові списки відкликаних сертифікатів для перевірки статуса сертифікатів.
     *
     * @param ctx контекст генератора відповіді
     * @param crls списки відкликаних сертифікатів
     *
     * @return код помилки
     */
    int eocspresp_set_crls(OcspResponseEnginePointer ctx, final CertificateListsPointer crls);

    /**
     * Генерує OCSP відповідь по отриманому запиту.
     *
     * @param ctx контекст генератора відповіді
     * @param req запит на перевірку статусу сертифіката
     * @param req_va адаптер перевірки підпису запиту, якщо він присутній
     * @param current_time поточний час
     * @param resp вказівник на створювану відповідь, який містить інформацію про сертифікати або інформацію про помилку
     *
     * @return код помилки
     */
    int eocspresp_generate(OcspResponseEnginePointer ctx, final OCSPRequestPointer req, final VerifyAdapterPointer req_va,
        long[] current_time, PointerByReference resp);

    /**
     * Формує відповідь OCSP зі статусом невірного запиту.
     *
     * @param resp вказівник на створювану відповідь OCSP зі статусом невірного запиту
     *
     * @return код помилки
     */
    int eocspresp_form_malformed_req(PointerByReference resp);

    /**
     * Формує відповідь OCSP зі статусом внутрішньої помилки.
     *
     * @param resp вказівник на створювану відповідь OCSP зі статусом внутрішньої помилки
     *
     * @return код помилки
     */
    int eocspresp_form_internal_error(PointerByReference resp);

    /**
     * Формує відповідь OCSP зі статусом перевантаження.
     *
     * @param resp вказівник на створювану відповідь OCSP зі статусом перевантаження
     *
     * @return код помилки
     */
    int eocspresp_form_try_later(PointerByReference resp);

    /**
     * Формує відповідь OCSP зі статусом неавторизованого запиту.
     *
     * @param resp вказівник на створювану відповідь OCSP зі статусом неавторизованого запиту
     *
     * @return код помилки
     */
    int eocspresp_form_unauthorized(PointerByReference resp);

    /**
     * Очищує контекст генератора відповіді.
     *
     * @param ctx контекст генератора відповіді
     */
    void eocspresp_free(OcspResponseEnginePointer ctx);

    /**
     * @defgroup cryptos_pkix_signed_datda_engine Генератор контейнера підписів
     */

    /**
     * Ініціалізує контекст .
     *
     * @param signer вказівник на об'єкт з інформацією про підписчика,
     *               переходить під управління signed_data_engine
     * @param ctx вказівник на створюваний контекст
     * @return код помилки
     */
    int esigned_data_alloc(SignerInfoEnginePointer signer, PointerByReference ctx);

    /**
     * Очищує контекст.
     *
     * @param ctx контекст
     */
    void esigned_data_free(SignedDataEnginePointer ctx);

    /**
     * Встановлює дані для підписування.
     *
     * @param ctx контекст
     * @param oid ідентифікатор даних
     * @param data дані для підписування
     * @param is_internal_data ознака наявності даних
     *
     * @return код помилки
     */
    int esigned_data_set_data(SignedDataEnginePointer ctx, final OidNumbersPointer oid, final ByteArrayPointer data,
        boolean is_internal_data);

    /**
     * Встановлює геш від даних для підписування.
     *
     * @param ctx контекст
     * @param oid ідентифікатор даних
     * @param hash геш від даних для підписування
     *
     * @return код помилки
     */
    int esigned_data_set_hash_data(SignedDataEnginePointer ctx, final OidNumbersPointer oid, final ByteArrayPointer hash);

    /**
     * Встановлює дані для підписування.
     *
     * @param ctx контекст
     * @param info дані для підписування
     *
     * @return код помилки
     */
    int esigned_data_set_content_info(SignedDataEnginePointer ctx, final EncapsulatedContentInfoPointer info);

    /**
     * Встановлює сертифікат підписчика.
     *
     * @param ctx контекст
     * @param cert сертифікат
     *
     * @return код помилки
     */
    int esigned_data_add_cert(SignedDataEnginePointer ctx, final CertificatePointer cert);

    /**
     * Доповнює список відкликаних сертифікатів.
     *
     * @param ctx контекст
     * @param crl СRL список
     *
     * @return код помилки
     */
    int esigned_data_add_crl(SignedDataEnginePointer ctx, final CertificateListPointer crl);

    /**
     * Доповнює інформацію про підписчика.
     *
     * @param ctx контекст
     * @param signer вказівник на об'єкт з інформацією про підписчика,
     *        переходить под управління signed_data_engine
     *
     * @return код помилки
     */
    int esigned_data_add_signer(SignedDataEnginePointer ctx, SignerInfoEnginePointer signer);

    /**
     * Створює контейнер підписаних даних.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ctx контекст
     * @param sdata вказівник на створюваний контейнер підписаних даних
     *
     * @return код помилки
     */
    int esigned_data_generate(final SignedDataEnginePointer ctx, PointerByReference sdata);

    /**
     * @defgroup cryptos_pkix_signer_info_engine Генератор контейнера інформації про підписчика
     *
     * Движок генерації SignerInfo.
     * Signer Info містить інформацію про підписчика, використаний ним алгоритм гешування,
     * використаний набір підписуємих та не підписуємих атрибутів, а також алгоритм і
     * значення підпису від атрибутів, які підписуються.
     */

    /**
     * Контекст генератора контейнеру інформації про підписчика
     */

    /**
     * Ініціалізує контекст .
     *
     * @param sa посилання на адаптер обчислення підпису
     * @param ess_da посилання на адаптер гешування для формування атрибуту “ESS signing-certificate v2”
     * @param data_da посилання на адаптер гешування для формування атрибуту “message-digest“
     * @param ctx вказівник на створюваний контекст
     * @return код помилки
     */
    int esigner_info_alloc(final SignAdapterPointer sa, final DigestAdapterPointer ess_da,
        final DigestAdapterPointer data_da, PointerByReference ctx);

    /**
     * Очищує контекст.
     *
     * @param ctx контекст
     */
    void esigner_info_free(SignerInfoEnginePointer ctx);

    /**
     * Визначає формат інформації про підписчика.
     * Визначає , чи додавати при генерації обов'язкові атрибути формату CAdES-BES.
     * За замовчуванням - додавати.
     *
     * @param ctx контекст
     * @param flag використання трьох основних атрибутів/довільний формат
     *
     * @return код помилки
     */
    int esigner_info_set_bes_attrs(SignerInfoEnginePointer ctx, boolean flag);

    /**
     * Установка підписуємих атрибутів.
     *
     * @param ctx контекст
     * @param signed_attrs атрибути
     *
     * @return код помилки
     */
    int esigner_info_set_signed_attrs(SignerInfoEnginePointer ctx, final AttributesPointer signed_attrs);

    /**
     * Додає підписуємий атрибут.
     *
     * @param ctx контекст
     * @param signed_attr атрибут
     *
     * @return код помилки
     */
    int esigner_info_add_signed_attr(SignerInfoEnginePointer ctx, final AttributePointer signed_attr);

    /**
     * Установка непідписуємих атрибутів.
     *
     * @param ctx контекст
     * @param unsigned_attrs атрибути
     *
     * @return код помилки
     */
    int esigner_info_set_unsigned_attrs(SignerInfoEnginePointer ctx, final AttributesPointer unsigned_attrs);

    /**
     * Додає непідписуємий атрибут.
     *
     * @param ctx контекст
     * @param unsigned_attr атрибут
     *
     * @return код помилки
     */
    int esigner_info_add_unsigned_attr(SignerInfoEnginePointer ctx, final AttributePointer unsigned_attr);

    /**
     * Встановлює дані тип та значення підписуємих даних.
     *
     * @param ctx контекст
     * @param data_type_oid тип даних, які підписуються
     * @param data дані, які підписуються
     *
     * @return код помилки
     */
    int esigner_info_set_data(SignerInfoEnginePointer ctx, final OBJECT_IDENTIFIERPointer data_type_oid,
        final OCTET_STRINGPointer data);

    /**
     * Встановлює тип та геш від підписуємих даних.
     *
     * @param ctx контекст
     * @param data_type_oid тип підписуємих даних
     * @param hash_data геш від підписуємих даних
     *
     * @return код помилки
     */
    int esigner_info_set_hash_data(SignerInfoEnginePointer ctx, final OBJECT_IDENTIFIERPointer data_type_oid,
        final OCTET_STRINGPointer hash_data);

    /**
     * Генерує інформацію про підписчика.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param ctx контекст
     * @param sinfo інформація про підписчика
     *
     * @return код помилки
     */
    int esigner_info_generate(final SignerInfoEnginePointer ctx, PointerByReference sinfo);

    /**
     * @defgroup cryptos_pkix_tsp_req_signer_info_engine Генератор запиту мітки часу
     */

    /**
     * Генерує TSP запит.
     *
     * @param digest_aid алгоритм гешування
     * @param hash геш від повідомлення в le форматі
     * @param rnd ідентифікатор запиту
     * @param policy відповідь TSP (політика сертифікації)
     * @param cert_req вимога у відповіді сертифікату TSP
     * @param tsp_req запит TSP
     *
     * @return код помилки
     */
    int etspreq_generate_from_hash(AlgorithmIdentifierPointer digest_aid, final ByteArrayPointer hash,
        final ByteArrayPointer rnd, final OBJECT_IDENTIFIERPointer policy, boolean cert_req, PointerByReference tsp_req);

    /**
     * Генерує TSP запит.
     *
     * @param da адаптер гешування
     * @param msg TSP повідомлення
     * @param rnd ідентифікатор запиту
     * @param policy відповідь TSP (політика сертифікації)
     * @param cert_req вимога у відповіді сертифікату TSP
     * @param tsp_req запит TSP
     *
     * @return код помилки
     */
    int etspreq_generate(final DigestAdapterPointer da, final ByteArrayPointer msg, final ByteArrayPointer rnd,
        OBJECT_IDENTIFIERPointer policy, boolean cert_req, PointerByReference tsp_req);
    int etspreq_generate_from_gost34311(final ByteArrayPointer hash, final String policy, boolean cert_req,
        PointerByReference tsp_req);

    /**
     * @defgroup cryptos_pkix_tsp_resp_engine Генератор відповіді на запит мітки часу
     */

    /**
     * Генерує TSP відповідь.
     *
     * @param tsp_map адаптери гешування та підпису для різних політик формування TSP відповіді
     * @param tsp_req TSP запит
     * @param sn серійний номер
     * @param tsp_digest_aids алгоритми гешування, які підтримуються
     * @param current_time поточний час
     * @param tsp_resp відповідь TSP
     *
     * @return код помилки
     */
    int etspresp_generate(final AdaptersMapPointer tsp_map, final ByteArrayPointer tsp_req, final INTEGERPointer sn,
        final DigestAlgorithmIdentifiersPointer tsp_digest_aids, final long[] current_time, PointerByReference tsp_resp);


    int cert_store_set_default_path(final String path);
    CertStorePointer cert_store_alloc(final String path);

    /**
     * Зберігає сертифікат в кеш плагіну.
     *
     * @param store сховище
     * @param prefix префікс перед ім'ям сертифікату
     * @param cert сертифікат
     *
     * @return код помилки
     */
    int cert_store_add_certificate(CertStorePointer store, final String prefix, final CertificatePointer cert);

    /**
     * Зберігає сертифікати в кеш плагіну.
     *
     * @param store сховище
     * @param prefix префікс перед ім'ям сертифікату
     * @param certs сертифікати
     *
     * @return код помилки
     */
    int cert_store_add_certificates(CertStorePointer store, final String prefix, final CertificatesPointer certs);
    int cert_store_get_certificates_by_alias(CertStorePointer store, final String alias,
        PointerByReference certs);
    int cert_store_get_certificate_by_pubkey_and_usage(CertStorePointer store, final ByteArrayPointer pubkey,
        int keyusage, PointerByReference cert);
    void cert_store_free(CertStorePointer store);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
    PrivateKeyInfoPointer pkcs8_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param key об'єкт, який видаляється, або NULL
     */
    void pkcs8_free(PrivateKeyInfoPointer key);

    /**
     * Генерує контейнер з закритим ключем.
     *
     * @param aid     алгоритм закритого ключа
     * @param key     контейнер закритого ключа
     *
     * @return код помилки
     */
    int pkcs8_generate(final AlgorithmIdentifierPointer aid, PointerByReference key);

    /**
     * Ініціалізує контейнер.
     *
     * @param key     контейнер закритого ключа
     * @param privkey закритий ключ
     * @param aid     алгоритм закритого ключа
     *
     * @return код помилки
     */
    int pkcs8_init(PrivateKeyInfoPointer key, final ByteArrayPointer privkey, final AlgorithmIdentifierPointer aid);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param key контейнер закритого ключа
     * @param encode вказівник на пам'ять, що виділяється, яка містить DER-представлення
     *
     * @return код помилки
     */
    int pkcs8_encode(final PrivateKeyInfoPointer key, PointerByReference encode);

    /**
     * Ініціалізує сертифікат з DER-представлення.
     *
     * @param key контейнер закритого ключа
     * @param encode буфер з байтами DER-кодування
     *
     * @return код помилки
     */
    int pkcs8_decode(PrivateKeyInfoPointer key, final ByteArrayPointer encode);

    /**
     * Повертає тип сховища.
     *
     * @param key контейнер закритого ключа
     * @param type тип ключа контейнера
     *
     * @return код помилки
     */
    int pkcs8_type(final PrivateKeyInfoPointer key, Pkcs8PrivatekeyType type);

    /**
     * Повертає закритий ключ.
     *
     * @param key     контейнер з закритим ключем
     * @param privkey закритий ключ
     *
     * @return код помилки
     */
    int pkcs8_get_privatekey(final PrivateKeyInfoPointer key, PointerByReference privkey);

    /**
     * Повертає закритий ключ  ДСТУ 4145 для виробки спільного секрету у форматі Big-Endian.
     *
     * @param private_key контейнер з закритим ключем
     * @param d           закритий ключ
     *
     * @return код помилки
     */
    int pkcs8_get_kep_privatekey(final PrivateKeyInfoPointer private_key, PointerByReference d);

    /**
     * Формує структуру SubjectPublicKeyInfo для відкритого ключа.
     *
     * @param key  контейнер з закритим ключем
     * @param spki SubjectPublicKeyInfo
     *
     * @return код помилки
     */
    int pkcs8_get_spki(final PrivateKeyInfoPointer key, PointerByReference spki);

    /**
     * Повертає контекст виробки підпису.
     *
     * @param key      контейнер з закритим ключем
     * @param cert     буфер з сертифікатом
     * @param sa       контекст виробки підпису
     *
     * @return код помилки
     */
    int pkcs8_get_sign_adapter(final PrivateKeyInfoPointer key, final ByteArrayPointer cert,
        PointerByReference sa);

    /**
     * Повертає контекст перевірки підпису.
     *
     * @param key контейнер з закритим ключем
     * @param va  контекст перевірки підпису
     *
     * @return код помилки
     */
    int pkcs8_get_verify_adapter(final PrivateKeyInfoPointer key, PointerByReference va);

    /**
     * Повертає контекст wrap adapter.
     *
     * @param key         контейнер з закритим ключем
     * @param ctx         контекст wrap адаптера
     *
     * @return код помилки
     */
    int pkcs8_get_dh_adapter(final PrivateKeyInfoPointer key, PointerByReference ctx);

    /**
     * Устанвливает содержимое структуры INTEGER.
     * Выделяемая память требует освобождения.
     *
     * @param integer    указатель на объект
     * @param bytes      указатель буфер с данными.
     * @param bytes_len  размер буфера
     *
     * @return код ошибки
     */
    int asn_bytes2INTEGER(INTEGERPointer integer, final byte[] bytes, @size_t long bytes_len);

    /**
     * Создает INTEGER_t из байтового представления целого числа.
     * Выделяемая память требует освобождения.
     *
     * @param bytes     байтовое представление целого числа
     * @param bytes_len размер входного буфера
     * @param integer   создаваемый INTEGER_t
     *
     * @return код ощибки
     */
    int asn_create_integer(final byte[] bytes, @size_t long bytes_len, PointerByReference integer);

    void asn_free(Asn1DescriptorPointer td, Pointer ptr);

    Asn1DescriptorPointer get_INTEGER_desc();
}
