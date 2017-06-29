/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.types.size_t;
import jnr.ffi.types.u_int64_t;
import ua.privatbank.cryptonite.jnr.cms.CertIDPointer;
import ua.privatbank.cryptonite.jnr.cms.CrlEngineXPointer;
import ua.privatbank.cryptonite.jnr.cms.OcspResponseCtxPointer;
import ua.privatbank.cryptonite.jnr.cms.PaDataType;
import ua.privatbank.cryptonite.jnr.cms.PointerArrayPointer;
import ua.privatbank.cryptonite.jnr.cms.StoragePointer;
import ua.privatbank.cryptonite.jnr.cms.VerifyInfoPointer;
import ua.privatbank.cryptonite.jnr.cms.VerifyInfosPointer;
import ua.privatbank.cryptonite.jnr.cms.VerifyInfosV2Pointer;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificatePointer;
import ua.privatbank.cryptonite.jnr.pkix.DhAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.ExtensionPointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPRequestPointer;
import ua.privatbank.cryptonite.jnr.pkix.OidNumbersPointer;
import ua.privatbank.cryptonite.jnr.pkix.QCStatementPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampRespPointer;
import ua.privatbank.cryptonite.jnr.pkix.VerifyAdapterPointer;

/** interface native library. */
public interface CryptoniteXNative {

    void cryptonite_init();

    void pkix_ptr_free(Pointer ptr);

    PointerArrayPointer pa_alloc(PaDataType type);

    ByteArrayPointer pa_get_ba_elem(final PointerArrayPointer pa, final @size_t long idx);
    String pa_get_string_elem(final PointerArrayPointer pa, final @size_t long idx);
    CertIDPointer pa_get_certid_elem(final PointerArrayPointer pa, final @size_t long idx);

    int pa_get_count(final PointerArrayPointer pa, long[] count);
    int pa_get_type(final PointerArrayPointer pa, int[] type);
    int pa_add_ba_elem(PointerArrayPointer pa, final ByteArrayPointer data);
    int pa_add_bytes_elem(PointerArrayPointer pa, final byte[] data, @size_t long data_len);
    int pa_add_string_elem(PointerArrayPointer pa, final String data);
    int pa_add_certid_elem(PointerArrayPointer pa, final CertIDPointer certid);

    void pa_free(PointerArrayPointer pa);

    int cert_get_issuer_info_by_oid(final CertificatePointer cert, final OidNumbersPointer oid, PointerByReference issuer);
    int cert_get_subject_info_by_oid(final CertificatePointer cert, final OidNumbersPointer oid, PointerByReference info);

    int cert_get_issuer_infos(final CertificatePointer cert, PointerByReference infos);
    int cert_get_subject_infos(final CertificatePointer cert, PointerByReference infos);

    int cert_get_inn(final CertificatePointer cert, PointerByReference inn);
    int cert_get_egrpou(final CertificatePointer cert, PointerByReference inn);

    int cert_get_sub_alt_name(final CertificatePointer cert, PointerByReference infos);

    int cert_get_qc_limit_value(final CertificatePointer cert, PointerByReference currency, long[] amount, long[] exponent);

    @u_int64_t long cert_get_not_before_v2(final CertificatePointer cert);

    @u_int64_t long cert_get_not_after_v2(final CertificatePointer cert);

    int ocspreq_get_certid_list(final OCSPRequestPointer ocspreq, PointerByReference certids, PointerByReference nonce);

    /**
     * Створює неініціалізований об'єкт.
     *
     * @return вказівник на створений об'єкт або NULL у випадку помилки
     */
     CertIDPointer certid_alloc();

    /**
     * Вивільняє пам'ять, яку займає об'єкт.
     *
     * @param certid об'єкт, який видаляється, або NULL
     */
     void certid_free(CertIDPointer certid);

    /**
     * Повертає байтове представлення в DER-кодуванні.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param certid CertID
     * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
     *
     * @return код помилки
     */
     int certid_encode(final CertIDPointer certid, PointerByReference out);

    /**
     * Ініціалізує CertID з DER-представлення.
     *
     * @param certid CertID
     * @param in буфер з байтами DER-кодування
     *
     * @return код помилки
     */
     int certid_decode(CertIDPointer certid, final ByteArrayPointer in);

    /**
     * Повертає інформацію про issuer name.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param certid CertID
     * @param hash геш
     *
     * @return код помилки
     */
     int certid_get_issuer_name_hash(final CertIDPointer certid, PointerByReference hash);

    /**
     * Повертає інформацію про issuer key.
     *
     * @param certid CertID
     * @param hash геш
     *
     * @return код помилки
     */
     int certid_get_issuer_key_hash(final CertIDPointer certid, PointerByReference hash);

    /**
     * Повертає серійний номер.
     * Виділена пам'ять потребує вивільнення.
     *
     * @param certid CertID
     * @param serial серійний номер
     *
     * @return код помилки
     */
    int certid_get_serial_number(final CertIDPointer certid, PointerByReference serial);

    /**
     * Формує ЕЦП у форматі CMS від повідомлення.
     *
     * @param sa sign adapter
     * @param cert сертифікат підписчика
     * @param data дані для підпису
     * @param include_data ознака того, що необхідно вкладати дані в контейнер підпису
     * @param include_cert ознака того, що необхідно вкладати сертифікат підписчика в контейнер підпису
     * @param signed_attrs атрибути, які підписуються
     * @param unsigned_attrs атрибути, які не підписуються
     * @param sign вказівник на створений CMS підпис
     *
     * @return код помилки
     */
    int cms_sign_data(SignAdapterPointer sa, final ByteArrayPointer cert, final ByteArrayPointer data,
                  boolean include_data, boolean include_cert, final ByteArrayPointer signed_attrs,
                  final ByteArrayPointer unsigned_attrs, PointerByReference sign);

    /**
     * Формує ЕЦП у форматі CMS від повідомлення.
     *
     * @param sa sign adapter
     * @param cert сертифікат підписчика
     * @param hash геш для підпису
     * @param include_cert ознака того, що необхідно вкладати сертифікат підписчика в контейнер підпису
     * @param signed_attrs атрибути, які підписуються
     * @param unsigned_attrs атрибути, які не підписуються
     * @param sign вказівник на створений CMS підпис
     *
     * @return код помилки
     */
    int cms_sign_hash(SignAdapterPointer sa, final ByteArrayPointer cert, final ByteArrayPointer hash,
                  boolean include_cert, final ByteArrayPointer signed_attrs,
                  final ByteArrayPointer unsigned_attrs, PointerByReference sign);

    /**
     * Перевіряє CMS підпис.
     *
     * @param cms_sign байтове представлення CMS контейнера з підписами
     * @param data дані для перевірки
     * @param certs масив сертифікатів в байтовому кодуванні
     * @param verify_infos результат перевірки підписів
     *
     * @return код помилки
     */
    int cms_verify(final ByteArrayPointer cms_sign, final ByteArrayPointer data, final PointerArrayPointer certs,
            PointerByReference verify_infos);

    void verify_infos_free(VerifyInfosPointer vi);

    /**
     * Формує та повертає запит на випуск сертифікату.
     *
     * @param sa sign adapter
     * @param subject_name ім'я суб'єкта у вигляді форматованого рядка, кожен атрибут імені
     *                     визначається фігурними дужками <code>{}</code>, ключ значення
     *                     кожного атрибуту імені розділяються через <code>=</code>
     * @param dns рядок, який містить DNS
     * @param email рядок, який містить адресу електронної пошти
     * @param subject_attr атрибути суб'єкта у вигляді форматованого рядка, кожен атрибут
     *                     визначається фігурними дужками <code>{}</code>, ключ значення
     *                     кожного атрибуту імені розділяються через <code>=</code>
     * @param request запит на випуск сертифікату в байтовому представленні
     *
     * @return код помилки
     */
    int cms_get_cert_request(SignAdapterPointer sa, final String subject_name, final String dns,
        final String email, final String subject_attr, PointerByReference request);

    int cms_encrypt(DhAdapterPointer dha,
            final ByteArrayPointer data, final ByteArrayPointer cert, final ByteArrayPointer dest_cert,
            final String chipher_oid, Boolean include_certificate, PointerByReference enveloped_data);

    int cms_decrypt(DhAdapterPointer dha,
            final ByteArrayPointer enveloped_data, final ByteArrayPointer enc_data,
            final ByteArrayPointer receiver_cert, final ByteArrayPointer sender_cert, PointerByReference decrypted_data);

    int cms_generate_sign_attrs(final TimeStampRespPointer tsresp, boolean include_time, PointerByReference attrs);
    int cms_split(final ByteArrayPointer cinfo_ba, PointerByReference cms_splited);
    int cms_join(final ByteArrayPointer data, final ByteArrayPointer cinfo1_ba, final ByteArrayPointer cinfo2_ba, PointerByReference cinfo_joined);

    //TODO: long = size_t
    int verify_infos_get_count(final VerifyInfosPointer vis, long[] count);
    int verify_infos_get_element(final VerifyInfosPointer vis, @size_t long idx, PointerByReference vi);
    int verify_info_get_cert(final VerifyInfoPointer vi, PointerByReference cert);
    int verify_info_get_hash(final VerifyInfoPointer vi, PointerByReference hash);
    int verify_info_get_signer_id(final VerifyInfoPointer vi, PointerByReference signer_id);
    int verify_info_get_sign_status(final VerifyInfoPointer vi, int[] status);
    int verify_info_get_tsp_status(final VerifyInfoPointer vi, int[] tsp_status);
    @u_int64_t long verify_info_get_tsp_value(final VerifyInfoPointer vi);
    int verify_info_get_tsp_sid(final VerifyInfoPointer vi, PointerByReference tsp_sid);
    @u_int64_t long verify_info_get_signing_time_value(final VerifyInfoPointer vi);
    void verify_info_free(VerifyInfoPointer vi);

    /**
     * Отримує сховище невідомого типу з його байтового представлення.
     * Використовується послідовний перебір типів вбудовування.
     *
     * @param name ім'я сховища
     * @param storage_body байтове представлення сховища
     * @param password пароль до сховища
     * @param storage контекст сховища
     *
     * @return код помилки
     */
    int storage_decode(final String name, final ByteArrayPointer storage_body, final String password, PointerByReference storage);

    /**
     * Створює файлове сховище заданого типу.
     *
     * @param type тип сховища
     * @param password пароль до сховища
     * @param rounds   кількість ітерацій гешування ключа
     * @param storage  контекст сховища
     *
     * @return код помилки
     */
    int storage_create(int type, final String password, final int rounds, PointerByReference storage);

    void storage_free(StoragePointer storage);

    /**
     * Повертає ім'я виробника пристрою.
     *
     * @param storage сховище
     * @param name рядок з ім'ям виробника пристрою
     *
     * @return код помилки
     */
    int storage_get_vendor_name(final StoragePointer storage, final PointerByReference name);

    /**
     * Повертає назву продукту.
     *
     * @param storage сховище
     * @param name рядок з назвою продукту
     *
     * @return код помилки
     */
    int storage_get_product_name(final StoragePointer storage, final PointerByReference name);

    /**
     * Повертає користувацьке ім'я сховища.
     *
     * @param storage сховище
     * @param name рядок з назвою вбудовування
     *
     * @return код помилки
     */
    int storage_get_storage_name(final StoragePointer storage, final PointerByReference name);

    /**
     * Змінює ім'я сховища.
     *
     * @param storage сховище
     * @param new_name нове ім'я сховища
     *
     * @return код помилки
     */
    int storage_rename_storage(StoragePointer storage, final String new_name);

    /**
     * Змінює пароль до сховища.
     *
     * @param storage сховище
     * @param cur_pwd поточний пароль до сховища або NULL
     * @param new_pwd новий пароль до сховища або NULL
     * @param remained_attempts кількість спроб, які залишилися для введення паролю, -1 значить нескінченно
     *
     * @return код помилки
     */
    int storage_change_password(StoragePointer storage, final String cur_pwd, final String new_pwd, int[] remained_attempts);

    /**
     * Отримання списку ключів.
     *
     * @param storage сховище
     * @param keys    список ключів зі сховища
     * @param cnt     кількість ключів у списку
     *
     * @return код помилки
     */
    int storage_enum_keys(final StoragePointer storage, final PointerByReference keys, final long[] cnt);

    /**
     * Вибір ключа.
     *
     * @param storage сховище
     * @param alias   алиас
     * @param pwd     користувацький пароль до ключа або NULL
     *
     * @return код помилки
     */
    int storage_select_key(StoragePointer storage, final String alias, final String pwd);

    /**
     * Чи можливе завантаження/генерація нових ключів?
     *
     * @param storage сховище
     * @param flag true - є ресурси для зберігання ще одного ключа
     *
     * @return код помилки
     */
    int storage_can_generate_key(final StoragePointer storage, boolean[] flag);

    /**
     * Генерує нову пару асиметричних ключів з певними параметрами.
     *
     * @param storage сховище
     * @param aid     AlgorithmIdentifier в байтовому представленні
     *
     * @return код помилки
     */
    int storage_generate_key(StoragePointer storage, final ByteArrayPointer aid, String alias, String password);

    /**
     * Генерує нову пару DH асиметричних ключів з певними параметрами.
     *
     * @param storage сховище
     * @param aid     AlgorithmIdentifier в байтовому представленні
     *
     * @return код помилки
     */
    int storage_generate_key_dh(StoragePointer storage, final ByteArrayPointer aid, String alias, String password);

    /**
     * Перейменовує обраний ключ.
     *
     * @param storage сховище
     * @param alias нове ім'я ключа
     *
     * @return код помилки
     */
    int storage_rename_key(StoragePointer storage, final String alias);

    /**
     * Змінює пароль на ключ.
     *
     * @param storage сховище
     * @param old_pwd поточний пароль на ключ
     * @param new_pwd новий пароль на ключ
     *
     * @return код помилки
     */
    int storage_change_key_pwd(StoragePointer storage, final String old_pwd, final String new_pwd);


    /**
     * Перевіряє, чи можливо задати такий аліас ключу.
     *
     * @param storage сховище
     * @param alias користувацьке ім'я ключа
     * @param flag прапорець доступності аліасу: 1 - доступний, 0 - не доступний
     *
     * @return код помилки
     */
    int storage_is_alias_available(final StoragePointer storage, final String alias, boolean[] flag);

//
//    /**
//     * Повертає байтове представлення стисненого відкритого ключа.
//     *
//     * @param storage сховище
//     * @param public стиснений відкритий ключ в байтовому представленні
//     *
//     * @return код помилки
//     */
//    int storage_get_compressed_public_key(final Storage storage, PointerByReference key);
//
//    /**
//     * Зберігає сертифікати.
//     *
//     * @param storage сховище
//     * @param cert список з вказівників на байтові представлення сертифікатів (null-terminated)
//     *
//     * @return код помилки
//     */
//    int storage_set_certificates(Storage storage, final ByteArrayPointer[] certs);

    /**
     * Повертає байтове представлення сертифікату ключа.
     *
     * @param storage сховище
     * @param key_usage бітова маска областей застосування сертифікату, які перевіряються
     * @param cert байтове представлення сертифікату ключа або NULL у випадку відсутності
     *
     * @return код помилки
     */
    int storage_get_certificate(final StoragePointer storage, int key_usage, PointerByReference cert);
//
//    /**
//     * Повертає список сертифікатів ключа в байтовому представленні.
//     *
//     * @param storage сховище
//     * @param certs байтове представлення списку сертифікатів або NULL у випадку відсутності (null-terminated)
//     *
//     * @return код помилки
//     */
//    int storage_get_certificates(final Storage storage, PointerByReference certs);

    /**
     * Повертає масив пошукових запитів на пошук сертифікату.
     *
     * @param storage  сховище
     * @param requests масив контекстів пошукових запитів
     *
     * @return код помилки
     */
    int storage_get_search_cert_req(final StoragePointer storage, PointerByReference requests);

    /**
     * Видаляє ключ.
     *
     * @param storage сховище
     *
     * @return код помилки
     */
    int storage_delete_key(StoragePointer storage);

    /**
     * Створює движок підпису.
     *
     * @param storage сховище
     * @param sa ініціалізований контекст движка підпису
     *
     * @return код помилки
     */
    int storage_get_sign_adapter(final StoragePointer storage, PointerByReference sa);

    /**
     * Ініціалізує dh adapter.
     *
     * @param storage сховище
     * @param dha dh adapter
     *
     * @return код помилки
     */
    int storage_get_dh_adapter(StoragePointer storage, PointerByReference dha);

    /**
     * Створює движок перевірки підпису.
     *
     * @param storage сховище
     * @param va ініціалізований контекст движка перевірки підпису
     *
     * @return код помилки
     */
    int storage_get_verify_adapter(final StoragePointer storage, PointerByReference va);

    /**
     * Зберігає файлове сховище в байтовому представленні.
     *
     * @param storage контекст сховища
     * @param storage_body байтове представлення сховища
     *
     * @return код помилки
     */
    int storage_encode(final StoragePointer storage, PointerByReference storage_body);

    int storage_get_aliases(final StoragePointer storage, PointerByReference storage_body);

    /**
     * Повертає байтове представлення стисненого відкритого ключа.
     *
     * @param storage сховище
     * @param key     стиснений відкритий ключ в байтовому представленні
     *
     * @return код помилки
     */
    int storage_get_compressed_public_key(final StoragePointer storage, PointerByReference key);

    int cms_verify_v2(final SignedDataPointer signed_data, PointerByReference verify_infos);

    void verify_infos_v2_free(VerifyInfosV2Pointer vis);

    /**
     * Встановлюе дані.
     *
     * @param sdata контейнер підпису
     * @param data  створюваний об'єкт підписаних даних
     *
     * @return код помилки
     */
    int sdata_set_data(SignedDataPointer sdata, final ByteArrayPointer data);

    int cert_engine_generate(SignAdapterPointer sa, final ByteArrayPointer certRequest, final ByteArrayPointer serialNumber,
             @u_int64_t long notBefore, @u_int64_t long notAfter, final PointerArrayPointer exts, PointerByReference cert);

    int stacktrace_print_err(PointerByReference errString);

    int ext_create_ext_key_usage_from_pa(boolean critical, PointerArrayPointer oidsPa, PointerByReference ext);
    int ext_create_cert_policies_from_pa(boolean critical, PointerArrayPointer oidsPa, PointerByReference ext);
    int ext_create_qc_statements_from_pa(boolean critical, PointerArrayPointer qcStatementsPa, PointerByReference ext);
    int ext_create_crl_distr_points_from_url(boolean critical, String crlDistrPointsUrl, PointerByReference ext);
    int ext_create_freshest_crl_from_url(boolean critical, String freshestCrlUrl, PointerByReference ext);
    int ext_create_any_x(boolean critical, String oid, ByteArrayPointer value, PointerByReference ext);
    int ext_encode(ExtensionPointer ext, PointerByReference encoded);

    int qc_statement_encode(QCStatementPointer qcStatement, PointerByReference encoded);
    void qc_statement_free(QCStatementPointer qcStatement);

    int crl_engine_full_alloc(PointerByReference engine_crl);
    int crl_engine_delta_alloc(ByteArrayPointer delta_crl_indicator, PointerByReference engine_crl);
    int crl_engine_add_revoked_info(CrlEngineXPointer engine_crl, final ByteArrayPointer cert_sn, @u_int64_t long revocation_date,
            int reason, @u_int64_t long invalidity_date);
    int crl_engine_get_encoded(CrlEngineXPointer engine_crl, SignAdapterPointer sa, @u_int64_t long this_update,
            @u_int64_t long next_update, ByteArrayPointer serial_number, String crl_distr_points_url,
            String freshest_crl_url, PointerByReference encoded);
    int crl_engine_free(CrlEngineXPointer engine_crl);

    /**
     * Ініціалізує генератор OCSP відповідей.
     *
     * @param sa адаптер підпису OCSP відповіді
     * @param id_type тип ідентифікатора
     * @param ctx вказівник на створюваний контекст генератору відповіді
     *
     * @return код помилки
     */
    int ocsp_resp_engine_alloc(final SignAdapterPointer sa, int id_type, PointerByReference ctx);

    int ocsp_resp_engine_add_response_ok(OcspResponseCtxPointer ctx,
                                        final ByteArrayPointer issuerNameHash,
                                        final ByteArrayPointer issuerKeyHash,
                                        final ByteArrayPointer serialNumber,
                                        @u_int64_t long thisUpdate,
                                        @u_int64_t long nextUpdate);

    int ocsp_resp_engine_add_response_unknown(OcspResponseCtxPointer ctx,
                                             final ByteArrayPointer issuerNameHash,
                                             final ByteArrayPointer issuerKeyHash,
                                             final ByteArrayPointer serialNumber,
                                             @u_int64_t long thisUpdate,
                                             @u_int64_t long nextUpdate);

    int ocsp_resp_engine_add_response_revoked(OcspResponseCtxPointer ctx,
                                             final ByteArrayPointer issuerNameHash,
                                             final ByteArrayPointer issuerKeyHash,
                                             final ByteArrayPointer serialNumber,
                                             @u_int64_t long revocation_time,
                                             int reason,
                                             @u_int64_t long this_update,
                                             @u_int64_t long next_update);

    int ocsp_resp_engine_clean_response(OcspResponseCtxPointer ctx);

    int ocsp_resp_engine_generate(final OcspResponseCtxPointer ctx, final ByteArrayPointer nonce, @u_int64_t long current_time, PointerByReference resp);

    /**
     * Очищує контекст генератора відповіді.
     *
     * @param ctx контекст генератора відповіді
     */
    void ocsp_resp_engine_free(OcspResponseCtxPointer ctx);

    int tsp_engine_generate(SignAdapterPointer sa, final ByteArrayPointer tsp_request, final ByteArrayPointer serial_number,
            @u_int64_t long date, PointerArrayPointer acceptable_policies_str, final String default_policy_str,
            PointerByReference tsp, long[] failure_info_code, PointerByReference errorStacktrace);

    String cryptonite_x_get_version();

    int sign_adapter_sign_data(SignAdapterPointer sa, final ByteArrayPointer data, PointerByReference sign);
    int sign_adapter_sign_hash(SignAdapterPointer sa, final ByteArrayPointer hash, PointerByReference sign);
    int verify_adapter_verify_data(VerifyAdapterPointer va, final ByteArrayPointer data, final ByteArrayPointer sign);
    int verify_adapter_verify_hash(VerifyAdapterPointer va, final ByteArrayPointer hash, final ByteArrayPointer sign);

    int pkix_rsa_publickeyto_ba(final ByteArrayPointer encoded, PointerByReference n, PointerByReference e);
}
