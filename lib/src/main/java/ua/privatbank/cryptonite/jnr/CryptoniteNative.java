/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.types.size_t;
import ua.privatbank.cryptonite.jnr.crypto.AesCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.crypto.DesCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.DsaCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Dstu4145CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Dstu4145ParamsId;
import ua.privatbank.cryptonite.jnr.crypto.Dstu7564CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Dstu7564SboxId;
import ua.privatbank.cryptonite.jnr.crypto.Dstu7624CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Dstu7624SboxId;
import ua.privatbank.cryptonite.jnr.crypto.EcdsaCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.EcdsaParamsId;
import ua.privatbank.cryptonite.jnr.crypto.ErrorCtx;
import ua.privatbank.cryptonite.jnr.crypto.FILEPointer;
import ua.privatbank.cryptonite.jnr.crypto.Gost28147CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Gost28147SboxId;
import ua.privatbank.cryptonite.jnr.crypto.Gost34311CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.HmacCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Md5CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.OptLevelId;
import ua.privatbank.cryptonite.jnr.crypto.PrngCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.PrngMode;
import ua.privatbank.cryptonite.jnr.crypto.RsaCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.RsaHashType;
import ua.privatbank.cryptonite.jnr.crypto.Sha1CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Sha2CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Sha2Variant;

/** interface native library. */
public interface CryptoniteNative {
    /**
     * Створює контекст AES.
     *
     * @return контекст AES
     */
    AesCtxPointer aes_alloc();

    /**
     * Генерує секретний ключ.
     *
     * @param prng контекст ГПСЧ
     * @param key_len размер ключа 16, 24 или 32
     * @param key секретний ключ
     * @return код помилки
     */
    int aes_generate_key(PrngCtxPointer prng, @size_t long key_len, PointerByReference key);

    /**
     * Ініціалізація контексту AES для режиму ECB.
     *
     * @param ctx контекст AES
     * @param key ключ шифрування
     * @return код помилки
     */
    int aes_init_ecb(AesCtxPointer ctx, final ByteArrayPointer key);

    /**
     * Ініціалізація контексту AES для режиму CBC.
     *
     * @param ctx контекст AES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int aes_init_cbc(AesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізація контексту AES для режиму CFB.
     *
     * @param ctx контекст AES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int aes_init_cfb(AesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізація контексту AES для режиму OFB.
     *
     * @param ctx контекст AES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int aes_init_ofb(AesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізація контексту AES для режиму CTR.
     *
     * @param ctx контекст AES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int aes_init_ctr(AesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Шифрування у режимі AES.
     *
     * @param ctx контекст AES
     * @param data дані
     * @param encrypted_data зашифровані дані
     * @return код помилки
     */
    int aes_encrypt(AesCtxPointer ctx, final ByteArrayPointer data, PointerByReference encrypted_data);

    /**
     * Розшифрування у режимі AES.
     *
     * @param ctx контекст AES
     * @param encrypted_data зашифровані дані
     * @param data розшифровані дані
     * @return код помилки
     */
    int aes_decrypt(AesCtxPointer ctx, final ByteArrayPointer encrypted_data, PointerByReference data);

    /**
     * Звільняє контекст AES.
     *
     * @param ctx контекст AES
     */
    void aes_free(AesCtxPointer ctx);

    /**
     * Створює контекст масиву байт.
     *
     * @return контекст масиву байт
     */
    ByteArrayPointer ba_alloc();

    /**
     * Створює контекст масиву байт.
     *
     * @param len розмір масиву байт
     * @return контекст масиву байт
     */
    ByteArrayPointer ba_alloc_by_len(@size_t long len);

    /**
     * Створює контекст масиву байт.
     *
     * @param buf массив байт
     * @param buf_len розмір масиву байт
     * @return контекст масиву байт
     */
    ByteArrayPointer ba_alloc_from_uint8(final Pointer buf, @size_t long buf_len);

    /**
     * Створює контекст масиву байт з файлу.
     *
     * @param path шлях до файлу
     * @param out  контекст масиву байт
     * @return код помилки
     */
    int ba_alloc_from_file(final String path, PointerByReference out);

    /**
     * Створює контекст масиву байт з файлу.
     *
     * @param path шлях до файлу
     * @return контекст масиву байт
     */
    ByteArrayPointer ba_alloc_from_stream(FILEPointer path);
    ByteArrayPointer ba_alloc_from_str(final String buf);
    ByteArrayPointer ba_copy_with_alloc(final ByteArrayPointer in, @size_t long off, @size_t long len);
    int ba_swap(final ByteArrayPointer a);
    int ba_xor(final ByteArrayPointer a, final ByteArrayPointer b);
    int ba_print(FILEPointer stream, final ByteArrayPointer ba);
    int ba_set(ByteArrayPointer a, Pointer value);
    ByteArrayPointer ba_alloc_from_le_hex_string(final String data);

    /**
     * Створює контекст масиву байт за двома іншими.
     *
     * @param a контекст масиву байт
     * @param b контекст масиву байт
     * @return контекст масиву байт
     */
    ByteArrayPointer ba_join(final ByteArrayPointer a, final ByteArrayPointer b);
    int ba_cmp(final ByteArrayPointer a, final ByteArrayPointer b);

    /**
     * Повертає розмір даних, які зберігають контекст масиву байт.
     *
     * @param ba контекст масиву байт
     * @return розмір даних, які зберігають контекст масиву байт.
     */
    @size_t long ba_get_len(final ByteArrayPointer ba);

    /**
     * Повертає вказівник на дані, які зберігають контекст масиву байт.
     *
     * @param ba контекст масиву байт
     * @return вказівник на дані, які зберігають контекст масиву байт
     */
    Pointer ba_get_buf(final ByteArrayPointer ba);

    /**
     * Зберігає дані у існуючий контекст масиву байт.
     *
     * @param buf массив байт
     * @param buf_len розмір масиву байт
     * @param ba контекст масиву байт
     * @return код помилки
     */
    int ba_from_uint8(final Pointer buf, @size_t long buf_len, ByteArrayPointer ba);

    /**
     * Повертає дані, які зберігають контекст масиву байт.
     * Виділяє пам'ять.
     *
     * @param ba контекст масиву байт
     * @param buf массив байт
     * @param buf_len розмір масиву байт
     * @return код помилки
     */
    int ba_to_uint8_with_alloc(final ByteArrayPointer ba, PointerByReference buf, @size_t long buf_len);

    /**
     * Повертає дані, які зберігають контекст масиву байт.
     * Не виділяє пам'ять.
     *
     * @param ba контекст масиву байт
     * @param buf массив байт
     * @param buf_len розмір масиву байт
     * @return код помилки
     */
    int ba_to_uint8(final ByteArrayPointer ba, Pointer buf, @size_t long buf_len);

    /**
     * Записує дані у файл, які зберігають контекст масиву байт.
     * Не виділяє пам'ять.
     *
     * @param ba   контекст масиву байт
     * @param path шлях до файлу
     * @return код помилки
     */
    int ba_to_file(final ByteArrayPointer ba, final String path);
    int ba_copy(final ByteArrayPointer in, @size_t long in_off, @size_t long len, ByteArrayPointer out, @size_t long out_off);
    int ba_append(final ByteArrayPointer in, @size_t long in_off, @size_t long len, ByteArrayPointer out);
    int ba_change_len(ByteArrayPointer ba, @size_t long len);

    /**
     * Звільняє контекст масиву байт.
     *
     * @param ba контекст масиву байт
     */
    void ba_free(ByteArrayPointer ba);
    void ba_free_private(ByteArrayPointer ba);

    /**
     * Додає до кешу контекст ДСТУ 4145 зі стандартними параметрами.
     *
     * @param params_id ідентифікатор стандартних параметрів
     * @param opt_level рівень передобчислення
     *
     * @return код помилки
     */
    int crypto_cache_add_dstu4145(Dstu4145ParamsId params_id, OptLevelId opt_level);

    /**
     * Додає до кешу контекст ДСТУ 4145 з параметрами у поліноміальному базисі.
     *
     * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
     * @param f_len число членів у полиномі f (3 або 5)
     * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param n порядок циклічної підгрупи групи точок еліптичної кривої
     * @param px X-координата точки еліптичної кривої порядока n
     * @param py Y-координата точки еліптичної кривої порядока n
     * @param opt_level рівень передобчислення
     *
     * @return код помилки
     */
    int crypto_cache_add_dstu4145_pb(final int f, @size_t long f_len, int a, final ByteArrayPointer b,
        ByteArrayPointer n,
        ByteArrayPointer px, final ByteArrayPointer py, OptLevelId opt_level);

    /**
     * Додає до кешу контекст ДСТУ 4145 з параметрами у оптимальному нормальному базисі.
     *
     * @param m степінь основного поля, непарне просте число
     * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param n порядок циклічної підгрупи групи точок еліптичної кривої
     * @param px X-координата точки еліптичної кривої порядока n
     * @param py Y-координата точки еліптичної кривої порядока n
     * @param opt_level рівень передобчислення
     *
     * @return код помилки
     */
    int crypto_cache_add_dstu4145_onb(final int m, int a, final ByteArrayPointer b, final ByteArrayPointer n,
        ByteArrayPointer px, final ByteArrayPointer py, OptLevelId opt_level);

    /**
     * Додає до кешу контекст ECDSA.
     *
     * @param p порядок скінченного простого поля GF(p)
     * @param a коефіцієнт a у рівнянні еліптичної кривої
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param q порядок базової точки
     * @param px X-координата базової точки
     * @param py Y-координата базової точки
     * @param opt_level рівень передобчислення
     *
     * @return код помилки
     */
    int crypto_cache_add_ecdsa(final ByteArrayPointer p, final ByteArrayPointer a, final ByteArrayPointer b,
        ByteArrayPointer q,
        ByteArrayPointer px, final ByteArrayPointer py, OptLevelId opt_level);

    /**
     * Додає до кешу контекст будь який новий контекст ДСТУ 4145 та ECDSA.
     *
     * @param opt_level рівень передобчислення
     *
     * @return код помилки
     */
    int crypto_cache_add_any_new(OptLevelId opt_level);

    /**
     * Звільняє контекст кеша крипто контекстів.
     */
    void crypto_cache_free();

    /**
     * Створює контекст DES.
     *
     * @return контекст DES
     */
    DesCtxPointer des_alloc();

    /**
     * Генерує секретний ключ.
     *
     * @param prng контекст ГПСЧ
     * @param key_len размер ключа 8, 16 или 24
     * @param key секретний ключ
     * @return код помилки
     */
    int des_generate_key(PrngCtxPointer prng, @size_t long key_len, PointerByReference key);

    /**
     * Ініціалізація контексту DES для режиму ECB.
     *
     * @param ctx контекст DES
     * @param key ключ шифрування
     * @return код помилки
     */
    int des_init_ecb(DesCtxPointer ctx, final ByteArrayPointer key);

    /**
     * Ініціалізація контексту DES для режиму CBC.
     *
     * @param ctx контекст DES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int des_init_cbc(DesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізація контексту DES для режиму CFB.
     *
     * @param ctx контекст DES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int des_init_cfb(DesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізація контексту DES для режиму OFB.
     *
     * @param ctx контекст DES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int des_init_ofb(DesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізація контексту DES для режиму CTR.
     *
     * @param ctx контекст DES
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int des_init_ctr(DesCtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Шифрування у режимі DES.
     *
     * @param ctx контекст DES
     * @param data розшифровані дані
     * @param encrypted_data зашифровані дані
     * @return код помилки
     */
    int des_encrypt(DesCtxPointer ctx, final ByteArrayPointer data, PointerByReference encrypted_data);

    /**
     * Розшифрування у режимі DES.
     *
     * @param ctx контекст DES
     * @param encrypted_data зашифровані дані
     * @param data розшифровані дані
     * @return код помилки
     */
    int des_decrypt(DesCtxPointer ctx, final ByteArrayPointer encrypted_data, PointerByReference data);

    /**
     * Шифрування у режимі TDES EDE.
     *
     * @param ctx контекст DES
     * @param data розшифровані дані
     * @param encrypted_data зашифровані дані
     * @return код помилки
     */
    int des3_encrypt(DesCtxPointer ctx, final ByteArrayPointer data, PointerByReference encrypted_data);

    /**
     * Розшифрування у режимі TDES EDE.
     *
     * @param ctx контекст DES
     * @param encrypted_data зашифровані дані
     * @param data розшифровані дані
     * @return код помилки
     */
    int des3_decrypt(DesCtxPointer ctx, final ByteArrayPointer encrypted_data, PointerByReference data);

    /**
     * Звільняє контекст DES.
     *
     * @param ctx контекст DES
     */
    void des_free(DesCtxPointer ctx);

    /**
     * Створює контекст DSA.
     *
     * @param p порядок простого скінченного поля GF(p)
     * @param q порядок простого скінченного поля GF(q)
     * @param g елемент простого скінченного поля GF(p)
     * @return контекст DSA
     */
    DsaCtxPointer dsa_alloc(final ByteArrayPointer p, final ByteArrayPointer q, final ByteArrayPointer g);
    DsaCtxPointer dsa_alloc_ext(int l, int n, PrngCtxPointer prng);

    /**
     * Повертає параметри DSA
     *
     * @param ctx контекст DSA
     * @param p порядок простого скінченного поля GF(p)
     * @param q порядок простого скінченного поля GF(q)
     * @param g елемент простого скінченного поля GF(p)
     *
     * @return код помилки
     */
    int dsa_get_params(final DsaCtxPointer ctx, PointerByReference p, PointerByReference q, PointerByReference g);

    /**
     * Генерує ключову пару для DSA.
     *
     * @param ctx контекст DSA
     * @param prng контекст ГПСЧ
     * @param priv_key закритий ключ DSA
     * @return код помилки
     */
    int dsa_generate_privkey(final DsaCtxPointer ctx, PrngCtxPointer prng, PointerByReference priv_key);

    /**
     * Формує відкритий ключ за закритим.
     *
     * @param ctx контекст DSA
     * @param priv_key закритий ключ
     * @param pub_key відкритий ключ
     * @return код помилки
     */
    int dsa_get_pubkey(final DsaCtxPointer ctx, final ByteArrayPointer priv_key, PointerByReference pub_key);

    /**
     * Ініціалізує контекст із закритим ключем.
     *
     * @param ctx контекст DSA
     * @param priv_key закритий ключ
     * @param prng контекст ГПСЧ
     * @return код помилки
     */
    int dsa_init_sign(DsaCtxPointer ctx, final ByteArrayPointer priv_key, PrngCtxPointer prng);

    /**
     * Підписує повідомлення.
     *
     * @param ctx контекст DSA
     * @param hash геш дані
     * @param r частина підпису
     * @param s частина підпису
     * @return код помилки
     */
    int dsa_sign(final DsaCtxPointer ctx, final ByteArrayPointer hash, PointerByReference r, PointerByReference s);

    /**
     * Ініціалізує контекст з відкритим ключем.
     *
     * @param ctx контекст DSA
     * @param pub_key відкритий ключ
     * @return код помилки
     */
    int dsa_init_verify(DsaCtxPointer ctx, final ByteArrayPointer pub_key);

    /**
     * Перевіряє повідомлення.
     *
     * @param ctx контекст DSA
     * @param hash геш дані
     * @param r частина підпису
     * @param s частина підпису
     * @return код помилки або RET_OK, якщо підпис вірний
     */
    int dsa_verify(final DsaCtxPointer ctx, final ByteArrayPointer hash, final ByteArrayPointer r, final ByteArrayPointer s);

    /**
     * Звільняє контекст DSA.
     *
     * @param ctx контекст DSA
     */
    void dsa_free(DsaCtxPointer ctx);

    /**
     * Створює контекст ДСТУ 4145 зі стандартними параметрами.
     *
     * @param params_id ідентифікатор стандартних параметрів
     * @return контекст ДСТУ 4145
     */
    Dstu4145CtxPointer dstu4145_alloc(Dstu4145ParamsId params_id);

    /**
     * Створює контекст ДСТУ 4145 з параметрами у поліноміальному базисі.
     *
     * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
     * @param f_len число членів у полиномі f (3 або 5)
     * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param n порядок циклічної підгрупи групи точок еліптичної кривої
     * @param px X-координата точки еліптичної кривої порядока n
     * @param py Y-координата точки еліптичної кривої порядока n
     *
     * @return контекст ДСТУ 4145
     */
    Dstu4145CtxPointer dstu4145_alloc_pb(final int f, @size_t long f_len, int a, final ByteArrayPointer b,
        ByteArrayPointer n, final ByteArrayPointer px, final ByteArrayPointer py);

    /**
     * Створює контекст ДСТУ 4145 з параметрами у оптимальному нормальному базисі.
     *
     * @param m степінь основного поля
     * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param n порядок циклічної підгрупи групи точок еліптичної кривої
     * @param px X-координата точки еліптичної кривої порядока n
     * @param py Y-координата точки еліптичної кривої порядока n
     *
     * @return контекст ДСТУ 4145
     */
    Dstu4145CtxPointer dstu4145_alloc_onb(final int m, int a, final ByteArrayPointer b, final ByteArrayPointer n,
        ByteArrayPointer px, final ByteArrayPointer py);

    /**
     * Повертає параметри ДСТУ 4145.
     *
     * @param ctx контекст ДСТУ 4145
     * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
     * @param f_len число членів у полиномі f (3 або 5)
     * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param n порядок циклічної підгрупи групи точок еліптичної кривої
     * @param px X-координата точки еліптичної кривої порядока n
     * @param py Y-координата точки еліптичної кривої порядока n
     *
     * @return код помилки
     */
    int dstu4145_get_params(final Dstu4145CtxPointer ctx, PointerByReference f, @size_t long f_len, int a, PointerByReference b,
        PointerByReference n, PointerByReference px, PointerByReference py);

    /**
     * Визначає чи є параметри ДСТУ 4145 ОНБ.
     *
     * @param ctx контекст ДСТУ 4145
     * @param is_onb_params чи є параметри ДСТУ 4145 ОНБ
     * @return код помилки
     */
    int dstu4145_is_onb_params(final Dstu4145CtxPointer ctx, boolean is_onb_params);

    /**
     * Визначає чи параметри однакові.
     *
     * @param param_a контекст ДСТУ 4145
     * @param param_b контекст ДСТУ 4145
     * @param equals чи параметри однакові
     * @return код помилки
     */
    int dstu4145_equals_params(final Dstu4145CtxPointer param_a, final Dstu4145CtxPointer param_b, boolean equals);

    /**
     * Копіює параметри.
     *
     * @param param контекст ДСТУ 4145
     * @return контекст ДСТУ 4145
     */
    Dstu4145CtxPointer dstu4145_copy_params_with_alloc(final Dstu4145CtxPointer param);

    /**
     * Копіює контекст ДСТУ 4145.
     *
     * @param param контекст ДСТУ 4145
     * @return контекст ДСТУ 4145
     */
    Dstu4145CtxPointer dstu4145_copy_with_alloc(final Dstu4145CtxPointer param);

    /**
     * Генерує закритий ключ ДСТУ 4145.
     *
     * @param ctx контекст ДСТУ 4145
     * @param prng контекст ГПСЧ
     * @param d закритий ключ ДСТУ 4145
     * @return код помилки
     */
    int dstu4145_generate_privkey(final Dstu4145CtxPointer ctx, PrngCtxPointer prng, PointerByReference d);

    /**
     * Формує відкритий ключ за закритим.
     *
     * @param ctx контекст ДСТУ 4145
     * @param d закритий ключ
     * @param qx Х-координата відкритого ключа
     * @param qy Y-координата відкритого ключа
     * @return код помилки
     */
    int dstu4145_get_pubkey(final Dstu4145CtxPointer ctx, final ByteArrayPointer d, PointerByReference qx, PointerByReference qy);

    /**
     * Формує стисле представлення відкритого ключа.
     *
     * @param ctx контекст ДСТУ 4145
     * @param qx Х-координата відкритого ключа
     * @param qy Y-координата відкритого ключа
     * @param q стисле представлення відкритого ключа
     * @return код помилки
     */
    int dstu4145_compress_pubkey(final Dstu4145CtxPointer ctx, final ByteArrayPointer qx, final ByteArrayPointer qy,
        PointerByReference q);

    /**
     * Формує розгорнуте представлення відкритого ключа.
     *
     * @param ctx контекст ДСТУ 4145
     * @param q стисле представлення відкритого ключа
     * @param qx Х-координата відкритого ключа
     * @param qy Y-координата відкритого ключа
     * @return код помилки
     */
    int dstu4145_decompress_pubkey(final Dstu4145CtxPointer ctx, final ByteArrayPointer q, PointerByReference qx,
        PointerByReference qy);

    /**
     * Встановити рівень передобчислення.
     *
     * @param ctx контекст ДСТУ 4145
     * @param opt_level рівень передобчислення
     * @return код помилки
     */
    int dstu4145_set_opt_level(Dstu4145CtxPointer ctx, OptLevelId opt_level);

    /**
     * Ініціалізує контекст для формування підписів.
     *
     * @param ctx контекст ДСТУ 4145
     * @param d закритий ключ
     * @param prng контекст ГПСЧ
     * @return код помилки
     */
    int dstu4145_init_sign(Dstu4145CtxPointer ctx, final ByteArrayPointer d, PrngCtxPointer prng);

    /**
     * Формує підпис по гешу.
     *
     * @param ctx контекст ДСТУ 4145
     * @param hash геш
     * @param r частина підпису
     * @param s частину підпису
     * @return код помилки
     */
    int dstu4145_sign(final Dstu4145CtxPointer ctx, final ByteArrayPointer hash, PointerByReference r, PointerByReference s);

    /**
     * Ініціалізує контекст для перевірки підписів.
     *
     * @param ctx контекст ДСТУ 4145
     * @param qx Х-координата відкритого ключа
     * @param qy Y-координата відкритого ключа
     * @return код помилки
     */
    int dstu4145_init_verify(Dstu4145CtxPointer ctx, final ByteArrayPointer qx, final ByteArrayPointer qy);

    /**
     * Виконує перевірку підпису з гешу від даних.
     *
     * @param ctx контекст ДСТУ 4145
     * @param hash геш
     * @param r частина підпису
     * @param s частина підпису
     * @return код помилки або RET_OK, якщо підпис вірний
     */
    int dstu4145_verify(final Dstu4145CtxPointer ctx, final ByteArrayPointer hash, final ByteArrayPointer r,
        ByteArrayPointer s);

    /**
     * Повертає загальне секретне значення по схемі Диффі-Хеллмана з кофактором згідно ДСТУ 4145.
     *
     * @param ctx контекст ДСТУ 4145
     * @param with_cofactor алгоритм з кофакторним множенням
     * @param d закритий ключ
     * @param qx Х-координата відкритого ключа
     * @param qy Y-координата відкритого ключа
     * @param zx Х-координата спільного секретного значення
     * @param zy Y-координата спільного секретного значення
     * @return код помилки
     */
    int dstu4145_dh(final Dstu4145CtxPointer ctx, boolean with_cofactor, final ByteArrayPointer d, final ByteArrayPointer qx,
        ByteArrayPointer qy, PointerByReference zx, PointerByReference zy);

    /**
     * Звільняє контекст ДСТУ 4145.
     *
     * @param ctx контекст ДСТУ 4145
     */
    void dstu4145_free(Dstu4145CtxPointer ctx);

    /**
     * Створює контекст ДСТУ 7564 зі стандартною таблицею замін.
     *
     * @param sbox_id ідентифікатор стандартної таблиці замін
     * @return контекст ДСТУ 7564
     */
    Dstu7564CtxPointer dstu7564_alloc(final Dstu7564SboxId sbox_id);

    /**
     * Створює контекст ДСТУ 7564 з користувацьким sbox.
     *
     * @param sbox користувацька таблиця замін розміром 1024 байт
     * @return контекст ДСТУ 7564
     */
    Dstu7564CtxPointer dstu7564_alloc_user_sbox(final ByteArrayPointer sbox);

    /**
     * Ініціалізація контексту DSTU7564.
     *
     * @param ctx контекст ДСТУ 7564
     * @param hash_len байтовий розмір геша, значення у межі 1..64 байт
     * @return код помилки
     */
    int dstu7564_init(Dstu7564CtxPointer ctx, @size_t long hash_len);

    /**
     * Модифікує геш-вектор фрагментом даних.
     *
     * @param ctx контекст ДСТУ 7564
     * @param data дані
     * @return код помилки
     */
    int dstu7564_update(Dstu7564CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує вироботку геша і повертає його значення.
     *
     * @param ctx контекст ДСТУ 7564
     * @param hash геш від даних
     * @return код помилки
     */
    int dstu7564_final(Dstu7564CtxPointer ctx, PointerByReference hash);

    /**
     * Ініціалізує контекст ДСТУ 7564 для створення кода аутентификації.
     *
     * @param ctx контекст ДСТУ 7564
     * @param key ключ аутентификации для режиму kmac
     * @param mac_len розмір імітовставки (байт), значення 32, 48, 64
     * @return код помилки
     */
    int dstu7564_init_kmac(Dstu7564CtxPointer ctx, final ByteArrayPointer key, @size_t long mac_len);

    /**
     * Модифікує геш-вектор фрагментом даних.
     *
     * @param ctx контекст ДСТУ 7564
     * @param data дані
     * @return код помилки
     */
    int dstu7564_update_kmac(Dstu7564CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує вироботку геша і повертає його значення.
     *
     * @param ctx контекст ДСТУ 7564
     * @param mac код аутентификации
     * @return код помилки
     */
    int dstu7564_final_kmac(Dstu7564CtxPointer ctx, PointerByReference mac);

    /**
     * Звільняє контекст ДСТУ 7564.
     *
     * @param ctx контекст ДСТУ 7564
     */
    void dstu7564_free(Dstu7564CtxPointer ctx);

    /**
     * Створює контекст ДСТУ 7624 зі стандартним sbox.
     *
     * @param sbox_id ідентифікатор стандартної таблиці замін
     * @return контекст ДСТУ 7624
     */
    Dstu7624CtxPointer dstu7624_alloc(Dstu7624SboxId sbox_id);

    /**
     * Створює контекст ДСТУ 7624 з користувацьким sbox.
     *
     * @param sbox користувацький sbox
     * @return контекст ДСТУ 7624
     */
    Dstu7624CtxPointer dstu7624_alloc_user_sbox(ByteArrayPointer sbox);

    /**
     * Генерує секретний ключ.
     *
     * @param prng контекст ГПСЧ
     * @param key_len розмір ключа 16, 32 или 64
     * @param key секретний ключ
     * @return код помилки
     */
    int dstu7624_generate_key(PrngCtxPointer prng, @size_t long key_len, PointerByReference key);

    /**
     * Ініціалізує контекст для шифрування у режимі простої заміни.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param block_size розмір блока, 16, 32, 64 байт
     * @return код помилки
     */
    int dstu7624_init_ecb(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final @size_t long block_size);

    /**
     * Ініціалізує контекст для шифрування у режимі гамування.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param iv синхропосилка, розміром блоку
     * @return код помилки
     */
    int dstu7624_init_ctr(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізує контекст для шифрування у режимі гамування з обратним зв'язком.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
     * @param q кількість байт, які будуть шифруватися за один цикл
     * @return код помилки
     */
    int dstu7624_init_cfb(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv, final @size_t long q);

    /**
     * Ініціалізує контекст для шифрування у режимі зчеплення шифроблоків.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
     * @return код помилки
     */
    int dstu7624_init_cbc(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізує контекст для шифрування у режимі гамування зі зворотним зв'язком по шифрограммі.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
     * @return код помилки
     */
    int dstu7624_init_ofb(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізує контекст для шифрування у режимі вибіркового гамування з прискореною виробкою імітовставки.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
     * @param q розмір імітовставки
     * @return код помилки
     */
    int dstu7624_init_gcm(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv, final @size_t long q);

    /**
     * Ініціалізує контекст для обчислення імітовставки.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param block_size розмір блока, 16, 32, 64 байт
     * @param q довжина імітовставки.
     * @return код помилки
     */
    int dstu7624_init_cmac(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final @size_t long block_size,
        @size_t long q);

    /**
     * Ініціалізує контекст для шифрування у режимі вибіркового гамування з прискореною виробкою імітовставки.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param block_size розмір блока, 16, 32, 64 байт
     * @param q розмір імітовставки
     * @return код помилки
     */
    int dstu7624_init_gmac(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final @size_t long block_size,
        @size_t long q);

    /**
     * Ініціалізує контекст для шифрування у режимі виробки імітовставки і гамування.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
     * @param q розмір імітовставки
     * @param n_max найбільша можлива довжина відкритої або конфіденційної частини повідомлення (в бітах)
     * @return код помилки
     */
    int dstu7624_init_ccm(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv, final @size_t long q,
        long n_max);

    /**
     * Ініціалізує контекст для шифрування у режимі індексованої заміни.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
     * @return код помилки
     */
    int dstu7624_init_xts(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізує контекст для шифрування у режимі захисту ключових даних.
     *
     * @param ctx контекст ДСТУ 7624
     * @param key ключ шифрування
     * @param block_size розмір блока, 16, 32, 64 байт
     * @return код помилки
     */
    int dstu7624_init_kw(Dstu7624CtxPointer ctx, final ByteArrayPointer key, final @size_t long block_size);

    /**
     * Шифрування та вироблення імітовставки.
     *
     * @param ctx контекст ДСТУ 7624
     * @param auth_data відкритий текст повідомлення
     * @param data дані для шифрування
     * @param mac імітовставка
     * @param encrypted_data зашифроване повідомлення
     * @return код помилки
     */
    int dstu7624_encrypt_mac(Dstu7624CtxPointer ctx, final ByteArrayPointer auth_data, final ByteArrayPointer data,
        PointerByReference mac, PointerByReference encrypted_data);

    /**
     * Розшифрування та забезпечення цілосності.
     *
     * @param ctx контекст ДСТУ 7624
     * @param auth_data відкритий текст повідомлення
     * @param encrypted_data дані для розшифрування
     * @param mac імітовставка
     * @param data розшифроване повідомлення
     * @return код помилки
     */
    int dstu7624_decrypt_mac(Dstu7624CtxPointer ctx, final ByteArrayPointer auth_data,
        ByteArrayPointer encrypted_data, ByteArrayPointer mac, PointerByReference data);

    /**
     * Шифрування даних.
     *
     * @param ctx контекст ДСТУ 7624
     * @param data дані для шифрування
     * @param encrypted_data зашифровані дані
     *
     * @return код помилки
     */
    int dstu7624_encrypt(Dstu7624CtxPointer ctx, final ByteArrayPointer data, PointerByReference encrypted_data);

    /**
     * Розшифрування даних.
     *
     * @param ctx контекст ДСТУ 7624
     * @param encrypted_data зашифровані дані
     * @param data розшифровані дані
     *
     * @return код помилки
     */
    int dstu7624_decrypt(Dstu7624CtxPointer ctx, final ByteArrayPointer encrypted_data, PointerByReference data);

    /**
     * Доповнює імітовставку блоком даних.
     *
     * @param ctx контекст ДСТУ 7624
     * @param data дані
     *
     * @return код помилки
     */
    int dstu7624_update_mac(Dstu7624CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує виробку імітовставки і повертає її значення.
     *
     * @param ctx контекст ДСТУ 7624
     * @param mac імітовставка
     *
     * @return код помилки
     */
    int dstu7624_final_mac(Dstu7624CtxPointer ctx, PointerByReference mac);

    /**
     * Звільняє контекст ДСТУ 7624.
     *
     * @param ctx контекст ДСТУ 7624
     */
    void dstu7624_free(Dstu7624CtxPointer ctx);

    /**
     * Створює контекст ECDSA зі стандартними параметрами.
     *
     * @param params_id ідентифікатор стандартних параметрів
     * @return контекст ECDSA
     */
    EcdsaCtxPointer ecdsa_alloc(EcdsaParamsId params_id);

    /**
     * Створює контекст ECDSA за параметрами.
     *
     * @param p порядок скінченного простого поля GF(p)
     * @param a коефіцієнт a у рівнянні еліптичної кривої
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param q порядок базової точки
     * @param px X-координата базової точки
     * @param py Y-координата базової точки
     *
     * @return контекст ECDSA
     */
    EcdsaCtxPointer ecdsa_alloc_ext(final ByteArrayPointer p, final ByteArrayPointer a, final ByteArrayPointer b,
        ByteArrayPointer q, final ByteArrayPointer px, final ByteArrayPointer py);

    /**
     * Повертає параметри ECDSA.
     *
     * @param ctx контекст ECDSA
     * @param p порядок скінченного простого поля GF(p)
     * @param a коефіцієнт a у рівнянні еліптичної кривої
     * @param b коефіцієнт b у рівнянні еліптичної кривої
     * @param q порядок базової точки
     * @param px X-координата базової точки
     * @param py Y-координата базової точки
     *
     * @return код помилки
     */
    int ecdsa_get_params(EcdsaCtxPointer ctx, PointerByReference p, PointerByReference a, PointerByReference b, PointerByReference q,
        PointerByReference px, PointerByReference py);

    /**
     * Визначає чи параметри однакові ECDSA.
     *
     * @param param_a контекст ECDSA
     * @param param_b контекст ECDSA
     * @param equals чи параметри однакові
     * @return код помилки
     */
    int ecdsa_equals_params(final EcdsaCtxPointer param_a, final EcdsaCtxPointer param_b, boolean equals);

    /**
     * Копіює параметри ECDSA.
     *
     * @param param контекст ECDSA
     * @return контекст ECDSA
     */
    EcdsaCtxPointer ecdsa_copy_params_with_alloc(final EcdsaCtxPointer param);

    /**
     * Копіює контекст ECDSA.
     *
     * @param param контекст ECDSA
     * @return контекст ECDSA
     */
    EcdsaCtxPointer ecdsa_copy_with_alloc(final EcdsaCtxPointer param);

    /**
     * Генерує закритий ключ ECDSA.
     *
     * @param ctx контекст ECDSA
     * @param prng контекст ГПСЧ
     * @param d закритий ключ ECDSA
     * @return код помилки
     */
    int ecdsa_generate_privkey(EcdsaCtxPointer ctx, PrngCtxPointer prng, PointerByReference d);

    /**
     * Формує відкритий ключ по закритому.
     *
     * @param ctx контекст ECDSA
     * @param d закритий ключ
     * @param qx Х-координата відкритого ключа
     * @param qy Y-координата відкритого ключа
     * @return код помилки
     */
    int ecdsa_get_pubkey(EcdsaCtxPointer ctx, final ByteArrayPointer d, PointerByReference qx, PointerByReference qy);
    int ecdsa_compress_pubkey(EcdsaCtxPointer ctx, final ByteArrayPointer qx, final ByteArrayPointer qy, PointerByReference q,
        int last_qy_bit);
    int ecdsa_decompress_pubkey(EcdsaCtxPointer ctx, final ByteArrayPointer q, int last_qy_bit, PointerByReference qx,
        PointerByReference qy);
    int ecdsa_set_opt_level(EcdsaCtxPointer ctx, OptLevelId opt_level);

    /**
     * Ініціалізує контекст для формування підпису.
     *
     * @param ctx контекст ECDSA
     * @param d закритий ключ
     * @param prng контекст ГПСЧ
     * @return код помилки
     */
    int ecdsa_init_sign(EcdsaCtxPointer ctx, final ByteArrayPointer d, PrngCtxPointer prng);

    /**
     * Формує підпис по гешу.
     *
     * @param ctx контекст ECDSA
     * @param hash геш
     * @param r частина підпису
     * @param s частина підпису
     * @return код помилки
     */
    int ecdsa_sign(EcdsaCtxPointer ctx, final ByteArrayPointer hash, PointerByReference r, PointerByReference s);

    /**
     * Ініціалізує контекст для перевірки підпису.
     *
     * @param ctx контекст ECDSA
     * @param qx Х-координата відкритого ключа
     * @param qy Y-координата відкритого ключа
     * @return код помилки
     */
    int ecdsa_init_verify(EcdsaCtxPointer ctx, final ByteArrayPointer qx, final ByteArrayPointer qy);

    /**
     * Виконує перевірку підпису по гешу від даних.
     *
     * @param ctx контекст ECDSA
     * @param hash геш
     * @param r частина підпису
     * @param s частина підпису
     *
     * @return код помилки або RET_OK, якщо підпис вірний
     */
    int ecdsa_verify(EcdsaCtxPointer ctx, final ByteArrayPointer hash, final ByteArrayPointer r, final ByteArrayPointer s);

    /**
     * Звільняє контекст ECDSA.
     *
     * @param ctx контекст ECDSA
     *
     */
    void ecdsa_free(EcdsaCtxPointer ctx);

    /**
     * Створює контекст ГОСТ 28147 зі стандартною таблицею замін.
     *
     * @param sbox_id ідентифікатор стандартної таблиці замін
     * @return контекст ГОСТ 28147
     */
    Gost28147CtxPointer gost28147_alloc(Gost28147SboxId sbox_id);

    /**
     * Створює контекст ГОСТ 28147 з користувацьким sbox.
     *
     * @param sbox користувацька таблиця замін разміром 128 байт
     * @return контекст ГОСТ 28147
     */
    Gost28147CtxPointer gost28147_alloc_user_sbox(final ByteArrayPointer sbox);
    Gost28147CtxPointer gost28147_copy_with_alloc(final Gost28147CtxPointer ctx);

    /**
     * Повертає розгорнуту таблицю замін.
     *
     * @param ctx контекст ГОСТ 28147
     * @param sbox таблиця замін разміром 128 байт
     * @return код помилки
     */
    int gost28147_get_ext_sbox(final Gost28147CtxPointer ctx, PointerByReference sbox);

    /**
     * Повертає зжату таблицю замін.
     *
     * @param ctx контекст ГОСТ 28147
     * @param sbox таблиця замін разміром 128 байт
     * @return код помилки
     */
    int gost28147_get_compress_sbox(final Gost28147CtxPointer ctx, PointerByReference sbox);

    /**
     * Генерує секретний ключ відповідно до ГОСТ 28147-89.
     *
     * @param prng контекст ГПСЧ
     * @param key секретний ключ
     * @return код помилки
     */
    int gost28147_generate_key(PrngCtxPointer prng, PointerByReference key);

    /**
     * Ініціалізує контекст для шифрування у режимі простої заміни.
     *
     * @param ctx контекст ГОСТ 28147
     * @param key ключ шифрування
     * @return код помилки
     */
    int gost28147_init_ecb(Gost28147CtxPointer ctx, final ByteArrayPointer key);

    /**
     * Ініціалізує контекст для шифрування у режимі гамування.
     *
     * @param ctx контекст ГОСТ 28147
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int gost28147_init_ctr(Gost28147CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізує контекст для шифрування у режимі гамування зі зворотнім зв'язком.
     *
     * @param ctx контекст ГОСТ 28147
     * @param key ключ шифрування
     * @param iv синхропосилка
     * @return код помилки
     */
    int gost28147_init_cfb(Gost28147CtxPointer ctx, final ByteArrayPointer key, final ByteArrayPointer iv);

    /**
     * Ініціалізує контекст для отримання імітовставки.
     *
     * @param ctx контекст ГОСТ 28147
     * @param key ключ шифрування
     * @return код помилки
     */
    int gost28147_init_mac(Gost28147CtxPointer ctx, final ByteArrayPointer key);

    /**
     * Шифрує блок даних.
     *
     * @param ctx контекст ГОСТ 28147
     * @param data дані для шифрування
     * @param encrypted_data зашифровані дані
     *
     * @return код помилки
     */
    int gost28147_encrypt(Gost28147CtxPointer ctx, final ByteArrayPointer data, PointerByReference encrypted_data);

    /**
     * Розшифровує блок даних.
     *
     * @param ctx контекст ГОСТ 28147
     * @param encrypted_data зашифровані дані
     * @param data розшифровані дані
     * @return код помилки
     */
    int gost28147_decrypt(Gost28147CtxPointer ctx, final ByteArrayPointer encrypted_data, PointerByReference data);

    /**
     * Обновлюемо імітовектор блоком даних.
     *
     * @param ctx контекст ГОСТ 28147
     * @param data дані
     * @return код помилки
     */
    int gost28147_update_mac(Gost28147CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершуе вироботку імітовектора і повертає його значення.
     *
     * @param ctx контекст ГОСТ 28147
     * @param mac імітовектор
     *
     * @return код помилки
     */
    int gost28147_final_mac(Gost28147CtxPointer ctx, PointerByReference mac);

    /**
     * Завершує вироботку імітовектора і повертає його розширене значення.
     *
     * @param ctx контекст ГОСТ 28147
     * @param mac розширений імітовектор
     *
     * @return код помилки
     */
    int gost28147_final_mac8(Gost28147CtxPointer ctx, PointerByReference mac);

    /**
     * Звільняє контекст ГОСТ 28147.
     *
     * @param ctx контекст ГОСТ 28147
     */
    void gost28147_free(Gost28147CtxPointer ctx);

    /**
     * Створює контекст ГОСТ 34.311 зі стандартним sbox.
     *
     * @param sbox_id ідентифікатор стандартной таблиці замін
     * @param sync синхропосилка
     * @return контекст ГОСТ 34.311
     */
    Gost34311CtxPointer gost34_311_alloc(Gost28147SboxId sbox_id, final ByteArrayPointer sync);

    /**
     * Створює контекст ГОСТ 34.311 з користувацьким sbox.
     *
     * @param sbox користувацький sbox
     * @param sync синхропосилка
     * @return контекст ГОСТ 34.311
     */
    Gost34311CtxPointer gost34_311_alloc_user_sbox(final ByteArrayPointer sbox, final ByteArrayPointer sync);
    Gost34311CtxPointer gost34_311_copy_with_alloc(final Gost34311CtxPointer ctx);

    /**
     * Модифікує геш-вектор фрагментом даних.
     *
     * @param ctx контекст ГОСТ 34.311
     * @param data дані для шифрування
     * @return код помилки
     */
    int gost34_311_update(Gost34311CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує вироботку геша і повертає його значення.
     *
     * @param ctx контекст ГОСТ 34.311
     * @param hash геш вектор
     * @return код помилки
     */
    int gost34_311_final(Gost34311CtxPointer ctx, PointerByReference hash);

    /**
     * Звільняє контекст ГОСТ 34.311.
     *
     * @param ctx контекст ГОСТ 34.311
     */
    void gost34_311_free(Gost34311CtxPointer ctx);

    /**
     * Створює контекст HMAC на базі ГОСТ 34.311 зі стандартним sbox.
     *
     * @param sbox_id ідентифікатор стандартної таблиці замін
     * @param sync синхропосилка
     * @return контекст HMAC
     */
    HmacCtxPointer hmac_alloc_gost34_311(Gost28147SboxId sbox_id, final ByteArrayPointer sync);

    /**
     * Створює контекст HMAC на базі ГОСТ 34.311 зі стандартним sbox.
     *
     * @param sbox користувацький sbox
     * @param sync синхропосилка
     * @return контекст HMAC
     */
    HmacCtxPointer hmac_alloc_gost34_311_user_sbox(final ByteArrayPointer sbox, final ByteArrayPointer sync);

    /**
     * Створює контекст HMAC на базі SHA1.
     *
     * @return контекст HMAC
     */
    HmacCtxPointer hmac_alloc_sha1();

    /**
     * Створює контекст HMAC на базі SHA2.
     *
     * @param variant тип геша
     * @return контекст HMAC
     */
    HmacCtxPointer hmac_alloc_sha2(Sha2Variant variant);

    /**
     * Створює контекст HMAC на базі MD5.
     *
     * @return контекст HMAC
     */
    HmacCtxPointer hmac_alloc_md5();

    /**
     * Ініціалізує контекст для виробки HMAC.
     *
     * @param ctx контекст
     * @param key секретний ключ
     * @return код помилки
     */
    int hmac_init(HmacCtxPointer ctx, final ByteArrayPointer key);

    /**
     * Модифікує геш-вектор фрагментом даних.
     *
     * @param ctx контекст ГОСТ 34.311
     * @param data дані для шифрування
     * @return код помилки
     */
    int hmac_update(HmacCtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує вироботку геша і повертає його значення.
     *
     * @param ctx контекст ГОСТ 34.311
     * @param hash геш вектор
     * @return код помилки
     */
    int hmac_final(HmacCtxPointer ctx, PointerByReference hash);

    /**
     * Звільняє контекст ГОСТ 34.311.
     *
     * @param ctx контекст ГОСТ 34.311
     */
    void hmac_free(HmacCtxPointer ctx);

    /**
     * Створює контекст MD5.
     *
     * @return контекст MD5
     */
    Md5CtxPointer md5_alloc();

    /**
     * Модифікує геш-вектор фрагментом даних.
     *
     * @param ctx контекст MD5
     * @param data фрагмент даних
     * @return код помилки
     */
    int md5_update(Md5CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує обчислення геш-вектора і повертає його значення.
     *
     * @param ctx контекст MD5
     * @param hash геш-вектор
     * @return код помилки
     */
    int md5_final(Md5CtxPointer ctx, PointerByReference hash);

    /**
     * Звільняє контекст MD5.
     *
     * @param ctx контекст MD5
     */
    void md5_free(Md5CtxPointer ctx);

    /**
     * Створює контекст ГПВЧ.
     *
     * @param mode режим ГПВЧ
     * @param seed послідовність випадкових байт
     * @return контекст ГПВЧ
     */
    PrngCtxPointer prng_alloc(PrngMode mode, final ByteArrayPointer seed);
    int prng_get_mode(PrngCtxPointer prng, PrngMode mode);

    /**
     * Домішує випадковість у стартовий вектор генератора.
     *
     * @param prng контекст ГПВЧ
     * @param seed послідовність випадкових байт
     * @return код помилки
     */
    int prng_seed(PrngCtxPointer prng, final ByteArrayPointer seed);

    /**
     * Повертає масив псевдовипадкових байт.
     *
     * @param prng контекст генерації псевдовипдкових чисел
     * @param buf буфер, в якому будуть розміщені псевдовипадкові байти
     * @return код помилки
     */
    int prng_next_bytes(PrngCtxPointer prng, ByteArrayPointer buf);

    /**
     * Звільняє контекст ГПВЧ.
     *
     * @param prng контекст ГПВЧ
     */
    void prng_free(PrngCtxPointer prng);

    /**
     * Заповнює масив випадковими байтами використовуючи системний ГПВЧ.
     *
     * @param buf масив для розміщення випадкових байт
     * @return код помилки
     */
    int rs_std_next_bytes(ByteArrayPointer buf);

    /**
     * Заповнює масив випадковими байтами на основі непередбачуваності часу зчитування з оперативної пам'яті фіксованого числа байт.
     *
     * @param buf масив для розміщення випадкових байт
     * @return код помилки
     */
    int rs_memory_next_bytes(ByteArrayPointer buf);

    /**
     * Створює контекст RSA.
     *
     * @return контекст RSA
     */
    RsaCtxPointer rsa_alloc();

    /**
     * Генерує закритий ключ RSA.
     *
     * @param ctx контекст RSA
     * @param prng ГПВЧ
     * @param bits бітність ключа
     * @param e відкрита експонента
     * @param n модуль
     * @param d секретна експонента
     * @return код помилки
     */
    int rsa_generate_privkey(RsaCtxPointer ctx, PrngCtxPointer prng, final @size_t long bits, final ByteArrayPointer e,
        PointerByReference n, PointerByReference d);

    /**
     * Генерує закритий ключ RSA.
     *
     * @param ctx контекст RSA
     * @param prng ГПВЧ
     * @param bits бітність ключа
     * @param e відкрита експонента
     * @param n модуль
     * @param d закрита експонента
     * @param p просте число №1
     * @param q просте число №2
     * @param dmp1 d mod (p-1)
     * @param dmq1 d mod (q-1)
     * @param iqmp зворотній елемент q
     * @return код помилки
     */
    int rsa_generate_privkey_ext(RsaCtxPointer ctx, PrngCtxPointer prng, final @size_t long bits, final ByteArrayPointer e,
        PointerByReference n, PointerByReference d, PointerByReference p, PointerByReference q, PointerByReference dmp1, PointerByReference dmq1, PointerByReference iqmp);

    /**
     * Перевіряє закритий ключ RSA.
     *
     * @param ctx контекст RSA
     * @param n модуль
     * @param e відкрита експонента
     * @param d закрита експонента
     * @param p просте число №1
     * @param q просте число №2
     * @param dmp1 d mod (p-1)
     * @param dmq1 d mod (q-1)
     * @param iqmp зворотній елемент q
     * @return код помилки
     */
    boolean rsa_validate_key(RsaCtxPointer ctx, final ByteArrayPointer n, final ByteArrayPointer e, final ByteArrayPointer d,
        ByteArrayPointer p, final ByteArrayPointer q, final ByteArrayPointer dmp1, final ByteArrayPointer dmq1, final ByteArrayPointer iqmp);

    /**
     * Ініціалізація контексту RSA для режиму OAEP.
     *
     * @param ctx контекст RSA
     * @param prng ГПВЧ
     * @param htype вибір геша. Береться з RsaHashType
     * @param label необов'язкова мітка, яка асоціюється з повідомленням;
     * значення за замовчуванням - пустий рядок
     * @param n модуль
     * @param e відкрита експонента
     * @return код помилки
     */
    int rsa_init_encrypt_oaep(RsaCtxPointer ctx, PrngCtxPointer prng, RsaHashType htype, ByteArrayPointer label,
        ByteArrayPointer n, final ByteArrayPointer e);

    /**
     * Ініціалізація контексту RSA для режиму OAEP.
     *
     * @param ctx контекст RSA
     * @param htype вибір геша. Береться з RsaHashType
     * @param label необов'язкова мітка, яка асоціюється з повідомленням;
     * значення за замовчуванням - пустий рядок
     * @param n модуль
     * @param d закрита экспонента
     * @return код помилки
     */
    int rsa_init_decrypt_oaep(RsaCtxPointer ctx, RsaHashType htype, ByteArrayPointer label, final ByteArrayPointer n,
        ByteArrayPointer d);

    /**
     * Ініціалізація контексту RSA для режиму PKCS1_5.
     *
     * @param ctx контекст RSA
     * @param prng ГПВЧ
     * @param n модуль
     * @param e відкрита експонента
     * @return код помилки
     */
    int rsa_init_encrypt_pkcs1_v1_5(RsaCtxPointer ctx, PrngCtxPointer prng, final ByteArrayPointer n, final ByteArrayPointer e);

    /**
     * Ініціалізація контексту RSA для режиму PKCS1_5.
     *
     * @param ctx контекст RSA
     * @param n модуль
     * @param d закрита экспонента
     * @return код помилки
     */
    int rsa_init_decrypt_pkcs1_v1_5(RsaCtxPointer ctx, final ByteArrayPointer n, final ByteArrayPointer d);

    /**
     * Шифрування даних.
     *
     * @param ctx контекст RSA
     * @param data дані для шифрування
     * @param encrypted_data зашифровані дані
     * @return код помилки
     */
    int rsa_encrypt(RsaCtxPointer ctx, final ByteArrayPointer data, PointerByReference encrypted_data);

    /**
     * Розшифрування даних.
     *
     * @param ctx контекст RSA
     * @param encrypted_data дані для розшифрування
     * @param data розшифровані дані
     * @return код помилки
     */
    int rsa_decrypt(RsaCtxPointer ctx, final ByteArrayPointer encrypted_data, PointerByReference data);

    /**
     * Ініціалізує контекст RSA для формування ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
     *
     * @param ctx контекст RSA
     * @param hash_type тип геша
     * @param n модуль
     * @param d закрита експонента
     * @return код помилки
     */
    int rsa_init_sign_pkcs1_v1_5(RsaCtxPointer ctx, RsaHashType hash_type, final ByteArrayPointer n,
        ByteArrayPointer d);

    /**
     * Формує ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
     *
     * @param ctx контекст RSA
     * @param hash значення геша
     * @param sign підпис RSA
     * @return код помилки
     */
    int rsa_sign_pkcs1_v1_5(RsaCtxPointer ctx, final ByteArrayPointer hash, PointerByReference sign);

    /**
     * Ініціалізує контекст RSA для перевірки ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
     *
     * @param ctx контекст RSA
     * @param hash_type тип геша
     * @param n модуль
     * @param e відкрита экспонента
     * @return код помилки
     */
    int rsa_init_verify_pkcs1_v1_5(RsaCtxPointer ctx, RsaHashType hash_type, final ByteArrayPointer n,
        ByteArrayPointer e);

    /**
     * Перевіряє ЕЦП згідно з PKCS#1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
     *
     * @param ctx контекст RSA
     * @param hash значення геша
     * @param sign підпис RSA
     * @return код помилки або RET_OK, якщо підпис вірний
     */
    int rsa_verify_pkcs1_v1_5(RsaCtxPointer ctx, final ByteArrayPointer hash, final ByteArrayPointer sign);

    /**
     * Звільняє контекст RSA.
     *
     * @param ctx контекст RSA
     */
    void rsa_free(RsaCtxPointer ctx);

    /**
     * Створює контекст SHA1.
     *
     * @return контекст SHA1
     */
    Sha1CtxPointer sha1_alloc();
    Sha1CtxPointer sha1_copy_with_alloc(final Sha1CtxPointer ctx);

    /**
     * Модифікує геш-вектор фрагментом даних.
     *
     * @param ctx контекст SHA1
     * @param data дані
     * @return код помилки
     */
    int sha1_update(Sha1CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує виробку геша і повертає його значення.
     *
     * @param ctx контекст SHA1
     * @param out геш від даних
     * @return код помилки
     */
    int sha1_final(Sha1CtxPointer ctx, PointerByReference out);

    /**
     * Звільняє контекст SHA1.
     *
     * @param ctx контекст SHA1
     */
    void sha1_free(Sha1CtxPointer ctx);

    Sha2CtxPointer sha2_alloc(Sha2Variant variant);
    Sha2CtxPointer sha2_copy_with_alloc(final Sha2CtxPointer ctx);

    /**
     * Модифікує геш-вектор фрагментом даних.
     *
     * @param ctx контекст SHA2
     * @param data дані
     * @return код помилки
     */
    int sha2_update(Sha2CtxPointer ctx, final ByteArrayPointer data);

    /**
     * Завершує обчислення геш-вектора і повертає його значення.
     *
     * @param ctx контекст SHA2
     * @param out геш від даних
     * @return код помилки
     */
    int sha2_final(Sha2CtxPointer ctx, PointerByReference out);

    /**
     * Звільняє контекст SHA2.
     *
     * @param ctx контекст SHA2
     */
    void sha2_free(Sha2CtxPointer ctx);

    ErrorCtx stacktrace_get_last();
    void stacktrace_create(final String file, final @size_t long line, final int error_code, final String msg);
    void stacktrace_add(final String file, final @size_t long line, final int error_code);
    ErrorCtx stacktrace_get_last_with_alloc();
    void error_ctx_free(ErrorCtx err);
    void stacktrace_free_current();
    void stacktrace_finalize();

}