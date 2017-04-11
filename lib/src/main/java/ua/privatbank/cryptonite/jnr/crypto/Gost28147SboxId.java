/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Gost28147SboxId implements IntegerEnum {

    /**
     *Ідентифікатори стандартних таблиць замін.
     */
    GOST28147_SBOX_ID_1(1),   /** Таблиця замін ДКЕ №1 із доповнення 1 до інструкції №114. */
    GOST28147_SBOX_ID_2(2),   /** Таблиця замін ДКЕ №1 із доповнення 2 до інструкції №114. */
    GOST28147_SBOX_ID_3(3),   /** Таблиця замін ДКЕ №1 із доповнення 3 до інструкції №114. */
    GOST28147_SBOX_ID_4(4),   /** Таблиця замін ДКЕ №1 із доповнення 4 до інструкції №114. */
    GOST28147_SBOX_ID_5(5),   /** Таблиця замін ДКЕ №1 із доповнення 5 до інструкції №114. */
    GOST28147_SBOX_ID_6(6),   /** Таблиця замін ДКЕ №1 із доповнення 6 до інструкції №114. */
    GOST28147_SBOX_ID_7(7),   /** Таблиця замін ДКЕ №1 із доповнення 7 до інструкції №114. */
    GOST28147_SBOX_ID_8(8),   /** Таблиця замін ДКЕ №1 із доповнення 8 до інструкції №114. */
    GOST28147_SBOX_ID_9(9),   /** Таблиця замін ДКЕ №1 із доповнення 9 до інструкції №114. */
    GOST28147_SBOX_ID_10(10), /** Таблиця замін ДКЕ №1 із доповнення 10 до інструкції №114. */
    GOST28147_SBOX_ID_11(11), /** Таблиця замін з ГОСТ 34.311-95. */
    GOST28147_SBOX_ID_12(12), /** Таблиця замін CryptoPro-Test з RFC-4357. */
    GOST28147_SBOX_ID_13(13), /** Таблиця замін CryptoPro-A з RFC-4357. */
    GOST28147_SBOX_ID_14(14), /** Таблиця замін CryptoPro-B з RFC-4357. */
    GOST28147_SBOX_ID_15(15), /** Таблиця замін CryptoPro-C з RFC-4357. */
    GOST28147_SBOX_ID_16(16), /** Таблиця замін CryptoPro-D з RFC-4357. */
    GOST28147_SBOX_ID_17(17), /** Таблиця замін id-GostR3411-94-CryptoProParamSet з RFC-4357. */
    GOST28147_SBOX_ID_18(18); /** Таблиця замін з openssl */

    Gost28147SboxId(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
