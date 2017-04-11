/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum EcdsaParamsId implements IntegerEnum {

    /**
     * ідентифікатори стандартних параметрів ECDSA.
     */
    ECDSA_PARAMS_ID_SEC_P192_R1(1),
    ECDSA_PARAMS_ID_SEC_P224_R1(2),
    ECDSA_PARAMS_ID_SEC_P256_R1(3),
    ECDSA_PARAMS_ID_SEC_P384_R1(4),
    ECDSA_PARAMS_ID_SEC_P521_R1(5);

    EcdsaParamsId(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
