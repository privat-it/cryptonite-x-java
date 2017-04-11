/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.id;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Pbkdf2HmacId implements IntegerEnum {

    PBKDF2_GOST_HMAC_ID(0),
    PBKDF2_SHA1_HMAC_ID(1),
    PBKDF2_SHA224_HMAC_ID(2),
    PBKDF2_SHA256_HMAC_ID(3),
    PBKDF2_SHA384_HMAC_ID(4),
    PBKDF2_SHA512_HMAC_ID(5);

    Pbkdf2HmacId(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
