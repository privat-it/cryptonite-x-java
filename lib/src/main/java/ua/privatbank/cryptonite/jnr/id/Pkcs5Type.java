/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.id;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Pkcs5Type implements IntegerEnum {

    PKCS5_UNKNOWN(0),
    PKCS5_IIT(1),
    PKCS5_DSTU(2);

    Pkcs5Type(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
