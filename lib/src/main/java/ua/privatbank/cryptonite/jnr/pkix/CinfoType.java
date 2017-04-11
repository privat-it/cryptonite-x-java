/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum CinfoType implements IntegerEnum {

    CONTENT_DATA(0),
    CONTENT_SIGNED(1),
    CONTENT_DIGESTED(2),
    CONTENT_ENCRYPTED(3),
    CONTENT_ENVELOPED(4),
    CONTENT_UNKNOWN(5);

    CinfoType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
