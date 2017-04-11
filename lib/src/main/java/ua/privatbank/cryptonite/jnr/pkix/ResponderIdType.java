/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum ResponderIdType implements IntegerEnum {

    OCSP_RESPONSE_BY_HASH_KEY(0),
    OCSP_RESPONSE_BY_NAME(1);

    ResponderIdType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
