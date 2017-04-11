/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.cms;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum PaDataType implements IntegerEnum {

    PA_UNDEFINED(0),
    PA_BYTEARRAY(1),
    PA_STRING(2),
    PA_CERTID(3);

    PaDataType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
