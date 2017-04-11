/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Pkcs12MacType implements IntegerEnum {

    /** Типи ключового сховища. */
    KS_FILE_PKCS12_UNKNOWN(0),
    KS_FILE_PKCS12_WITH_GOST34311(1),
    KS_FILE_PKCS12_WITH_SHA1(2),
    KS_FILE_PKCS12_WITH_SHA224(3),
    KS_FILE_PKCS12_WITH_SHA256(4),
    KS_FILE_PKCS12_WITH_SHA384(5),
    KS_FILE_PKCS12_WITH_SHA512(6);

    Pkcs12MacType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
