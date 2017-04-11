/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum RsaHashType implements IntegerEnum {

    RSA_HASH_SHA1(0),
    RSA_HASH_SHA256(1),
    RSA_HASH_SHA384(2),
    RSA_HASH_SHA512(3);

    RsaHashType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
