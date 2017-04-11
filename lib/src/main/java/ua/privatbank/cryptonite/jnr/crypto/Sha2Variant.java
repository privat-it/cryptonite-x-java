/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Sha2Variant implements IntegerEnum {

    SHA2_VARIANT_224(0),
    SHA2_VARIANT_256(1),
    SHA2_VARIANT_384(2),
    SHA2_VARIANT_512(3);

    Sha2Variant(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
