/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Dstu7624SboxId implements IntegerEnum {

    DSTU7564_SBOX_1(0);

    Dstu7624SboxId(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
