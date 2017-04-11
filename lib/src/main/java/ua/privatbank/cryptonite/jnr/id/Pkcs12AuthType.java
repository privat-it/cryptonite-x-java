/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.id;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Pkcs12AuthType implements IntegerEnum {

    /** Типи аутентифікації для роботи з ключем. */
    AUTH_KEY_PASS(0),
    AUTH_NO_PASS(1),
    AUTH_STORAGE_PASS(2);

    Pkcs12AuthType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
