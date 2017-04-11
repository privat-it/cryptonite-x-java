/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Pkcs8PrivatekeyType implements IntegerEnum {

    /** Типи ключів контейнера. */
    PRIVATEKEY_DSTU(0),
    PRIVATEKEY_RSA(1),
    PRIVATEKEY_DSA(2),
    PRIVATEKEY_ECDSA(3),
    PRIVATEKEY_UNKNOWN(4);

    Pkcs8PrivatekeyType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
