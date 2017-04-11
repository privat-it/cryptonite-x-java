/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum KeyUsageBits implements IntegerEnum {

    KEY_USAGE_DIGITAL_SIGNATURE(0x00000001),
    KEY_USAGE_NON_REPUDIATION(0x00000002),
    KEY_USAGE_KEY_ENCIPHERMENT(0x00000004),
    KEY_USAGE_DATA_ENCIPHERMENT(0x00000008),
    KEY_USAGE_KEY_AGREEMENT(0x00000010),
    KEY_USAGE_KEY_CERTSIGN(0x00000020),
    KEY_USAGE_CRL_SIGN(0x00000040),
    KEY_USAGE_ENCIPHER_ONLY(0x00000080),
    KEY_USAGE_DECIPHER_ONLY(0x00000100);

    KeyUsageBits(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
