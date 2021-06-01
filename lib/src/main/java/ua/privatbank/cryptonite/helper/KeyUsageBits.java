/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public enum KeyUsageBits {

    DIGITAL_SIGNATURE(0x00000001),
    NON_REPUDIATION(0x00000002),
    KEY_ENCIPHERMENT(0x00000004),
    DATA_ENCIPHERMENT(0x00000008),
    KEY_AGREEMENT(0x00000010),
    KEY_CERTSIGN(0x00000020),
    CRL_SIGN(0x00000040),
    ENCIPHER_ONLY(0x00000080),
    DECIPHER_ONLY(0x00000100);

    KeyUsageBits(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private final int value;

    public boolean equals(int value) {
        return (this.value & value) != 0;
    }
}
