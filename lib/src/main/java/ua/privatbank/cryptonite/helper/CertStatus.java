/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public enum CertStatus {

    GOOD(0),
    REVOKED(1),
    CONTENT_DIGESTED(2),
    UNKNOWN(3);

    CertStatus(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private final int value;
}
