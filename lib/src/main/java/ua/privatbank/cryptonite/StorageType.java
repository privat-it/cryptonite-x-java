/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

public enum StorageType {

    PKCS12_WITH_GOST34311(1),
    PKCS12_WITH_SHA1(2),
    PKCS12_WITH_SHA224(3),
    PKCS12_WITH_SHA256(4),
    PKCS12_WITH_SHA384(5),
    PKCS12_WITH_SHA512(6),
    PKCS12_WITH_PBKDF2_GOST34311(7),
    PKCS12_WITHOUT_MAC(8),
    JKS(9),
    CRYPTONITE_KEY(10),
    IIT_KEY(11);

    StorageType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private final int value;
}
