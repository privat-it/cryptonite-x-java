/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public enum ResponderType {

    HASH_KEY(0), NAME(1);

    ResponderType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private final int value;
}