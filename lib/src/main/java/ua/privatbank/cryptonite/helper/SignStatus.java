/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public enum SignStatus {
    VALID(0),
    INVALID(1),
    VALID_WITHOUT_DATA(2),
    INVALID_BY_TSP(3);

    SignStatus(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private final int value;

    public static SignStatus getInstance(int status) {
        switch (status) {
        case 0:
            return VALID;
        case 1:
            return INVALID;
        case 2:
            return VALID_WITHOUT_DATA;
        case 3:
            return INVALID_BY_TSP;
        }

        return null;
    }
}
