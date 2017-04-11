/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.id;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum SignStatus implements IntegerEnum {

    SIGN_STATUS_VALID(0),
    SIGN_STATUS_INVALID(1),
    SIGN_STATUS_VALID_WITHOUT_DATA(2),
    SIGN_STATUS_INVALID_BY_TSP(3);

    SignStatus(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;

    public static SignStatus getInstance(int status) {
        switch (status) {
        case 0:
            return SIGN_STATUS_VALID;
        case 1:
            return SIGN_STATUS_INVALID;
        case 2:
            return SIGN_STATUS_VALID_WITHOUT_DATA;
        case 3:
            return SIGN_STATUS_INVALID_BY_TSP;
        }

        return null;
    }
}
