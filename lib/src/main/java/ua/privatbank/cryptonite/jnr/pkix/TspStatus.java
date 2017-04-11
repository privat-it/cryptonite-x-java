/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum TspStatus implements IntegerEnum {

    TSP_NONE(0),
    TSP_VALID(1),
    TSP_NO_CERT_FOR_VERIFY(2),
    TSP_INVALID_DATA(3),
    TSP_INVALID(4);

    TspStatus(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;

    public static TspStatus getInstance(int status) {
        switch (status) {
        case 0:
            return TSP_NONE;
        case 1:
            return TSP_VALID;
        case 2:
            return TSP_NO_CERT_FOR_VERIFY;
        case 3:
            return TSP_INVALID_DATA;
        case 4:
            return TSP_INVALID;
        }

        return null;
    }
}
