/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum CRLReason implements IntegerEnum {

    UNSPECIFIED             (0),
    KEYCOMPROMISE           (1),
    CACOMPROMISE            (2),
    AFFILIATIONCHANGED      (3),
    SUPERSEDED              (4),
    CESSATIONOFOPERATION    (5),
    CERTIFICATEHOLD         (6),
    /* VALUE 7 IS NOT USED */
    REMOVEFROMCRL           (8),
    PRIVILEGEWITHDRAWN      (9),
    AACOMPROMISE           (10);

    CRLReason(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
