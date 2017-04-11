/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum OCSPResponseStatus implements IntegerEnum {

    SUCCESSFUL(0),
    MALFORMEDREQUEST(1),
    INTERNALERROR(2),
    TRYLATER(3),
    SIGREQUIRED(5),
    UNAUTHORIZED(6);

    OCSPResponseStatus(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
