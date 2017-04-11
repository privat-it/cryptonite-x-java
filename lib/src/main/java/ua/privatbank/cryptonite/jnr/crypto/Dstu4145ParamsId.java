/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum Dstu4145ParamsId implements IntegerEnum {

    /**
     * Ідентифікатори стандартних параметрів ДСТУ 4145.
     */
    DSTU4145_PARAMS_ID_M163_PB(1),
    DSTU4145_PARAMS_ID_M167_PB(2),
    DSTU4145_PARAMS_ID_M173_PB(3),
    DSTU4145_PARAMS_ID_M179_PB(4),
    DSTU4145_PARAMS_ID_M191_PB(5),
    DSTU4145_PARAMS_ID_M233_PB(6),
    DSTU4145_PARAMS_ID_M257_PB(7),
    DSTU4145_PARAMS_ID_M307_PB(8),
    DSTU4145_PARAMS_ID_M367_PB(9),
    DSTU4145_PARAMS_ID_M431_PB(10),
    DSTU4145_PARAMS_ID_M173_ONB(11),
    DSTU4145_PARAMS_ID_M179_ONB(12),
    DSTU4145_PARAMS_ID_M191_ONB(13),
    DSTU4145_PARAMS_ID_M233_ONB(14),
    DSTU4145_PARAMS_ID_M431_ONB(15);

    Dstu4145ParamsId(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
