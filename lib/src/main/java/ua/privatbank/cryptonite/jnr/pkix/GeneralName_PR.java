/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum GeneralName_PR implements IntegerEnum {

    NOTHING(0),
    OTHERNAME(1),
    RFC822NAME(2),
    DNSNAME(3),
    X400ADDRESS(4),
    DIRECTORYNAME(5),
    EDIPARTYNAME(6),
    UNIFORMRESOURCEIDENTIFIER(7),
    IPADDRESS(8),
    REGISTEREDID(9);

    GeneralName_PR(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
