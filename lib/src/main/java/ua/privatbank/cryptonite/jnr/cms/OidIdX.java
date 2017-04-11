/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.cms;

import jnr.ffi.util.EnumMapper.IntegerEnum;

public enum OidIdX implements IntegerEnum {

    OID_RSA_WITH_SHA1_ID(153),      /* 1.2.840.113549.1.1.5 */
    OID_RSA_WITH_SHA224_ID(154),    /* 1.2.840.113549.1.1.14 */
    OID_RSA_WITH_SHA256_ID(155),    /* 1.2.840.113549.1.1.11 */
    OID_RSA_WITH_SHA384_ID(156),    /* 1.2.840.113549.1.1.12 */
    OID_RSA_WITH_SHA512_ID(157),    /* 1.2.840.113549.1.1.13 */
    OID_RSA_ENCRYPTION_ID(158);     /* 1.2.840.113549.1.1.1 */

    OidIdX(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }

    private final int value;
}
