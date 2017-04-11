/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.Struct;
import ua.privatbank.cryptonite.jnr.id.Pkcs12AuthType;

public class Pkcs12KeypairPointer extends Struct {
    
    private final java.lang.String alias = new java.lang.String();
    private final Enum32<Pkcs12AuthType> auth = new Enum32<Pkcs12AuthType>(Pkcs12AuthType.class);
    private final Signed32 int_id = new Signed32();

    public Pkcs12KeypairPointer(jnr.ffi.Runtime runtime) {
        super(runtime);
    }

    @Override
    public java.lang.String toString() {
        return "Pkcs12Keypair [alias=" + alias + ", auth=" + auth + ", int_id=" + int_id + "]";
    }
}
