/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import ua.privatbank.cryptonite.Utils;

public class RsaPublicKey {
    
    private final byte[] modulus;
    private final byte[] exponent;
    
    public RsaPublicKey(final byte[] modulus, final byte[] exponent) {
        this.exponent = exponent.clone();
        this.modulus = modulus.clone();
    }

    public byte[] getModulus() {
        return modulus;
    }

    public byte[] getExponent() {
        return exponent;
    }

    @Override
    public String toString() {
        return "RsaPublicKey [modulus=" + Utils.byteToHex(modulus) + ", exponent=" + Utils.byteToHex(exponent) + "]";
    }
}
