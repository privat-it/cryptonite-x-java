/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public class OCSPCertId {
    private byte[] issuerNameHash;
    private byte[] issuerKeyHash;
    private byte[] serialNumber;

    public OCSPCertId(byte[] issuerNameHash, byte[] issuerKeyHash, byte[] serialNumber) {
        this.issuerNameHash = issuerNameHash.clone();
        this.issuerKeyHash = issuerKeyHash.clone();
        this.serialNumber = serialNumber.clone();
    }

    public byte[] getIssuerNameHash() {
        return issuerNameHash;
    }
    public byte[] getIssuerKeyHash() {
        return issuerKeyHash;
    }
    public byte[] getSerialNumber() {
        return serialNumber;
    }
}
