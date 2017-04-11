/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public enum OCSPResponseErrors {

    OCSP_RESP_STATUS_MALFORMEDREQUEST(new byte[] {(byte)0x30, (byte)0x03, (byte)0x0A, (byte)0x01, (byte)0x01}),
    OCSP_RESP_STATUS_INTERNALERROR(new byte[] {   (byte)0x30, (byte)0x03, (byte)0x0A, (byte)0x01, (byte)0x02}),
    OCSP_RESP_STATUS_TRYLATER(new byte[] {        (byte)0x30, (byte)0x03, (byte)0x0A, (byte)0x01, (byte)0x03}),
    OCSP_RESP_STATUS_SIGREQUIRED(new byte[] {     (byte)0x30, (byte)0x03, (byte)0x0A, (byte)0x01, (byte)0x05}),
    OCSP_RESP_STATUS_UNAUTHORIZED(new byte[] {    (byte)0x30, (byte)0x03, (byte)0x0A, (byte)0x01, (byte)0x06});

    private final byte[] encoded;

    private OCSPResponseErrors(final byte[] encoded) {
        this.encoded = encoded.clone();
    }

    public byte[] getEncoded() {
        return encoded;
    }
}
