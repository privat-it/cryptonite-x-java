/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import java.util.List;

import ua.privatbank.cryptonite.Utils;

public class OCSPRequestInfo {
    private final List<OCSPCertId> listCertId;
    private final byte[] nonce;

    public OCSPRequestInfo(final List<OCSPCertId> listCertId, final byte[] nonce) {
        super();
        this.listCertId = listCertId;
        this.nonce = nonce;
    }

    public List<OCSPCertId> getListCertId() {
        return listCertId;
    }

    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public String toString() {
        return "OCSPRequestInfo [listCertId=" + listCertId + ", nonce=" + Utils.byteToHex(nonce) + "]";
    }
}
