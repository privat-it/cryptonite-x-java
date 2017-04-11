/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public class TSPResponse {
    private byte[] response;
    private long errorCode;
    private String errorMsg;

    public TSPResponse(byte[] response, long errorCode, String errorMsg) {
        this.response = response.clone();
        this.errorCode = errorCode;
        this.errorMsg = errorMsg;
    }

    public byte[] getBytes() {
        return response;
    }

    public long getErrorCode() {
        return errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }
}
