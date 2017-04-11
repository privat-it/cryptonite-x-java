/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

public final class Utils {
    
    private Utils() { }

    public static String byteToHex(final byte[] data) {
        final StringBuilder hex = new StringBuilder();

        for (int i = 0; i < data.length; i++) {
            hex.append(String.format("%02x", data[i]));
        }

        return hex.toString();
    }

    public static byte[] swap(final byte[] src) {

        final byte[] dst = new byte[src.length];

        for (int i = 0; i < src.length; i++) {
            dst[dst.length - i - 1] = src[i];
        }

        return dst;
    }
}
