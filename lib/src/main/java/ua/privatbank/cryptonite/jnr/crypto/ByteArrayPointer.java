/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.mapper.FromNativeContext;
import jnr.ffi.mapper.FromNativeConverter;
import jnr.ffi.mapper.ToNativeContext;
import jnr.ffi.mapper.ToNativeConverter;
import ua.privatbank.cryptonite.CryptoniteJnr;
import ua.privatbank.cryptonite.Utils;

public final class ByteArrayPointer {

    private final Pointer pointer;

    public ByteArrayPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    public ByteArrayPointer(PointerByReference pointer) {
        this.pointer = pointer.getValue();
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(ByteArrayPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static ByteArrayPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new ByteArrayPointer(value) : null;
    }

    @Override
    public String toString() {
        return "ByteArray [" + Utils.byteToHex(CryptoniteJnr.byteArrayToByte(this)) + "]";
    }
}
