/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.asn1;

import jnr.ffi.Pointer;
import jnr.ffi.mapper.FromNativeContext;
import jnr.ffi.mapper.FromNativeConverter;
import jnr.ffi.mapper.ToNativeContext;
import jnr.ffi.mapper.ToNativeConverter;

public final class ANYPointer {

    private final Pointer pointer;

    public ANYPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(ANYPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static ANYPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new ANYPointer(value) : null;
    }
}
