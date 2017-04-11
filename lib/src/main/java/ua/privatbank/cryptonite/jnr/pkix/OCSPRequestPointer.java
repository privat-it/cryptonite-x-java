/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.pkix;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.mapper.FromNativeContext;
import jnr.ffi.mapper.FromNativeConverter;
import jnr.ffi.mapper.ToNativeContext;
import jnr.ffi.mapper.ToNativeConverter;

public final class OCSPRequestPointer {

    private final Pointer pointer;

    public OCSPRequestPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    public OCSPRequestPointer(PointerByReference pointer) {
        this.pointer = pointer.getValue();
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(OCSPRequestPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static OCSPRequestPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new OCSPRequestPointer(value) : null;
    }

    public Pointer getPointer() {
        return pointer;
    }
}
