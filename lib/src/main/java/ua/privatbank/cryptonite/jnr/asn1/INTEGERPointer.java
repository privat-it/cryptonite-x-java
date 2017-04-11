/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.asn1;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.mapper.FromNativeContext;
import jnr.ffi.mapper.FromNativeConverter;
import jnr.ffi.mapper.ToNativeContext;
import jnr.ffi.mapper.ToNativeConverter;

public final class INTEGERPointer {

    private final Pointer pointer;

    public INTEGERPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    public INTEGERPointer(PointerByReference pointer) {
        this.pointer = pointer.getValue();
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(INTEGERPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static INTEGERPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new INTEGERPointer(value) : null;
    }

    public Pointer getPointer() {
        return pointer;
    }
}
