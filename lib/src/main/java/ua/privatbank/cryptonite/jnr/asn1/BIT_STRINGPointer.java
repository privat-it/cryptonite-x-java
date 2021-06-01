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

public final class BIT_STRINGPointer {

    private final Pointer pointer;

    public BIT_STRINGPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    public BIT_STRINGPointer(PointerByReference pointer) {
        this.pointer = pointer.getValue();
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(BIT_STRINGPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static BIT_STRINGPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new BIT_STRINGPointer(value) : null;
    }

    public Pointer getPointer() {
        return pointer;
    }
}
