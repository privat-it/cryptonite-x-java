/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.cms;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.mapper.FromNativeContext;
import jnr.ffi.mapper.FromNativeConverter;
import jnr.ffi.mapper.ToNativeContext;
import jnr.ffi.mapper.ToNativeConverter;

public final class PointerArrayPointer {

    private final Pointer pointer;

    public PointerArrayPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    public PointerArrayPointer(PointerByReference pointer) {
        this(pointer.getValue());
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(PointerArrayPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static PointerArrayPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new PointerArrayPointer(value) : null;
    }
}
