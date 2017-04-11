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

public final class KeypairPointer {

    private final Pointer pointer;

    public KeypairPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    public KeypairPointer(PointerByReference pointer) {
        this(pointer.getValue());
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(KeypairPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static KeypairPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new KeypairPointer(value) : null;
    }
}
