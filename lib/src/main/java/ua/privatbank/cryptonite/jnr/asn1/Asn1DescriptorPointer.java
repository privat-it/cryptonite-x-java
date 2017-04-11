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

public final class Asn1DescriptorPointer {

    private final Pointer pointer;

    public Asn1DescriptorPointer(Pointer pointer) {
        this.pointer = pointer;
    }

    @ToNativeConverter.ToNative(nativeType = Pointer.class)
    public static Pointer toNative(Asn1DescriptorPointer value, ToNativeContext context) {
        return value != null ? value.pointer : null;
    }

    @FromNativeConverter.FromNative(nativeType = Pointer.class)
    public static Asn1DescriptorPointer fromNative(Pointer value, FromNativeContext context) {
        return value != null ? new Asn1DescriptorPointer(value) : null;
    }
}
