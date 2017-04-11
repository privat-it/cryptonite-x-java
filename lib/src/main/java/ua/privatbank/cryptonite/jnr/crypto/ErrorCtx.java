/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.jnr.crypto;

import jnr.ffi.Struct;

public final class ErrorCtx extends Struct {

    public final Pointer file = new Pointer();
    public final size_t line = new size_t();
    public final int32_t errorCode = new int32_t();
    public final Pointer next = new Pointer();

    public ErrorCtx(jnr.ffi.Runtime runtime) {
        super(runtime);
    }

    public static ErrorCtx of(jnr.ffi.Pointer pointer) {
        ErrorCtx ctx = new ErrorCtx(jnr.ffi.Runtime.getSystemRuntime());
        ctx.useMemory(pointer);
        return ctx;
    }

    public java.lang.String getFile() {
        jnr.ffi.Pointer pointer = file.get();
        return (pointer != null) ? pointer.getString(0) : null;
    }

    public long getLine() {
        return line.longValue();
    }

    public int getErrorCode() {
        return errorCode.intValue();
    }

    public ErrorCtx getNext() {
        if (next.get() != null){
            ErrorCtx ctx = new ErrorCtx(next.get().getRuntime());
            ctx.useMemory(next.get());
            return ctx;
        }

        return null;
    }

    @Override
    public java.lang.String toString() {
        ErrorCtx ctx = getNext();
        return getFile() + ":" + getLine() + 
                ", error:" + java.lang.String.format("0x%03x", getErrorCode()) + "\n\t" + ((ctx != null) ? ctx : "");
    }
}
