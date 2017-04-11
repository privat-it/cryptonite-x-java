/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

import jnr.ffi.LibraryLoader;
import ua.privatbank.cryptonite.jnr.crypto.ErrorCtx;

abstract class CryptoniteAbstract {

    public static String VERSION = "";
    public static String NAME = "";

    protected static <T> T loadLibrary(final String libName, Class<T> jnrInterface) {
        NAME = JarLoader.loadJarLib(libName);
        LibraryLoader<T> loader = LibraryLoader.create(jnrInterface);
        loader.search(JarLoader.LIB_PATH);
        return loader.load(libName);
    }

    protected static void execute(int code) throws CryptoniteException {
        if (code != CryptoniteException.RET_OK) {
            final StringBuilder message = new StringBuilder();

            message.append("\nNativeStacktrace ");
            message.append("lib:");
            message.append(NAME);
            message.append(" ver:");
            message.append(VERSION);
            message.append("\n\t");

            final ErrorCtx ctx = CryptoniteJnr.stacktraceGetLastWithAlloc();
            message.append(ctx);
            CryptoniteJnr.stacktraceErrorFree(ctx);

            throw new CryptoniteException(code, message.toString());
        }
    }
}
