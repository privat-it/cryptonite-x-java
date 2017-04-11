/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;
import jnr.ffi.byref.PointerByReference;

import ua.privatbank.cryptonite.jnr.CryptoniteNative;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.crypto.Dstu4145CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Dstu4145ParamsId;
import ua.privatbank.cryptonite.jnr.crypto.ErrorCtx;
import ua.privatbank.cryptonite.jnr.crypto.Gost28147CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Gost28147SboxId;
import ua.privatbank.cryptonite.jnr.crypto.Gost34311CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Md5CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.PrngCtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.PrngMode;
import ua.privatbank.cryptonite.jnr.crypto.Sha1CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Sha2CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Sha2Variant;

public class CryptoniteJnr extends CryptoniteAbstract {

    /** Instance native library. */
    private static CryptoniteNative instance = null;

    /** Name native library. */
    public static final String LIB_NAME = "cryptonite";

    static {
        init();
    }

    public static void init() {
        if (instance == null) {
            instance = loadLibrary(LIB_NAME, CryptoniteNative.class);

            VERSION = "9c44ddb8ae9e";
        }
    }

    public static ByteArrayPointer byteToByteArray(final byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        final Pointer ptrMemory = Memory.allocate(Runtime.getRuntime(instance), bytes.length);
        ptrMemory.put(0, bytes, 0, bytes.length);

        return instance.ba_alloc_from_uint8(ptrMemory, bytes.length);
    }

    public static byte[] byteArrayToByte(ByteArrayPointer ba) {
        if (ba == null) {
            return null;
        }

        final Pointer buf = instance.ba_get_buf(ba);

        if (buf == null) {
            return null;
        }

        final int len = (int)instance.ba_get_len(ba);

        byte[] bytes = new byte[len];
        buf.get(0, bytes, 0, len);

        return bytes;
    }

    public static byte[] byteArrayToByte(PointerByReference ba) {
        final ByteArrayPointer pointer = new ByteArrayPointer(ba);
        final byte[] data = byteArrayToByte(pointer);
        freeByteArray(pointer);

        return data;
    }
    
    public static String byteArrayToString(ByteArrayPointer ba) {
        if (ba == null) {
            return null;
        }

        final Pointer buf = instance.ba_get_buf(ba);

        if (buf == null) {
            return null;
        }

        final int len = (int)instance.ba_get_len(ba);

        byte[] bytes = new byte[len];
        buf.get(0, bytes, 0, len);

        return new String(bytes);
    }

    public static void byteArraySwap(final ByteArrayPointer byteArray) {
        instance.ba_swap(byteArray);
    }

    public static void freeByteArray(final ByteArrayPointer byteArray) {
        instance.ba_free(byteArray);
    }

    public static ByteArrayPointer byteArrayByRnd(int len) throws CryptoniteException {
        ByteArrayPointer ba = instance.ba_alloc_by_len(len);

        try {
            execute(instance.rs_std_next_bytes(ba));
        } catch (CryptoniteException e){
            instance.ba_free(ba);
            throw e;
        }

        return ba;
    }

    public static PrngCtxPointer getDstuPrng(final byte[] seed) {
        return instance.prng_alloc(PrngMode.PRNG_MODE_DSTU, byteToByteArray(seed));
    }

    public static Dstu4145CtxPointer dstu4145Alloc(Dstu4145ParamsId params_id){
        return instance.dstu4145_alloc(params_id);
    }

    public static byte[] dstu4145GeneratePrivkey(Dstu4145CtxPointer ctx, PrngCtxPointer prng) throws CryptoniteException {
        final PointerByReference d = new PointerByReference();

        execute(instance.dstu4145_generate_privkey(ctx, prng, d));

        final ByteArrayPointer dBa =  new ByteArrayPointer(d);
        final byte[] privkey = byteArrayToByte(dBa);
        instance.ba_free(dBa);

        return privkey;
    }

    public static void dstu4145Free(Dstu4145CtxPointer ctx) {
        instance.dstu4145_free(ctx);
    }

    public static Gost28147CtxPointer gost28147Alloc(Gost28147SboxId sbox_id) {
        return instance.gost28147_alloc(sbox_id);
    }

    public static void gost28147InitCtr(Gost28147CtxPointer ctx, final byte[] key, final byte[] iv) throws CryptoniteException {
        final ByteArrayPointer ptrKey = byteToByteArray(key);
        final ByteArrayPointer ptrIv = byteToByteArray(iv);

        try {
            execute(instance.gost28147_init_ctr(ctx, ptrKey, ptrIv));
        } finally {
            freeByteArray(ptrKey);
            freeByteArray(ptrIv);
        }
    }

    public static byte[] gost28147Encrypt(Gost28147CtxPointer ctx, final byte[] data) throws CryptoniteException {
        final PointerByReference encrypted = new PointerByReference();
        final ByteArrayPointer ptrData = byteToByteArray(data);
        ByteArrayPointer ptrEncrypt = null;
        final byte[] encrypt;

        try {
            execute(instance.gost28147_encrypt(ctx, ptrData, encrypted));

            ptrEncrypt = new ByteArrayPointer(encrypted);
            encrypt = byteArrayToByte(ptrEncrypt);
        } finally {
            freeByteArray(ptrData);
            freeByteArray(ptrEncrypt);
        }

         return encrypt;
    }

    public static byte[] gost28147Decrypt(Gost28147CtxPointer ctx, final byte[] data) throws CryptoniteException {
        final PointerByReference encrypted = new PointerByReference();
        final ByteArrayPointer ptrData = byteToByteArray(data);
        ByteArrayPointer ptrDecrypt = null;
        final byte[] decrypt;

        try {
            execute(instance.gost28147_decrypt(ctx, ptrData, encrypted));

            ptrDecrypt = new ByteArrayPointer(encrypted);
            decrypt =  byteArrayToByte(ptrDecrypt);
        } finally {
            freeByteArray(ptrData);
            freeByteArray(ptrDecrypt);
        }

        return decrypt;
    }

    public static void gost28147Free(Gost28147CtxPointer ctx) {
        instance.gost28147_free(ctx);
    }

    public static Gost34311CtxPointer gost34311Alloc(Gost28147SboxId sbox_id, final byte[] sync) {
        final ByteArrayPointer ptrSync = byteToByteArray(sync);
        final Gost34311CtxPointer ptrGost = instance.gost34_311_alloc(sbox_id, ptrSync);

        freeByteArray(ptrSync);

        return ptrGost;
    }

    public static void gost34311Update(Gost34311CtxPointer ctx, final byte[] data) throws CryptoniteException {
        final ByteArrayPointer ptrData = byteToByteArray(data);

        try{
            execute(instance.gost34_311_update(ctx, ptrData));
        } finally {
            freeByteArray(ptrData);
        }
    }

    public static byte[] gost34311Final(Gost34311CtxPointer ctx) throws CryptoniteException {
        final PointerByReference hash = new PointerByReference();
        ByteArrayPointer ptrHash = null;
        final byte[] hashBytes;

        try {
            execute(instance.gost34_311_final(ctx, hash));

            ptrHash = new ByteArrayPointer(hash);
            hashBytes =  byteArrayToByte(ptrHash);
        } finally {
            freeByteArray(ptrHash);
        }

        return hashBytes;
    }

    public static void gost34311Free(Gost34311CtxPointer ctx) {
        instance.gost34_311_free(ctx);
    }

    public static Md5CtxPointer md5Alloc() {
        return instance.md5_alloc();
    }

    public static void md5Update(Md5CtxPointer ctx, final byte[] data) throws CryptoniteException {
        final ByteArrayPointer ptrData = byteToByteArray(data);

        try {
            execute(instance.md5_update(ctx, ptrData));
        } finally {
            freeByteArray(ptrData);
        }
    }

    public static byte[] md5Final(Md5CtxPointer ctx) throws CryptoniteException {
        final PointerByReference hash = new PointerByReference();
        ByteArrayPointer ptrHash = null;
        final byte[] hashBytes;

        try {
            execute(instance.md5_final(ctx, hash));

            ptrHash = new ByteArrayPointer(hash);
            hashBytes =  byteArrayToByte(ptrHash);
        } finally {
            freeByteArray(ptrHash);
        }

        return hashBytes;
    }

    public static void md5Free(Md5CtxPointer ctx) {
        instance.md5_free(ctx);
    }

    public static Sha1CtxPointer sha1Alloc() {
        return instance.sha1_alloc();
    }

    public static void sha1Update(Sha1CtxPointer ctx, final byte[] data) throws CryptoniteException {
        final ByteArrayPointer ptrData = byteToByteArray(data);

        try {
            execute(instance.sha1_update(ctx, ptrData));
        } finally {
            freeByteArray(ptrData);
        }
    }

    public static byte[] sha1Final(Sha1CtxPointer ctx) throws CryptoniteException {
        final PointerByReference hash = new PointerByReference();
        ByteArrayPointer ptrHash = null;
        final byte[] hashBytes;

        try {
            execute(instance.sha1_final(ctx, hash));

            ptrHash = new ByteArrayPointer(hash);
            hashBytes =  byteArrayToByte(ptrHash);
        } finally {
            freeByteArray(ptrHash);
        }

        return hashBytes;
    }

    public static void sha1Free(Sha1CtxPointer ctx) {
        instance.sha1_free(ctx);
    }

    public static Sha2CtxPointer sha2Alloc(Sha2Variant variant) {
        return instance.sha2_alloc(variant);
    }

    public static void sha2Update(Sha2CtxPointer ctx, final byte[] data) throws CryptoniteException {
        final ByteArrayPointer ptrData = byteToByteArray(data);

        try {
            execute(instance.sha2_update(ctx, ptrData));
        } finally {
            freeByteArray(ptrData);
        }
    }

    public static byte[] sha2Final(Sha2CtxPointer ctx) throws CryptoniteException {
        final PointerByReference hash = new PointerByReference();
        ByteArrayPointer ptrHash = null;
        final byte[] hashBytes;

        try {
            execute(instance.sha2_final(ctx, hash));

            ptrHash = new ByteArrayPointer(hash);
            hashBytes =  byteArrayToByte(ptrHash);
        } finally {
            freeByteArray(ptrHash);
        }

        return hashBytes;
    }

    public static void sha2Free(Sha2CtxPointer ctx) {
        instance.sha2_free(ctx);
    }

    public static ErrorCtx stacktraceGetLastWithAlloc() {
        return instance.stacktrace_get_last_with_alloc();
    }

    public static void stacktraceErrorFree(ErrorCtx ctx) {
        instance.error_ctx_free(ctx);
    }
}

