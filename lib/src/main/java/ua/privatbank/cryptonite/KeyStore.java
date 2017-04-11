/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import ua.privatbank.cryptonite.jnr.cms.StoragePointer;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.pkix.DhAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.VerifyAdapterPointer;

public final class KeyStore {

    private final byte[] encoded;
    private final String password;
    private String path = null;
    private String alias = null;
    private List<String> keyList = null;

    public KeyStore(final String path, final String password) throws CryptoniteException {
        try {
            this.path = path;
            encoded = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            throw new CryptoniteException(CryptoniteException.RET_FILE_OPEN_ERROR, e);
        }

        this.password = password;

        checkStorage();
    }

    public KeyStore(final byte[] encoded, String password) throws CryptoniteException {

        this.encoded = encoded.clone();
        this.password = password;

        checkStorage();
    }

    public List<String> getKeysList() {
        return keyList;
    }

    public byte[] getEncoded() {
        return encoded;
    }

    public void selectKey(final String alias) throws CryptoniteException {
        if (keyList != null && keyList.contains(alias)) {
            this.alias = alias;
        } else {
            throw new CryptoniteException(CryptoniteException.RET_STORAGE_KEY_NOT_FOUND);
        }
    }

    private StoragePointer selectKey() throws CryptoniteException {
        if (alias == null) {
            throw new CryptoniteException(CryptoniteException.RET_STORAGE_KEY_NOT_SELECTED);
        }

        final StoragePointer storage = CryptoniteXJnr.storageDecode(path, encoded, password);
        CryptoniteXJnr.storageSelectKey(storage, alias, password);

        return storage;
    }

    SignAdapterPointer getSignAdapter() throws CryptoniteException {
        StoragePointer storage = null;
        final SignAdapterPointer sa;

        try{
            storage = selectKey();
            sa = CryptoniteXJnr.storageGetSignAdapter(storage);
        } finally {
            CryptoniteXJnr.storageFree(storage);
        }

        return sa;
    }

    VerifyAdapterPointer getVerifyAdapter() throws CryptoniteException {
        StoragePointer storage = null;
        final VerifyAdapterPointer va;

        try{
            storage = selectKey();
            va = CryptoniteXJnr.storageGetVerifyAdapter(storage);
        } finally {
            CryptoniteXJnr.storageFree(storage);
        }

        return va;
    }

    DhAdapterPointer getDhAdapterPointer() throws CryptoniteException {
        StoragePointer storage = null;
        final DhAdapterPointer dha;

        try{
            storage = selectKey();
            dha = CryptoniteXJnr.storageGetDhAdapter(storage);
        } finally {
            CryptoniteXJnr.storageFree(storage);
        }

        return dha;
    }

    public byte[] getPublicKey() throws CryptoniteException {
        StoragePointer storage = null;
        try{
            storage = selectKey();
            return CryptoniteXJnr.storageGetPublicKey(storage);
        } finally {
            CryptoniteXJnr.storageFree(storage);
        }
    }

    public byte[] getCetificate(int keyUsage) throws CryptoniteException {
        StoragePointer storage = null;
        ByteArrayPointer certPa = null;
        byte[] cert = null;

        try {
            storage = selectKey();
            certPa = CryptoniteXJnr.storageGetCertificate(storage, keyUsage);
            cert = CryptoniteJnr.byteArrayToByte(certPa);
        } finally {
            CryptoniteJnr.freeByteArray(certPa);
            CryptoniteXJnr.storageFree(storage);
        }

        return cert;
    }

    private void checkStorage() throws CryptoniteException {
        final StoragePointer storage = CryptoniteXJnr.storageDecode("", encoded, password);

        keyList = CryptoniteXJnr.storageGetAliases(storage);
        if (keyList != null && keyList.size() == 1) {
            alias = keyList.get(0);
        }

        CryptoniteXJnr.storageFree(storage);
    }
}
