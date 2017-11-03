/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import ua.privatbank.cryptonite.helper.CRLReason;
import ua.privatbank.cryptonite.helper.ExtensionX;
import ua.privatbank.cryptonite.helper.OCSPCertId;
import ua.privatbank.cryptonite.helper.OCSPRequestInfo;
import ua.privatbank.cryptonite.helper.QcStatementX;
import ua.privatbank.cryptonite.helper.RevokedInfoX;
import ua.privatbank.cryptonite.helper.RsaPublicKey;
import ua.privatbank.cryptonite.helper.SignStatus;
import ua.privatbank.cryptonite.helper.SupportedCommonName;
import ua.privatbank.cryptonite.helper.TSPResponse;
import ua.privatbank.cryptonite.jnr.CryptoniteXNative;
import ua.privatbank.cryptonite.jnr.cms.CertIDPointer;
import ua.privatbank.cryptonite.jnr.cms.CrlEngineXPointer;
import ua.privatbank.cryptonite.jnr.cms.OcspResponseCtxPointer;
import ua.privatbank.cryptonite.jnr.cms.PaDataType;
import ua.privatbank.cryptonite.jnr.cms.PointerArrayPointer;
import ua.privatbank.cryptonite.jnr.cms.StoragePointer;
import ua.privatbank.cryptonite.jnr.cms.VerifyInfoPointer;
import ua.privatbank.cryptonite.jnr.cms.VerifyInfosPointer;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.id.OidId;
import ua.privatbank.cryptonite.jnr.pkix.CertificatePointer;
import ua.privatbank.cryptonite.jnr.pkix.DhAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.ExtensionPointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPRequestPointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPResponsePointer;
import ua.privatbank.cryptonite.jnr.pkix.QCStatementPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampRespPointer;
import ua.privatbank.cryptonite.jnr.pkix.TspStatus;
import ua.privatbank.cryptonite.jnr.pkix.VerifyAdapterPointer;

public class CryptoniteXJnr extends CryptoniteAbstract {

    /** Instance native library. */
    private static CryptoniteXNative instance = null;

    /** Name native library. */
    public static final String LIB_NAME = "cryptonite_x";

    static {
        init();
    }

    public static void init() {
        if (instance == null) {
            CryptonitePkiJnr.init();
            instance = loadLibrary(LIB_NAME, CryptoniteXNative.class);
            instance.cryptonite_init();

            VERSION = instance.cryptonite_x_get_version();
        }
    }

    public static String pointerByReferenceToString(PointerByReference pointerByReference) {
        final Pointer pointer = pointerByReference.getValue();
        final String string = pointer.getString(0);

        instance.pkix_ptr_free(pointer);

        return string;
    }

    public static PointerArrayPointer CmsSplit(final byte[] CMSData) throws CryptoniteException {
        final PointerByReference ptrSplit = new PointerByReference();
        final ByteArrayPointer ptrCmsSignData = CryptoniteJnr.byteToByteArray(CMSData);

        try {
            execute(instance.cms_split(ptrCmsSignData, ptrSplit));
        } finally {
            CryptoniteJnr.freeByteArray(ptrCmsSignData);
        }

        return new PointerArrayPointer(ptrSplit.getValue());
    }

    public static ByteArrayPointer CmsJoin(final byte[] data, final byte[] CMSData1, final byte[] CMSData2) throws CryptoniteException {
        final PointerByReference ptrJoin = new PointerByReference();
        final ByteArrayPointer ptrCmsSignData1 = CryptoniteJnr.byteToByteArray(CMSData1);
        final ByteArrayPointer ptrCmsSignData2 = CryptoniteJnr.byteToByteArray(CMSData2);
        final ByteArrayPointer ptrData = CryptoniteJnr.byteToByteArray(data);

        try {
            execute(instance.cms_join(ptrData, ptrCmsSignData1, ptrCmsSignData2, ptrJoin));
        } finally {
            CryptoniteJnr.freeByteArray(ptrData);
            CryptoniteJnr.freeByteArray(ptrCmsSignData1);
            CryptoniteJnr.freeByteArray(ptrCmsSignData2);
        }

        return new ByteArrayPointer(ptrJoin);
    }

    public static PointerArrayPointer pointerArrayAlloc(final PaDataType type) {
        return instance.pa_alloc(type);
    }

    public static long pointerArrayGetCount(final PointerArrayPointer pa) throws CryptoniteException {
        final long[] count = new long[1];
        execute(instance.pa_get_count(pa, count));
        return count[0];
    }

    public static void pointerArrayAddBytesElement(PointerArrayPointer pa, byte[] data) throws CryptoniteException {
        execute(instance.pa_add_bytes_elem(pa, data, data.length));
    }

    public static ByteArrayPointer pointerArrayGetByteArrayElement(final PointerArrayPointer pointer, long idx) {
        return instance.pa_get_ba_elem(pointer, idx);
    }

    public static String pointerArrayGetBaStringElement(final PointerArrayPointer pointer, long idx) {
        return CryptoniteJnr.byteArrayToString(instance.pa_get_ba_elem(pointer, idx));
    }

    public static CertIDPointer pointerArrayGetCertIdElement(final PointerArrayPointer pa, long idx) {
        return instance.pa_get_certid_elem(pa, idx);
    }

    public static String pointerArrayGetString(final PointerArrayPointer pa, long idx) {
        return instance.pa_get_string_elem(pa, idx);
    }

    public static void pointerArrayFree(final PointerArrayPointer pointer) {
        instance.pa_free(pointer);
    }

    public static byte[] cmsSignData(SignAdapterPointer sa, final byte[] cert, boolean includeCert, final byte[] data,
            boolean includeData, final byte[] signedAttrs, final byte[] unsignedAattrs) throws CryptoniteException {
        final PointerByReference sign = new PointerByReference();
        final ByteArrayPointer ptrCert = CryptoniteJnr.byteToByteArray(cert);
        final ByteArrayPointer ptrData = CryptoniteJnr.byteToByteArray(data);
        final ByteArrayPointer ptrSignedAttrs = CryptoniteJnr.byteToByteArray(signedAttrs);
        final ByteArrayPointer ptrUnsignedAttrs = CryptoniteJnr.byteToByteArray(unsignedAattrs);
        byte[] signByte;

        try {
            execute(instance.cms_sign_data(sa, ptrCert, ptrData, includeData, includeCert, ptrSignedAttrs, ptrUnsignedAttrs,
                    sign));

            final ByteArrayPointer byteArray = new ByteArrayPointer(sign);
            signByte = CryptoniteJnr.byteArrayToByte(byteArray);
            CryptoniteJnr.freeByteArray(byteArray);
        } finally {
            CryptoniteJnr.freeByteArray(ptrData);
            CryptoniteJnr.freeByteArray(ptrSignedAttrs);
            CryptoniteJnr.freeByteArray(ptrUnsignedAttrs);
            CryptoniteJnr.freeByteArray(ptrCert);
        }

        return signByte;
    }

    public static byte[] cmsSignHash(SignAdapterPointer sa, final byte[] cert, final byte[] hash, boolean includeCert,
            final byte[] signedAttrs, final byte[] unsignedAttrs) throws CryptoniteException {
        final PointerByReference sign = new PointerByReference();
        final ByteArrayPointer ptrCert = CryptoniteJnr.byteToByteArray(cert);
        final ByteArrayPointer ptrHash = CryptoniteJnr.byteToByteArray(hash);
        final ByteArrayPointer ptrSignedAttrs = CryptoniteJnr.byteToByteArray(signedAttrs);
        final ByteArrayPointer ptrUnsignedAttrs = CryptoniteJnr.byteToByteArray(unsignedAttrs);
        final byte[] signByte;

        try {
            execute(instance.cms_sign_hash(sa, ptrCert, ptrHash, includeCert, ptrSignedAttrs, ptrUnsignedAttrs, sign));
            final ByteArrayPointer byteArray = new ByteArrayPointer(sign);
            signByte = CryptoniteJnr.byteArrayToByte(byteArray);
            CryptoniteJnr.freeByteArray(byteArray);
        } finally {
            CryptoniteJnr.freeByteArray(ptrHash);
            CryptoniteJnr.freeByteArray(ptrSignedAttrs);
            CryptoniteJnr.freeByteArray(ptrUnsignedAttrs);
            CryptoniteJnr.freeByteArray(ptrCert);
        }

        return signByte;
    }

    public static byte[] cmsEncrypt(final DhAdapterPointer dha, final byte[] data,
            final byte[] srcCert, final byte[] destCert, String chipherOid, Boolean includeCert) throws CryptoniteException {
        final PointerByReference ptrEnveloped = new PointerByReference();
        final ByteArrayPointer ptrData = CryptoniteJnr.byteToByteArray(data);
        final ByteArrayPointer ptrSrcCert = CryptoniteJnr.byteToByteArray(srcCert);
        final ByteArrayPointer ptrDestCert = CryptoniteJnr.byteToByteArray(destCert);

        final byte[] envelopedData;

        try {
            execute(instance.cms_encrypt(dha, ptrData, ptrSrcCert, ptrDestCert, chipherOid, includeCert, ptrEnveloped));
            envelopedData = CryptoniteJnr.byteArrayToByte(ptrEnveloped);
        } finally {
            CryptoniteJnr.freeByteArray(ptrData);
            CryptoniteJnr.freeByteArray(ptrSrcCert);
            CryptoniteJnr.freeByteArray(ptrDestCert);
        }

        return envelopedData;
    }

    public static byte[] cmsDecrypt(final DhAdapterPointer dha, final byte[] envelopedData, final byte[] encryptData,
            final byte[] receiverCert, final byte[] senderCert) throws CryptoniteException {
        final PointerByReference ptrData = new PointerByReference();
        final ByteArrayPointer ptrEnvelopedData = CryptoniteJnr.byteToByteArray(envelopedData);
        final ByteArrayPointer ptrEncryptData = CryptoniteJnr.byteToByteArray(encryptData);
        final ByteArrayPointer ptrReceiverCert = CryptoniteJnr.byteToByteArray(receiverCert);
        final ByteArrayPointer ptrSenderCert = CryptoniteJnr.byteToByteArray(senderCert);

        final byte[] data;

        try {
            execute(instance.cms_decrypt(dha, ptrEnvelopedData, ptrEncryptData, ptrReceiverCert, ptrSenderCert, ptrData));
            data = CryptoniteJnr.byteArrayToByte(ptrData);
        } finally {
            CryptoniteJnr.freeByteArray(ptrEnvelopedData);
            CryptoniteJnr.freeByteArray(ptrEncryptData);
            CryptoniteJnr.freeByteArray(ptrReceiverCert);
            CryptoniteJnr.freeByteArray(ptrSenderCert);
        }

        return data;
    }

    public static PointerArrayPointer listToPointerArray(List<byte[]> list) throws CryptoniteException {
        if (list == null) {
            return null;
        }

        final PointerArrayPointer pa = pointerArrayAlloc(PaDataType.PA_BYTEARRAY);

        try {
            for (byte[] elem : list) {
                pointerArrayAddBytesElement(pa, elem);
            }
        } catch (Exception e) {
            pointerArrayFree(pa);
            throw e;
        }

        return pa;
    }

    public static VerifyInfosPointer cmsVerify(final byte[] cmsSign, final byte[] data, final List<byte[]> certs) throws CryptoniteException {
        PointerByReference verify_info = new PointerByReference();
        final ByteArrayPointer ptrCmsSign = CryptoniteJnr.byteToByteArray(cmsSign);
        final ByteArrayPointer ptrData = CryptoniteJnr.byteToByteArray(data);
        PointerArrayPointer certsPtr = null;

        try {
            certsPtr = listToPointerArray(certs);
            execute(instance.cms_verify(ptrCmsSign, ptrData, certsPtr, verify_info));
        } finally {
            CryptoniteJnr.freeByteArray(ptrCmsSign);
            CryptoniteJnr.freeByteArray(ptrData);
            pointerArrayFree(certsPtr);
        }

        return new VerifyInfosPointer(verify_info.getValue());
    }

    public static void verifyInfosFree(VerifyInfosPointer vis) {
        instance.verify_infos_free(vis);
    }

    public static long verifyInfosGetCount(final VerifyInfosPointer vis) throws CryptoniteException {
        long[] count = new long[1];
        execute(instance.verify_infos_get_count(vis, count));

        return count[0];
    }

    public static VerifyInfoPointer verifyInfosGetElement(final VerifyInfosPointer vis, int idx) throws CryptoniteException {
        PointerByReference vi = new PointerByReference();
        execute(instance.verify_infos_get_element(vis, idx, vi));

        return new VerifyInfoPointer(vi);
    }

    public static CertificatePointer verifyInfoGetCertificate(final VerifyInfoPointer vi) throws CryptoniteException {
        PointerByReference cert = new PointerByReference();
        execute(instance.verify_info_get_cert(vi, cert));

        return (cert.getValue() != null) ? new CertificatePointer(cert.getValue()) : null;
    }

    public static byte[] verifyInfoGetHash(final VerifyInfoPointer vi) throws CryptoniteException {
        PointerByReference hash = new PointerByReference();
        execute(instance.verify_info_get_hash(vi, hash));
        return CryptoniteJnr.byteArrayToByte(hash);
    }

    public static byte[] verifyInfoGetSignerId(final VerifyInfoPointer vi) throws CryptoniteException {
        PointerByReference signer = new PointerByReference();
        execute(instance.verify_info_get_signer_id(vi, signer));

        return CryptoniteJnr.byteArrayToByte(signer);
    }

    public static byte[] verifyInfoGetTspSid(final VerifyInfoPointer vi) throws CryptoniteException {
        PointerByReference sid = new PointerByReference();
        execute(instance.verify_info_get_tsp_sid(vi, sid));
        return CryptoniteJnr.byteArrayToByte(sid);
    }

    public static SignStatus verifyInfoGetSignStatus(final VerifyInfoPointer vi) throws CryptoniteException {
        int[] status = new int[1];
        execute(instance.verify_info_get_sign_status(vi, status));

        return SignStatus.getInstance(status[0]);
    }

    public static TspStatus verifyInfoGetTspStatus(final VerifyInfoPointer vi) throws CryptoniteException {
        int[] status = new int[1];
        execute(instance.verify_info_get_tsp_status(vi, status));

        return TspStatus.getInstance(status[0]);
    }

    public static Date verifyInfoGetTspValue(final VerifyInfoPointer vi) {
        final Date date;
        long value = instance.verify_info_get_tsp_value(vi);

        if (value == 0) {
            date = null;
        } else {
            date = new Date(value);
        }

        return date;
    }

    public static Date verifyInfoGetSigningTime(final VerifyInfoPointer vi) {
        final Date date;
        long value = instance.verify_info_get_signing_time_value(vi);

        if (value == 0) {
            date = null;
        } else {
            date = new Date(value);
        }

        return date;
    }

    public static byte[] cmsGenerateSignAttrs(final TimeStampRespPointer timeStampResp, boolean includeTime) throws CryptoniteException {
        if (timeStampResp == null && !includeTime) {
            return null;
        }

        final PointerByReference ptrAttrs = new PointerByReference();
        execute(instance.cms_generate_sign_attrs(timeStampResp, includeTime, ptrAttrs));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrAttrs.getValue());
        final byte[] attrs = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return attrs;
    }

    public static ByteArrayPointer cmsGetCertRequest(SignAdapterPointer sa, final String subject_name, final String dns, final String email,
            final String subject_attr) throws CryptoniteException {
        final PointerByReference request = new PointerByReference();
        execute(instance.cms_get_cert_request(sa, subject_name, dns, email, subject_attr, request));

        return new ByteArrayPointer(request);
    }

    public static StoragePointer storageDecode(final String name, final byte[] body, final String password) throws CryptoniteException {
        final PointerByReference storage = new PointerByReference();
        final ByteArrayPointer ptrBody = CryptoniteJnr.byteToByteArray(body);

        try {
            execute(instance.storage_decode(name, ptrBody, password, storage));
        } finally {
            CryptoniteJnr.freeByteArray(ptrBody);
        }

        return new StoragePointer(storage.getValue());
    }

    public static StoragePointer storageCreate(StorageType type, final String password, final int rounds) throws CryptoniteException {
        final PointerByReference storage = new PointerByReference();

        execute(instance.storage_create(type.getValue(), password, rounds, storage));

        return new StoragePointer(storage.getValue());
    }

    public static void storageFree(StoragePointer storage) {
        instance.storage_free(storage);
    }

    public static String storageGetVendor(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference name = new PointerByReference();

        execute(instance.storage_get_vendor_name(storage, name));

        return name.getValue().getString(0);
    }

    public static String storageGetProduct(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference name = new PointerByReference();

        execute(instance.storage_get_product_name(storage, name));

        return name.getValue().getString(0);
    }

    public static String storageGetName(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference name = new PointerByReference();

        execute(instance.storage_get_storage_name(storage, name));

        return name.getValue().getString(0);
    }

    public static void storageRename(final StoragePointer storage, final String new_name) throws CryptoniteException {
        execute(instance.storage_rename_storage(storage, new_name));
    }

    public static int storageChengPassword(final StoragePointer storage, final String cur_pwd, final String new_pwd) throws CryptoniteException {
        final int[] remained_attempts = new int[1];
        execute(instance.storage_change_password(storage, cur_pwd, new_pwd, remained_attempts));

        return remained_attempts[0];
    }

    public static List<String> storageGetAliases(final StoragePointer storage) throws CryptoniteException {
        final ArrayList<String> listAliases = new ArrayList<String>();
        final PointerByReference aliases = new PointerByReference();

        execute(instance.storage_get_aliases(storage, aliases));

        final PointerArrayPointer pa = new PointerArrayPointer(aliases);
        for (int i = 0; i < pointerArrayGetCount(pa); i++) {
            listAliases.add(pointerArrayGetBaStringElement(pa, i));
        }

        pointerArrayFree(pa);

        return listAliases;
    }

    public static void storageSelectKey(final StoragePointer storage, final String alias, final String pwd) throws CryptoniteException {
        execute(instance.storage_select_key(storage, alias, pwd));
    }

    public static boolean storageCanGenerateKey(final StoragePointer storage) throws CryptoniteException {
        final boolean[] flag = new boolean[1];

        execute(instance.storage_can_generate_key(storage, flag));

        return flag[0];
    }

    public static void storageGenerateKey(final StoragePointer storage, final ByteArrayPointer aid, String alias, String password) throws CryptoniteException {
        execute(instance.storage_generate_key(storage, aid, alias, password));
    }

    public static void storageGenerateDhKey(final StoragePointer storage, final ByteArrayPointer aid, String alias, String password) throws CryptoniteException {
        execute(instance.storage_generate_key_dh(storage, aid, alias, password));
    }

    public static void storageRenameKey(final StoragePointer storage, final String alias) throws CryptoniteException {
        execute(instance.storage_rename_key(storage, alias));
    }

    public static void storageChangeKeyPassword(final StoragePointer storage, final String old_pwd, final String new_pwd) throws CryptoniteException {
        execute(instance.storage_change_key_pwd(storage, old_pwd, new_pwd));
    }

    public static boolean storageIsAliasAvailable(final StoragePointer storage, final String alias) throws CryptoniteException {
        final boolean[] flag = new boolean[1];

        execute(instance.storage_is_alias_available(storage, alias, flag));

        return flag[0];
    }

    public static ByteArrayPointer storageGetCertificate(final StoragePointer storage, int key_usage) throws CryptoniteException {
        final PointerByReference cert = new PointerByReference();

        execute(instance.storage_get_certificate(storage, key_usage, cert));

        return new ByteArrayPointer(cert);
    }

    public static void storageDeleteKey(final StoragePointer storage) throws CryptoniteException {
        execute(instance.storage_delete_key(storage));
    }

    public static SignAdapterPointer storageGetSignAdapter(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference sa = new PointerByReference();

        execute(instance.storage_get_sign_adapter(storage, sa));

        return new SignAdapterPointer(sa);
    }

    public static DhAdapterPointer storageGetDhAdapter(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference dha = new PointerByReference();

        execute(instance.storage_get_dh_adapter(storage, dha));

        return new DhAdapterPointer(dha.getValue());
    }

    public static VerifyAdapterPointer storageGetVerifyAdapter(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference va = new PointerByReference();

        execute(instance.storage_get_verify_adapter(storage, va));

        return new VerifyAdapterPointer(va.getValue());
    }

    public static byte[] storageEncode(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference storage_body = new PointerByReference();

        execute(instance.storage_encode(storage, storage_body));

        final ByteArrayPointer encodedPtr = new ByteArrayPointer(storage_body);
        final byte[] encoded = CryptoniteJnr.byteArrayToByte(encodedPtr);

        CryptoniteJnr.freeByteArray(encodedPtr);

        return encoded;
    }

    public static byte[] storageGetPublicKey(final StoragePointer storage) throws CryptoniteException {
        final PointerByReference keyPtr = new PointerByReference();

        execute(instance.storage_get_compressed_public_key(storage, keyPtr));

        final ByteArrayPointer bytePtr = new ByteArrayPointer(keyPtr);
        final byte[] encoded = CryptoniteJnr.byteArrayToByte(bytePtr);

        CryptoniteJnr.freeByteArray(bytePtr);

        return encoded;
    }

    private static String getExtValue(int retCode, final PointerByReference pinter) throws CryptoniteException {
        final String value;

        if (retCode == CryptoniteException.RET_OK) {
            value = CryptoniteJnr.pointerToString(pinter);
        } else if ((retCode == CryptoniteException.RET_PKIX_OBJ_NOT_FOUND) ||  (retCode == CryptoniteException.RET_PKIX_EXT_NOT_FOUND)) {
            value = "";
        } else {
            throw new CryptoniteException(retCode);
        }

        return value;
    }

    public static String certGetIssuerInfo(final CertificatePointer cert, final OidId oid) throws CryptoniteException {
        final PointerByReference info = new PointerByReference();
        final int ret = instance.cert_get_issuer_info_by_oid(cert, CryptonitePkiJnr.oidsGetOidNumbersById(oid), info);
        return getExtValue(ret, info);
    }

    public static String certGetSubjectInfo(final CertificatePointer cert, final OidId oid) throws CryptoniteException {
        final PointerByReference info = new PointerByReference();
        final int ret = instance.cert_get_subject_info_by_oid(cert, CryptonitePkiJnr.oidsGetOidNumbersById(oid), info);

        return getExtValue(ret, info);
    }

    public static String certGetInn(final CertificatePointer cert) throws CryptoniteException {
        final PointerByReference info = new PointerByReference();
        final int ret = instance.cert_get_inn(cert, info);

        return getExtValue(ret, info);
    }

    public static String certGetEgrpou(final CertificatePointer cert) throws CryptoniteException {
        final PointerByReference info = new PointerByReference();
        final int ret = instance.cert_get_egrpou(cert, info);

        return getExtValue(ret, info);
    }

    public static HashMap<SupportedCommonName, String> certGetIssuerInfos(final CertificatePointer cert) throws CryptoniteException {
        final HashMap<SupportedCommonName, String> map = new HashMap<SupportedCommonName, String>();
        final PointerByReference infos = new PointerByReference();

        execute(instance.cert_get_issuer_infos(cert, infos));

        final PointerArrayPointer arrayPtr = new PointerArrayPointer(infos.getValue());

        for (long i = 0; i < pointerArrayGetCount(arrayPtr); i++) {
            final String[] value = pointerArrayGetBaStringElement(arrayPtr, i).split(":");
            map.put(new SupportedCommonName(value[0]), value[1]);
        }

        pointerArrayFree(arrayPtr);

        return map;
    }

    public static HashMap<SupportedCommonName, String> certGetSubjectInfos(final CertificatePointer cert) throws CryptoniteException {
        final HashMap<SupportedCommonName, String> map = new HashMap<SupportedCommonName, String>();
        final PointerByReference infos = new PointerByReference();

        execute(instance.cert_get_subject_infos(cert, infos));

        final PointerArrayPointer arrayPtr = new PointerArrayPointer(infos.getValue());

        for (long i = 0; i < pointerArrayGetCount(arrayPtr); i++) {
            final String[] value = pointerArrayGetBaStringElement(arrayPtr, i).split(":");
            map.put(new SupportedCommonName(value[0]), value[1]);
        }

        pointerArrayFree(arrayPtr);

        return map;
    }

    public static HashMap<String, String> certGetSubjectAltName(final CertificatePointer cert) throws CryptoniteException {
        final HashMap<String, String> map = new HashMap<String, String>();
        final PointerByReference infos = new PointerByReference();
        int code;

        code = instance.cert_get_sub_alt_name(cert, infos);
        if (code == CryptoniteException.RET_PKIX_OBJ_NOT_FOUND || code == CryptoniteException.RET_PKIX_EXT_NOT_FOUND) {
            return null;
        } else {
            execute(code);
        }

        final PointerArrayPointer arrayPtr = new PointerArrayPointer(infos.getValue());

        for (long i = 0; i < pointerArrayGetCount(arrayPtr); i++) {
            final String[] value = pointerArrayGetBaStringElement(arrayPtr, i).split(":");
            map.put(value[0], value[1]);
        }

        pointerArrayFree(arrayPtr);

        return map;
    }

    public static QcStatementX certGetQcStatement(final CertificatePointer cert) throws CryptoniteException {
        final long[] amount = new long[1];
        final long[] exponent = new long[1];
        final PointerByReference currency = new PointerByReference();

        int code = instance.cert_get_qc_limit_value(cert, currency, amount, exponent);
        if (code == CryptoniteException.RET_PKIX_OBJ_NOT_FOUND || code == CryptoniteException.RET_PKIX_EXT_NOT_FOUND) {
            return null;
        } else {
            execute(code);
        }

        final ByteArrayPointer text = new ByteArrayPointer(currency);
        final String value = CryptoniteJnr.byteArrayToString(text);
        CryptoniteJnr.freeByteArray(text);

        return new QcStatementX(value, amount[0], exponent[0]);
    }

    public static Date certificateGetNotBefore(final CertificatePointer cert) throws CryptoniteException {
        return new Date(instance.cert_get_not_before_v2(cert));
    }

    public static Date certificateGetNotAfter(final CertificatePointer cert) throws CryptoniteException {
        return new Date(instance.cert_get_not_after_v2(cert));
    }

    public static void signedDataSetData(final SignedDataPointer sdata, final ByteArrayPointer data) throws CryptoniteException {
        execute(instance.sdata_set_data(sdata, data));
    }

    public static ByteArrayPointer engineGenerateCertificate(final SignAdapterPointer sa,
                                                      final byte[] certRequest,
                                                      final byte[] serialNumber,
                                                      final Date notBefore, final Date notAfter,
                                                      final List<ExtensionX> exts) throws CryptoniteException {
        final PointerByReference cert = new PointerByReference();
        final ByteArrayPointer certRequestBa = CryptoniteJnr.byteToByteArray(certRequest);
        final ByteArrayPointer serialNumberBa = CryptoniteJnr.byteToByteArray(serialNumber);
        PointerArrayPointer extsPa = null;

        try {
            extsPa = CryptoniteXJnr.pointerArrayAlloc(PaDataType.PA_BYTEARRAY);
            for (ExtensionX extension : exts) {
                CryptoniteXJnr.pointerArrayAddBytesElement(extsPa, extension.getEncoded());
            }

            execute(instance.cert_engine_generate(sa,
                    certRequestBa, serialNumberBa,
                    notBefore.getTime(), notAfter.getTime(),
                    extsPa,
                    cert));
        } finally {
            CryptoniteJnr.freeByteArray(certRequestBa);
            CryptoniteJnr.freeByteArray(serialNumberBa);
            CryptoniteXJnr.pointerArrayFree(extsPa);
        }

        return new ByteArrayPointer(cert);
    }

    public static CrlEngineXPointer engineCrlDeltaAlloc(final byte[] deltaCrlIndicator) throws CryptoniteException {
        final PointerByReference crl = new PointerByReference();
        final ByteArrayPointer deltaCrlIndicatorPtr = CryptoniteJnr.byteToByteArray(deltaCrlIndicator);

        try {
            execute(instance.crl_engine_delta_alloc(deltaCrlIndicatorPtr, crl));
        } finally {
            CryptoniteJnr.freeByteArray(deltaCrlIndicatorPtr);
        }

        return new CrlEngineXPointer(crl.getValue());
    }

    public static CrlEngineXPointer engineCrlFullAlloc() throws CryptoniteException {
        final PointerByReference crl = new PointerByReference();
        execute(instance.crl_engine_full_alloc(crl));
        return new CrlEngineXPointer(crl.getValue());
    }

    public static void engineCrlAddRevokedInfo(CrlEngineXPointer ctx, final RevokedInfoX revokedInfo) throws CryptoniteException {
        final ByteArrayPointer serialNumberPtr = CryptoniteJnr.byteToByteArray(revokedInfo.getSerialNumber());
        final long revocationTime = (revokedInfo.getRevocationDate() != null) ? revokedInfo.getRevocationDate().getTime() : 0;
        final long invalidityTime = (revokedInfo.getInvalidityDate() != null) ? revokedInfo.getInvalidityDate().getTime() : 0;

        try {
            execute(instance.crl_engine_add_revoked_info(ctx,
                                                         serialNumberPtr,
                                                         revocationTime,
                                                         revokedInfo.getRevocationReason().getValue(),
                                                         invalidityTime));
        } finally {
            CryptoniteJnr.freeByteArray(serialNumberPtr);
        }
    }

    public static byte[] engineCrlGenerate(CrlEngineXPointer ctx, final SignAdapterPointer sa, final Date thisUpdate, final Date nextUpdate,
            final byte[] serialNumber, String distrPointsUrl, String freshestCrlUrl) throws CryptoniteException {

        final ByteArrayPointer serialNumberPtr = CryptoniteJnr.byteToByteArray(serialNumber);
        final PointerByReference encoded = new PointerByReference();
        byte[] crlBytes;

        try {
            execute(instance.crl_engine_get_encoded(ctx, sa, thisUpdate.getTime(), nextUpdate.getTime(),
                    serialNumberPtr, distrPointsUrl, freshestCrlUrl, encoded));

            final ByteArrayPointer byteArray = new ByteArrayPointer(encoded);
            crlBytes = CryptoniteJnr.byteArrayToByte(byteArray);
            CryptoniteJnr.freeByteArray(byteArray);
        } finally {
            CryptoniteJnr.freeByteArray(serialNumberPtr);
        }

        return crlBytes;
    }

    public static void engineCrlFree(CrlEngineXPointer ctx) {
        instance.crl_engine_free(ctx);
    }

    public static PointerArrayPointer listToPointerArray(String[] list) throws CryptoniteException {
        if (list == null) {
            return null;
        }

        final PointerArrayPointer pa = pointerArrayAlloc(PaDataType.PA_STRING);

        try {
            for (String elem : list) {
                execute(instance.pa_add_string_elem(pa, elem));
            }
        } catch (Exception e) {
            pointerArrayFree(pa);
            throw e;
        }

        return pa;
    }

    public static ExtensionPointer extCreateExtKeyUsage(final boolean critical, String[] oids) throws CryptoniteException {
        final PointerByReference ext = new PointerByReference();
        final PointerArrayPointer oidsPa = listToPointerArray(oids);

        try {
            execute(instance.ext_create_ext_key_usage_from_pa(true, oidsPa, ext));
        } finally {
            instance.pa_free(oidsPa);
        }

        return new ExtensionPointer(ext.getValue());
    }

    public static ExtensionPointer extCreateCertPolicies(final boolean critical, String[] oids) throws CryptoniteException {
        final PointerByReference ext = new PointerByReference();
        final PointerArrayPointer oidsPa = listToPointerArray(oids);

        try {
            execute(instance.ext_create_cert_policies_from_pa(critical, oidsPa, ext));
        } finally {
            instance.pa_free(oidsPa);
        }

        return new ExtensionPointer(ext.getValue());
    }

    public static ExtensionPointer extCreateQcStatements(final boolean critical, List<QcStatementX> qcStatements) throws CryptoniteException {
        PointerByReference ext = new PointerByReference();

        PointerArrayPointer qcStatementsPa = instance.pa_alloc(PaDataType.PA_BYTEARRAY);
        for (QcStatementX qcStatement : qcStatements) {
            pointerArrayAddBytesElement(qcStatementsPa, qcStatement.getEncoded());
        }

        try {
            execute(instance.ext_create_qc_statements_from_pa(critical, qcStatementsPa, ext));
        } finally {
            instance.pa_free(qcStatementsPa);
        }

        return new ExtensionPointer(ext.getValue());
    }

    public static ExtensionPointer extCreateCrlDistrPointsUrl(final boolean critical, String crlDistrPointsUrl) throws CryptoniteException {
        PointerByReference ext = new PointerByReference();

        execute(instance.ext_create_crl_distr_points_from_url(critical, crlDistrPointsUrl, ext));

        return new ExtensionPointer(ext.getValue());
    }

    public static ExtensionPointer extCreateFreshestCrlUrl(final boolean critical, String freshestCrlUrl) throws CryptoniteException {
        PointerByReference ext = new PointerByReference();

        execute(instance.ext_create_freshest_crl_from_url(critical, freshestCrlUrl, ext));

        return new ExtensionPointer(ext.getValue());
    }

    public static ExtensionPointer extCreateAny(final boolean critical, String extOid, byte[] encodedExtension) throws CryptoniteException {
        final PointerByReference ext = new PointerByReference();
        final ByteArrayPointer encodedExtensionBa = CryptoniteJnr.byteToByteArray(encodedExtension);

        try {
            execute(instance.ext_create_any_x(critical, extOid, encodedExtensionBa, ext));
        } finally {
            CryptoniteJnr.freeByteArray(encodedExtensionBa);
        }

        return new ExtensionPointer(ext.getValue());
    }

    public static byte[] extEncode(final ExtensionPointer ext) throws CryptoniteException {
        PointerByReference encoded = new PointerByReference();
        byte[] encodedBytes = null;

        execute(instance.ext_encode(ext, encoded));

        final ByteArrayPointer extBa = new ByteArrayPointer(encoded);
        encodedBytes = CryptoniteJnr.byteArrayToByte(extBa);
        CryptoniteJnr.freeByteArray(extBa);

        return encodedBytes;
    }

    public static byte[] qcStatementEncode(final QCStatementPointer qcStatement) throws CryptoniteException {
        PointerByReference encoded = new PointerByReference();
        byte[] encodedBytes = null;

        execute(instance.qc_statement_encode(qcStatement, encoded));

        final ByteArrayPointer qcStatementBa = new ByteArrayPointer(encoded);
        encodedBytes = CryptoniteJnr.byteArrayToByte(qcStatementBa);
        CryptoniteJnr.freeByteArray(qcStatementBa);

        return encodedBytes;
    }

    public static void qcStatementFree(final QCStatementPointer qcStatement) {
        instance.qc_statement_free(qcStatement);
    }

    public static OcspResponseCtxPointer engineOCSPResponseAlloc(final SignAdapterPointer sa, int id_type) throws CryptoniteException {
        PointerByReference ocsp = new PointerByReference();
        execute(instance.ocsp_resp_engine_alloc(sa, id_type, ocsp));
        return new OcspResponseCtxPointer(ocsp);
    }

    public static void engineOCSPResponseAddCertificateGood(OcspResponseCtxPointer ctx, final OCSPCertId certID,
            Date thisUpdate, Date nextUpdate) throws CryptoniteException {

        final ByteArrayPointer issuerNameHashPtr = CryptoniteJnr.byteToByteArray(certID.getIssuerNameHash());
        final ByteArrayPointer issuerKeyHashPtr = CryptoniteJnr.byteToByteArray(certID.getIssuerKeyHash());
        final ByteArrayPointer serialNumberPtr = CryptoniteJnr.byteToByteArray(certID.getSerialNumber());
        final long time = (nextUpdate != null) ? nextUpdate.getTime() : 0;

        try {
            execute(instance.ocsp_resp_engine_add_response_ok(ctx, issuerNameHashPtr, issuerKeyHashPtr, serialNumberPtr,
                    thisUpdate.getTime(), time));
        } finally {
            CryptoniteJnr.freeByteArray(issuerNameHashPtr);
            CryptoniteJnr.freeByteArray(issuerKeyHashPtr);
            CryptoniteJnr.freeByteArray(serialNumberPtr);
        }
    }

    public static void engineOCSPResponseAddCertificateUnknown(OcspResponseCtxPointer ctx, final OCSPCertId certID,
            final Date thisUpdate, final Date nextUpdate) throws CryptoniteException {

        final ByteArrayPointer issuerNameHashPtr = CryptoniteJnr.byteToByteArray(certID.getIssuerNameHash());
        final ByteArrayPointer issuerKeyHashPtr = CryptoniteJnr.byteToByteArray(certID.getIssuerKeyHash());
        final ByteArrayPointer serialNumberPtr = CryptoniteJnr.byteToByteArray(certID.getSerialNumber());
        final long time = (nextUpdate != null) ? nextUpdate.getTime() : 0;

        try {
            execute(instance.ocsp_resp_engine_add_response_unknown(ctx, issuerNameHashPtr, issuerKeyHashPtr,
                    serialNumberPtr, thisUpdate.getTime(), time));
        } finally {
            CryptoniteJnr.freeByteArray(issuerNameHashPtr);
            CryptoniteJnr.freeByteArray(issuerKeyHashPtr);
            CryptoniteJnr.freeByteArray(serialNumberPtr);
        }
    }

    public static void engineOCSPResponseAddCertificateRevoked(OcspResponseCtxPointer ctx, final OCSPCertId certID,
            Date revocationTime, CRLReason reason, Date thisUpdate, Date nextUpdate) throws CryptoniteException {

        final ByteArrayPointer issuerNameHashPtr = CryptoniteJnr.byteToByteArray(certID.getIssuerNameHash());
        final ByteArrayPointer issuerKeyHashPtr = CryptoniteJnr.byteToByteArray(certID.getIssuerKeyHash());
        final ByteArrayPointer serialNumberPtr = CryptoniteJnr.byteToByteArray(certID.getSerialNumber());
        final long time = (nextUpdate != null) ? nextUpdate.getTime() : 0;

        try {
            execute(instance.ocsp_resp_engine_add_response_revoked(ctx, issuerNameHashPtr, issuerKeyHashPtr,
                    serialNumberPtr, revocationTime.getTime(), reason.getValue(), thisUpdate.getTime(), time));
        } finally {
            CryptoniteJnr.freeByteArray(issuerNameHashPtr);
            CryptoniteJnr.freeByteArray(issuerKeyHashPtr);
            CryptoniteJnr.freeByteArray(serialNumberPtr);
        }
    }

    public static void engineOCSPResponseCertificatesClean(OcspResponseCtxPointer ctx) throws CryptoniteException {
        execute(instance.ocsp_resp_engine_clean_response(ctx));
    }

    public static byte[] engineOCSPResponseFinal(final OcspResponseCtxPointer ctx, final byte[] nonce, Date currentTime) throws CryptoniteException {
        PointerByReference resp = new PointerByReference();
        final ByteArrayPointer noncePtr = CryptoniteJnr.byteToByteArray(nonce);
        final byte[] encoded;

        try {
            execute(instance.ocsp_resp_engine_generate(ctx, noncePtr, currentTime.getTime(), resp));

            final OCSPResponsePointer ocspResponse = new OCSPResponsePointer(resp.getValue());
            encoded = CryptonitePkiJnr.ocspResposeEncode(ocspResponse);

            CryptonitePkiJnr.ocspResposeFree(ocspResponse);
        } finally {
            CryptoniteJnr.freeByteArray(noncePtr);
        }

        return encoded;
    }

    public static void engineOCSPResponseFree(OcspResponseCtxPointer ctx) {
        instance.ocsp_resp_engine_free(ctx);
    }

    public static TSPResponse generateTsp(SignAdapterPointer sa, byte[] tspRequest, Date date, byte[] serialNumber, boolean isSaveTspCert,
            String[] acceptablePoliciesStr, String defaultPolicyStr)
            throws CryptoniteException {
        final PointerByReference tsp = new PointerByReference();
        final PointerByReference errorStacktrace = new PointerByReference();
        final long[] failureInfoCode = new long[1];
        TSPResponse tspResponse = null;

        final ByteArrayPointer tspRequestBa = CryptoniteJnr.byteToByteArray(tspRequest);
        final ByteArrayPointer serialNumberBa = CryptoniteJnr.byteToByteArray(serialNumber);

        PointerArrayPointer acceptablePoliciesPa = null;
        if (acceptablePoliciesStr != null) {
            acceptablePoliciesPa = instance.pa_alloc(PaDataType.PA_STRING);
            for (String acceptablePolicy : acceptablePoliciesStr) {
                instance.pa_add_string_elem(acceptablePoliciesPa, acceptablePolicy);
            }
        }

        try {
            execute(instance.tsp_engine_generate(sa, tspRequestBa, serialNumberBa, date.getTime(), acceptablePoliciesPa,
                    defaultPolicyStr, tsp, failureInfoCode, errorStacktrace));

            final ByteArrayPointer tspBa = new ByteArrayPointer(tsp);
            String errorMsg = (errorStacktrace.getValue() != null) ? pointerByReferenceToString(errorStacktrace) : null;
            tspResponse = new TSPResponse(CryptoniteJnr.byteArrayToByte(tspBa), failureInfoCode[0], errorMsg);
            CryptoniteJnr.freeByteArray(tspBa);
        } finally {
            CryptoniteJnr.freeByteArray(tspRequestBa);
            CryptoniteJnr.freeByteArray(serialNumberBa);
            instance.pa_free(acceptablePoliciesPa);
        }

        return tspResponse;
    }

    public static void certIdFree(final CertIDPointer certid) {
        instance.certid_free(certid);
    }

    public static byte[] certIdGetIssuerKeyHash(final CertIDPointer certid) throws CryptoniteException {
        final PointerByReference hash = new PointerByReference();

        execute(instance.certid_get_issuer_key_hash(certid, hash));

        final ByteArrayPointer hashBa = new ByteArrayPointer(hash);
        final byte[] hashBytes = CryptoniteJnr.byteArrayToByte(hashBa);

        CryptoniteJnr.freeByteArray(hashBa);

        return hashBytes;
    }

    public static byte[] certIdGetIssuerNameHash(final CertIDPointer certid) throws CryptoniteException {
        final PointerByReference hash = new PointerByReference();

        execute(instance.certid_get_issuer_name_hash(certid, hash));

        final ByteArrayPointer hashBa = new ByteArrayPointer(hash);
        final byte[] hashBytes = CryptoniteJnr.byteArrayToByte(hashBa);

        CryptoniteJnr.freeByteArray(hashBa);

        return hashBytes;
    }

    public static byte[] certIdGetSerialNumber(final CertIDPointer certid) throws CryptoniteException {
        final PointerByReference serial = new PointerByReference();

        execute(instance.certid_get_serial_number(certid, serial));

        final ByteArrayPointer serialBa = new ByteArrayPointer(serial);
        final byte[] serialBytes = CryptoniteJnr.byteArrayToByte(serialBa);

        CryptoniteJnr.freeByteArray(serialBa);

        return serialBytes;
    }

    public static OCSPRequestInfo ocspRequestGetCertId(final byte[] ocspreq) throws CryptoniteException {
        final PointerByReference certids = new PointerByReference();
        final PointerByReference nonce = new PointerByReference();
        PointerArrayPointer pa = null;
        ByteArrayPointer nonceBa = null;
        final byte[] nonceByte;

        final List<OCSPCertId> list = new ArrayList<OCSPCertId>();
        final OCSPRequestPointer request = CryptonitePkiJnr.ocspRequestDecode(ocspreq);

        try {
            execute(instance.ocspreq_get_certid_list(request, certids, nonce));

            pa = new PointerArrayPointer(certids);

            for (int i = 0; i < CryptoniteXJnr.pointerArrayGetCount(pa); i++) {
                final CertIDPointer certID = CryptoniteXJnr.pointerArrayGetCertIdElement(pa, i);

                list.add(new OCSPCertId(CryptoniteXJnr.certIdGetIssuerNameHash(certID),
                                        CryptoniteXJnr.certIdGetIssuerKeyHash(certID),
                                        CryptoniteXJnr.certIdGetSerialNumber(certID)));
            }

            nonceBa = new ByteArrayPointer(nonce);
            nonceByte = CryptoniteJnr.byteArrayToByte(nonceBa);
        } finally {
            pointerArrayFree(pa);
            CryptoniteJnr.freeByteArray(nonceBa);
            CryptonitePkiJnr.ocspRequestFree(request);
        }

        return new OCSPRequestInfo(list, nonceByte);
    }

    public static byte[] signData(SignAdapterPointer sa, final byte[] data) throws CryptoniteException {
        final PointerByReference signPtr = new PointerByReference();
        final ByteArrayPointer ptrData = CryptoniteJnr.byteToByteArray(data);
        final byte[] signByte;

        try {
            execute(instance.sign_adapter_sign_data(sa, ptrData, signPtr));

            final ByteArrayPointer byteArray = new ByteArrayPointer(signPtr);
            signByte = CryptoniteJnr.byteArrayToByte(byteArray);
            CryptoniteJnr.freeByteArray(byteArray);
        } finally {
            CryptoniteJnr.freeByteArray(ptrData);
        }

        return signByte;
    }

    public static byte[] signHash(SignAdapterPointer sa, final byte[] hash) throws CryptoniteException {
        final PointerByReference signPtr = new PointerByReference();
        final ByteArrayPointer ptrHash = CryptoniteJnr.byteToByteArray(hash);
        final byte[] signByte;

        try {
            execute(instance.sign_adapter_sign_hash(sa, ptrHash, signPtr));

            final ByteArrayPointer byteArray = new ByteArrayPointer(signPtr);
            signByte = CryptoniteJnr.byteArrayToByte(byteArray);
            CryptoniteJnr.freeByteArray(byteArray);
        } finally {
            CryptoniteJnr.freeByteArray(ptrHash);
        }

        return signByte;
    }

    public static boolean verifyData(VerifyAdapterPointer va, final byte[] data, final byte[] sign) throws CryptoniteException {
        final ByteArrayPointer ptrData = CryptoniteJnr.byteToByteArray(data);
        final ByteArrayPointer ptrSign = CryptoniteJnr.byteToByteArray(sign);
        boolean isValid = false;

        try {
            int ret = instance.verify_adapter_verify_data(va, ptrData, ptrSign);
            if (ret != CryptoniteException.RET_OK && ret != CryptoniteException.RET_VERIFY_FAILED) {
                execute(ret);
            }

            isValid = (ret == CryptoniteException.RET_OK);
        } finally {
            CryptoniteJnr.freeByteArray(ptrData);
            CryptoniteJnr.freeByteArray(ptrSign);
        }

        return isValid;
    }

    public static boolean verifyHash(VerifyAdapterPointer va, final byte[] hash, final byte[] sign) throws CryptoniteException {
        final ByteArrayPointer ptrHash = CryptoniteJnr.byteToByteArray(hash);
        final ByteArrayPointer ptrSign = CryptoniteJnr.byteToByteArray(sign);
        boolean isValid = false;

        try {
            int ret = instance.verify_adapter_verify_hash(va, ptrHash, ptrSign);
            if (ret != CryptoniteException.RET_OK && ret != CryptoniteException.RET_VERIFY_FAILED) {
                execute(ret);
            }

            isValid = (ret == CryptoniteException.RET_OK);
        } finally {
            CryptoniteJnr.freeByteArray(ptrHash);
            CryptoniteJnr.freeByteArray(ptrSign);
        }

        return isValid;
    }

    public static RsaPublicKey convertCompressPublicKey(final byte[] compress) throws CryptoniteException {
        final ByteArrayPointer ptrcompress = CryptoniteJnr.byteToByteArray(compress);
        final PointerByReference nPtr = new PointerByReference();
        final PointerByReference ePtr = new PointerByReference();
        final byte[] e;
        final byte[] n;

        try {
            execute(instance.pkix_rsa_publickeyto_ba(ptrcompress, nPtr, ePtr));

            final ByteArrayPointer nBytes = new ByteArrayPointer(nPtr);
            final ByteArrayPointer eBytes = new ByteArrayPointer(ePtr);

            n = CryptoniteJnr.byteArrayToByte(nBytes);
            e = CryptoniteJnr.byteArrayToByte(eBytes);

            CryptoniteJnr.freeByteArray(nBytes);
            CryptoniteJnr.freeByteArray(eBytes);
        } finally {
            CryptoniteJnr.freeByteArray(ptrcompress);
        }

        return new RsaPublicKey(n, e);
    }
}
