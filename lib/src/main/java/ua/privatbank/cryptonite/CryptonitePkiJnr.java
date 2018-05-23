/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

import java.util.List;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;

import ua.privatbank.cryptonite.jnr.CryptonitePkiNative;
import ua.privatbank.cryptonite.jnr.asn1.Asn1DescriptorPointer;
import ua.privatbank.cryptonite.jnr.asn1.INTEGERPointer;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.id.OidId;
import ua.privatbank.cryptonite.jnr.pkix.AlgorithmIdentifierPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificatePointer;
import ua.privatbank.cryptonite.jnr.pkix.ContentInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.DhAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.DigestAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.EncapsulatedContentInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.ExtensionPointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPRequestPointer;
import ua.privatbank.cryptonite.jnr.pkix.OCSPResponsePointer;
import ua.privatbank.cryptonite.jnr.pkix.OcspRequestEnginePointer;
import ua.privatbank.cryptonite.jnr.pkix.OidNumbersPointer;
import ua.privatbank.cryptonite.jnr.pkix.PrivateKeyInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.QCStatementPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.SubjectPublicKeyInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampReqPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampRespPointer;
import ua.privatbank.cryptonite.jnr.pkix.VerifyAdapterPointer;

public class CryptonitePkiJnr extends CryptoniteAbstract {

    /** Instance native library. */
    private static CryptonitePkiNative instance = null;

    /** Name native library. */
    public static final String LIB_NAME = "cryptonite_pki";

    static {
        init();
    }

    public static void init() {
        if (instance == null) {
            CryptoniteJnr.init();
            instance = loadLibrary(LIB_NAME, CryptonitePkiNative.class);

            VERSION = "9c44ddb8ae9e";
        }
    }

    public static INTEGERPointer integerCreate(final byte[] value) throws CryptoniteException {
        final PointerByReference ptrInteger = new PointerByReference();
        execute(instance.asn_create_integer(value, value.length, ptrInteger));
        return new INTEGERPointer(ptrInteger);
    }

    public static void integerFree(final INTEGERPointer integer) {
        Asn1DescriptorPointer descriptor = instance.get_INTEGER_desc();
        instance.asn_free(descriptor, integer.getPointer());
    }

    public static OidNumbersPointer oidsGetOidNumbersById(OidId oid_id) {
        return instance.oids_get_oid_numbers_by_id(oid_id);
    }

    public static CertificatePointer certificateDecode(final byte[] cert) throws CryptoniteException {
        final ByteArrayPointer ptrByteCert = CryptoniteJnr.byteToByteArray(cert);
        final CertificatePointer ptrAsn1Cert = instance.cert_alloc();

        try {
            execute(instance.cert_decode(ptrAsn1Cert, ptrByteCert));
        } catch (Exception e) {
            instance.cert_free(ptrAsn1Cert);
            throw e;
        } finally {
            CryptoniteJnr.freeByteArray(ptrByteCert);
        }

        return ptrAsn1Cert;
    }

    public static byte[] certificateEncode(final CertificatePointer cert) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();
        execute(instance.cert_encode(cert, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static byte[] certificateGetSerialNumber(final CertificatePointer cert) throws CryptoniteException {
        final PointerByReference ptrSn = new PointerByReference();
        execute(instance.cert_get_sn(cert, ptrSn));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrSn);
        CryptoniteJnr.byteArraySwap(byteArray);
        final byte[] sn = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return sn;
    }

    public static boolean certificateVerify(final byte[] cert, final byte[] rootCert) throws CryptoniteException {
        CertificatePointer certPtr = certificateDecode(cert);
        VerifyAdapterPointer vaPtr = getVerifyAdapterByCert(rootCert);

        try {
            execute(instance.cert_verify(certPtr, vaPtr));

            return true;
        } catch (Exception e) {
            return false;
        } finally {
            certificateFree(certPtr);
            verifyAdapterFree(vaPtr);
        }
    }

    public static void certificateFree(final CertificatePointer cert) {
        instance.cert_free(cert);
    }

    public static String certificateGetTsp(final CertificatePointer cert) throws CryptoniteException {
        final PointerByReference data = new PointerByReference();

        execute(instance.cert_get_tsp_url(cert, data));

        final ByteArrayPointer byteArray = new ByteArrayPointer(data);
        final String url = CryptoniteJnr.byteArrayToString(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return url;
    }

    public static AlgorithmIdentifierPointer aidDecode(final byte[] aid) throws CryptoniteException {
        final ByteArrayPointer ptrByteAid = CryptoniteJnr.byteToByteArray(aid);
        final AlgorithmIdentifierPointer ptrAid = instance.aid_alloc();

        try {
            execute(instance.aid_decode(ptrAid, ptrByteAid));
        } catch (Exception e) {
            instance.aid_free(ptrAid);
            throw e;
        } finally {
            CryptoniteJnr.freeByteArray(ptrByteAid);
        }

        return ptrAid;
    }

    public static byte[] certificateGetSpki(final CertificatePointer cert) throws CryptoniteException {
        final PointerByReference ptrSpki = new PointerByReference();
        final byte[] encoded;

        execute(instance.cert_get_spki(cert, ptrSpki));

        final SubjectPublicKeyInfoPointer spki = new SubjectPublicKeyInfoPointer(ptrSpki.getValue());

        try {
            encoded = spkiEncode(spki);
        } finally {
            spkiFree(spki);
        }

        return encoded;
    }

    public static boolean certificateIsOcspExtKeyUsage(final byte[] cert) throws CryptoniteException {
        CertificatePointer certPtr = certificateDecode(cert);

        try {
            boolean flag = false;
            execute(instance.cert_is_ocsp_cert(certPtr, flag));
            return flag;
        } catch (Exception e) {
            return false;
        } finally {
            CryptonitePkiJnr.certificateFree(certPtr);;
        }
    }

    public static void aidFree(final AlgorithmIdentifierPointer aid) {
        instance.aid_free(aid);
    }

    public static byte[] spkiEncode(final SubjectPublicKeyInfoPointer spki) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();
        execute(instance.spki_encode(spki, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static void spkiFree(final SubjectPublicKeyInfoPointer spki) {
        instance.spki_free(spki);
    }

    public static SignAdapterPointer getSignAdapterByCert(final byte[] privateKey, final byte[] cert) throws CryptoniteException {
        final PointerByReference sa = new PointerByReference();
        final ByteArrayPointer ptrPrivateKey = CryptoniteJnr.byteToByteArray(privateKey);
        CertificatePointer ptrCert = null;

        try {
            ptrCert = certificateDecode(cert);
            execute(instance.sign_adapter_init_by_cert(ptrPrivateKey, ptrCert, sa));
        } finally {
            CryptoniteJnr.freeByteArray(ptrPrivateKey);
            certificateFree(ptrCert);
        }

        return new SignAdapterPointer(sa);
    }

    public static SignAdapterPointer getSignAdapterByAlg(final byte[] privateKey, final byte[] aid, final byte[] params) throws CryptoniteException {
        final PointerByReference sa = new PointerByReference();
        final ByteArrayPointer ptrPrivateKey = CryptoniteJnr.byteToByteArray(privateKey);
        AlgorithmIdentifierPointer ptrAid = null;
        AlgorithmIdentifierPointer ptrParams = null;

        try {
            ptrAid = aidDecode(aid);
            ptrParams = aidDecode(params);
            
            execute(instance.sign_adapter_init_by_aid(ptrPrivateKey, ptrAid, ptrParams, sa));
        } finally {
            aidFree(ptrAid);
            aidFree(ptrParams);
        }

        return new SignAdapterPointer(sa);
    }

    public static void signAdapterFree(final SignAdapterPointer sa) {
        instance.sign_adapter_free(sa);
    }

    public static VerifyAdapterPointer getVerifyAdapterByCert(final byte[] cert) throws CryptoniteException {
        final PointerByReference va = new PointerByReference();
        CertificatePointer ptrCert = null;

        try {
            ptrCert = certificateDecode(cert);
            execute(instance.verify_adapter_init_by_cert(ptrCert, va));
        } finally {
            certificateFree(ptrCert);
        }

        return new VerifyAdapterPointer(va);
    }

    public static void verifyAdapterFree(final VerifyAdapterPointer va) {
        instance.verify_adapter_free(va);
    }

    public static DigestAdapterPointer getDefaultDigestAdapter() throws CryptoniteException {
        final PointerByReference ptrDa = new PointerByReference();
        execute(instance.digest_adapter_init_default(ptrDa));
        return new DigestAdapterPointer(ptrDa);
    }

    public static void digestAdapterFree(final DigestAdapterPointer da) {
        instance.digest_adapter_free(da);
    }

    public static void dhAdapterPointerFree(final DhAdapterPointer dha) {
        instance.dh_adapter_free(dha);
    }

    public static ContentInfoPointer contentInfoAlloc() {
        return instance.cinfo_alloc();
    }

    public static void contentInfoInitBySignedData(ContentInfoPointer cinfo, final SignedDataPointer sdata) throws CryptoniteException {
        execute(instance.cinfo_init_by_signed_data(cinfo, sdata));
    }

    public static ContentInfoPointer contentInfoDecode(final byte[] cinfo) throws CryptoniteException {
        final ByteArrayPointer ptrByteCinfo = CryptoniteJnr.byteToByteArray(cinfo);
        final ContentInfoPointer ptrCinfo = instance.cinfo_alloc();

        try {
            execute(instance.cinfo_decode(ptrCinfo, ptrByteCinfo));
        } catch (Exception e) {
            contentInfoFree(ptrCinfo);
            throw e;
        } finally {
            CryptoniteJnr.freeByteArray(ptrByteCinfo);
        }

        return ptrCinfo;
    }

    public static byte[] contentInfoEncode(final ContentInfoPointer cinfo) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();

        execute(instance.cinfo_encode(cinfo, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static void contentInfoFree(final ContentInfoPointer cinfo) {
        instance.cinfo_free(cinfo);
    }

    public static byte[] contentInfoGetData(final ContentInfoPointer cinfo) throws CryptoniteException {
        PointerByReference data = new PointerByReference();
        execute(instance.cinfo_get_data(cinfo, data));

        final ByteArrayPointer byteArray = new ByteArrayPointer(data);
        final byte[] dataBytes = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return dataBytes;
    }

    public static SignedDataPointer contentInfoGetSignedData(final ContentInfoPointer cinfo) throws CryptoniteException {
        PointerByReference sdata = new PointerByReference();
        execute(instance.cinfo_get_signed_data(cinfo, sdata));

        return new SignedDataPointer(sdata.getValue());
    }

    public static SignedDataPointer signedDataDecode(final byte[] sdata) throws CryptoniteException {
        final ByteArrayPointer ptrByteSdata = CryptoniteJnr.byteToByteArray(sdata);
        final SignedDataPointer ptrSdata = instance.sdata_alloc();

        try {
            execute(instance.sdata_decode(ptrSdata, ptrByteSdata));
        } catch (Exception e) {
            signedDataFree(ptrSdata);
            throw e;
        } finally {
            CryptoniteJnr.freeByteArray(ptrByteSdata);
        }

        return ptrSdata;
    }

    public static byte[] signedDataEncode(final SignedDataPointer signedData) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();
        execute(instance.sdata_encode(signedData, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static void signedDataFree(final SignedDataPointer signedData) {
        instance.sdata_free(signedData);
    }

    public static Pointer signedDataGetContent(final SignedDataPointer signedData) throws CryptoniteException {
        PointerByReference content = new PointerByReference();
        execute(instance.sdata_get_content(signedData, content));

        return content.getValue();
    }

    public static byte[] signedDataGetData(final SignedDataPointer signedData) throws CryptoniteException {
        PointerByReference ptrData = new PointerByReference();
        execute(instance.sdata_get_data(signedData, ptrData));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrData);
        final byte[] data = CryptoniteJnr.byteArrayToByte(byteArray);
        CryptoniteJnr.freeByteArray(byteArray);

        return data;
    }

    public static void signedDataSetData(final SignedDataPointer signedData, final EncapsulatedContentInfoPointer content) throws CryptoniteException {
        execute(instance.sdata_set_content(signedData, content));
    }

    public static void timeStampReqFree(final TimeStampReqPointer tsreq) {
        instance.tsreq_free(tsreq);
    }

    public static byte[] timeStampReqEncode(final TimeStampReqPointer tsreq) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();

        execute(instance.tsreq_encode(tsreq, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static TimeStampRespPointer timeStampRespDecode(final byte[] encoded) throws CryptoniteException {
        final ByteArrayPointer ptrByteTsresp = CryptoniteJnr.byteToByteArray(encoded);
        final TimeStampRespPointer ptrTsresp = instance.tsresp_alloc();

        try {
            execute(instance.tsresp_decode(ptrTsresp, ptrByteTsresp));
        } catch (Exception e) {
            timeStampRespFree(ptrTsresp);
            throw e;
        } finally {
            CryptoniteJnr.freeByteArray(ptrByteTsresp);
        }

        return ptrTsresp;
    }

    public static byte[] timeStampRespEncode(final TimeStampRespPointer timeStampResp) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();

        execute(instance.tsresp_encode(timeStampResp, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static void timeStampRespFree(final TimeStampRespPointer timeStampResp) {
        instance.tsresp_free(timeStampResp);
    }

    public static PrivateKeyInfoPointer pkcs8Decode(final byte[] pkcs8) throws CryptoniteException {
        final ByteArrayPointer ptrBytePkcs8 = CryptoniteJnr.byteToByteArray(pkcs8);
        final PrivateKeyInfoPointer ptrPkcs8 = instance.pkcs8_alloc();

        try {
            execute(instance.pkcs8_decode(ptrPkcs8, ptrBytePkcs8));
        } catch (Exception e) {
            pkcs8Free(ptrPkcs8);
        } finally {
            CryptoniteJnr.freeByteArray(ptrBytePkcs8);
        }

        return ptrPkcs8;
    }

    public static byte[] pkcs8Encode(final PrivateKeyInfoPointer pkcs8) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();

        execute(instance.pkcs8_encode(pkcs8, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static void pkcs8Free(final PrivateKeyInfoPointer pkcs8) {
        instance.pkcs8_free(pkcs8);
    }

    public static byte[] pkcs8Generate(final byte[] aid) throws CryptoniteException {
        final PointerByReference ptrKey = new PointerByReference();
        AlgorithmIdentifierPointer ptrAid = null;
        PrivateKeyInfoPointer key = null;
        final byte[] encode;

        try {
            ptrAid = aidDecode(aid);
            execute(instance.pkcs8_generate(ptrAid, ptrKey));

            key = new PrivateKeyInfoPointer(ptrKey.getValue());
            encode = pkcs8Encode(key);
        } finally {
            pkcs8Free(key);
            aidFree(ptrAid);
        }

        return encode;
    }

    public static SignAdapterPointer pkcs8GetSignAdapter(final byte[] pkcs8) throws CryptoniteException {
        final PointerByReference sa = new PointerByReference();
        final PrivateKeyInfoPointer ptrPkcs8 = pkcs8Decode(pkcs8);

        try {
            execute(instance.pkcs8_get_sign_adapter(ptrPkcs8, null, sa));
        } finally {
            pkcs8Free(ptrPkcs8);
        }

        return new SignAdapterPointer(sa.getValue());
    }

    public static SubjectPublicKeyInfoPointer pkcs8GetSpki(final byte[] pkcs8) throws CryptoniteException {
        final PointerByReference spki = new PointerByReference();
        final PrivateKeyInfoPointer ptrPkcs8 = pkcs8Decode(pkcs8);

        try {
            execute(instance.pkcs8_get_spki(ptrPkcs8, spki));
        } finally {
            pkcs8Free(ptrPkcs8);
        }

        return new SubjectPublicKeyInfoPointer(spki.getValue());
    }

    public static TimeStampReqPointer timeStampReqGenerate(final byte[] hash, final String policy, boolean certReq) throws CryptoniteException {
        PointerByReference tsp_req = new PointerByReference();
        final ByteArrayPointer ptrHash = CryptoniteJnr.byteToByteArray(hash);

        try {
            execute(instance.etspreq_generate_from_gost34311(ptrHash, policy, certReq, tsp_req));
        } finally {
            CryptoniteJnr.freeByteArray(ptrHash);
        }

        return new TimeStampReqPointer(tsp_req.getValue());
    }

    public static ExtensionPointer extCreateKeyUsage(final boolean critical, int usageBits) throws CryptoniteException {
        PointerByReference ext = new PointerByReference();

        execute(instance.ext_create_key_usage(critical, usageBits, ext));

        return new ExtensionPointer(ext.getValue());
    }

    public static ExtensionPointer extCreateBasicConstraints(final boolean critical, final boolean ca, int pathLenConstraint) throws CryptoniteException {
        PointerByReference ext = new PointerByReference();

        execute(instance.ext_create_basic_constraints(critical, null, ca, pathLenConstraint, ext));

        return new ExtensionPointer(ext.getValue());
    }

    public static QCStatementPointer extCreateQcStatementCompliance() throws CryptoniteException {
        PointerByReference qcStatement = new PointerByReference();

        execute(instance.ext_create_qc_statement_compliance(qcStatement));

        return new QCStatementPointer(qcStatement.getValue());
    }

    public static QCStatementPointer extCreateQcStatementLimitValue(String currency_code, long amount, long exponent) throws CryptoniteException {
        PointerByReference qcStatement = new PointerByReference();

        execute(instance.ext_create_qc_statement_limit_value(currency_code, amount, exponent, qcStatement));

        return new QCStatementPointer(qcStatement.getValue());
    }

    public static void extFree(final ExtensionPointer ext) {
        instance.ext_free(ext);
    }

    public static boolean ocspResponseVerify(final byte[] ocspResp, final byte[] cert) throws CryptoniteException {
        OCSPResponsePointer ocspResponsePointer = ocspResponseDecode(ocspResp);
        VerifyAdapterPointer vaPtr = getVerifyAdapterByCert(cert);

        try {
            execute(instance.ocspresp_verify(ocspResponsePointer, vaPtr));

            return true;
        } catch (Exception e) {
            return false;
        } finally {
            ocspResposeFree(ocspResponsePointer);
            verifyAdapterFree(vaPtr);
        }
    }

    public static byte[] ocspResposeEncode(final OCSPResponsePointer ocsp) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();
        execute(instance.ocspresp_encode(ocsp, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static void ocspResposeFree(final OCSPResponsePointer ocsp) {
        instance.ocspresp_free(ocsp);
    }

    public static void ocspRequestFree(OCSPRequestPointer ocspreq) {
        instance.ocspreq_free(ocspreq);
    }

    public static byte[] ocspRequestEncode(final OCSPRequestPointer ocsp) throws CryptoniteException {
        final PointerByReference ptrEncoded = new PointerByReference();
        execute(instance.ocspreq_encode(ocsp, ptrEncoded));

        final ByteArrayPointer byteArray = new ByteArrayPointer(ptrEncoded);
        final byte[] encode = CryptoniteJnr.byteArrayToByte(byteArray);

        CryptoniteJnr.freeByteArray(byteArray);

        return encode;
    }

    public static OCSPRequestPointer ocspRequestDecode(final byte[] request) throws CryptoniteException {
        final ByteArrayPointer ptrByteRequest = CryptoniteJnr.byteToByteArray(request);
        final OCSPRequestPointer ptrAsn1Request = instance.ocspreq_alloc();

        try {
            execute(instance.ocspreq_decode(ptrAsn1Request, ptrByteRequest));
        } catch (Exception e) {
            ocspRequestFree(ptrAsn1Request);
            throw e;
        } finally {
            CryptoniteJnr.freeByteArray(ptrByteRequest);
        }

        return ptrAsn1Request;
    }

    public static OCSPResponsePointer ocspResponseDecode(final byte[] response) throws CryptoniteException {
        final ByteArrayPointer ptrByteResponse = CryptoniteJnr.byteToByteArray(response);
        final OCSPResponsePointer ptrAsn1Response = instance.ocspresp_alloc();

        try {
            execute(instance.ocspresp_decode(ptrAsn1Response, ptrByteResponse));
        } catch (Exception e) {
            ocspResposeFree(ptrAsn1Response);
            throw e;
        } finally {
            CryptoniteJnr.freeByteArray(ptrByteResponse);
        }

        return ptrAsn1Response;
    }

    public static byte[] engineOCSPRequestGenerate(final SignAdapterPointer sa,
            final byte[] rootCert, final byte[] ocspCert, Boolean includeNonce, List<byte[]> serialNumbers) throws CryptoniteException {
        final PointerByReference ptrCtx = new PointerByReference();
        final PointerByReference ptrRequest = new PointerByReference();
        OcspRequestEnginePointer ctx = null;
        OCSPRequestPointer request = null;
        VerifyAdapterPointer vaRoot = null;
        VerifyAdapterPointer vaOcsp = null;
        DigestAdapterPointer da = null;
        INTEGERPointer sn = null;
        ByteArrayPointer nonce = null;
        final byte[] encode;

        try {
            vaRoot = getVerifyAdapterByCert(rootCert);
            vaOcsp = (ocspCert != null) ? getVerifyAdapterByCert(ocspCert) : null;
            da = getDefaultDigestAdapter();

            execute(instance.eocspreq_alloc(includeNonce, vaRoot, vaOcsp, sa, da, ptrCtx));
            ctx = new OcspRequestEnginePointer(ptrCtx);

            for (byte[] serialNumber : serialNumbers) {
                sn = integerCreate(serialNumber);
                execute(instance.eocspreq_add_sn(ctx, sn));
                integerFree(sn);
                sn = null;
            }

            if (includeNonce) {
                nonce = CryptoniteJnr.byteArrayByRnd(20);
            }

            execute(instance.eocspreq_generate(ctx, nonce, ptrRequest));
            request = new OCSPRequestPointer(ptrRequest);
            encode = ocspRequestEncode(request);

        } finally {
            verifyAdapterFree(vaRoot);
            verifyAdapterFree(vaOcsp);
            digestAdapterFree(da);
            ocspRequestFree(request);

            instance.eocspreq_free(ctx);

            CryptoniteJnr.freeByteArray(nonce);
        }

        return encode;
    }
}
