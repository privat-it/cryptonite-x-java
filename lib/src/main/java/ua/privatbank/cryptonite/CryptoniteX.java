/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;

import ua.privatbank.cryptonite.helper.OCSPRequestInfo;
import ua.privatbank.cryptonite.helper.CryptoniteHashType;
import ua.privatbank.cryptonite.helper.ExtensionX;
import ua.privatbank.cryptonite.helper.KeyAndRequest;
import ua.privatbank.cryptonite.helper.OCSPResponseErrors;
import ua.privatbank.cryptonite.helper.RevokedInfoX;
import ua.privatbank.cryptonite.helper.OCSPSingleResponse;
import ua.privatbank.cryptonite.helper.ResponderType;
import ua.privatbank.cryptonite.helper.SignInfo;
import ua.privatbank.cryptonite.helper.TSPResponse;
import ua.privatbank.cryptonite.jnr.cms.CrlEngineXPointer;
import ua.privatbank.cryptonite.jnr.cms.OcspResponseCtxPointer;
import ua.privatbank.cryptonite.jnr.cms.PointerArrayPointer;
import ua.privatbank.cryptonite.jnr.cms.StoragePointer;
import ua.privatbank.cryptonite.jnr.cms.VerifyInfosPointer;
import ua.privatbank.cryptonite.jnr.crypto.ByteArrayPointer;
import ua.privatbank.cryptonite.jnr.crypto.Gost28147SboxId;
import ua.privatbank.cryptonite.jnr.crypto.Gost34311CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Md5CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Sha1CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Sha2CtxPointer;
import ua.privatbank.cryptonite.jnr.crypto.Sha2Variant;
import ua.privatbank.cryptonite.jnr.pkix.CertificatePointer;
import ua.privatbank.cryptonite.jnr.pkix.ContentInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.DhAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignAdapterPointer;
import ua.privatbank.cryptonite.jnr.pkix.SignedDataPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampReqPointer;
import ua.privatbank.cryptonite.jnr.pkix.TimeStampRespPointer;
import ua.privatbank.cryptonite.jnr.pkix.VerifyAdapterPointer;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;

public class CryptoniteX {

    private static final String TSP_POLICI_OID = "1.2.84.2.1.1.1.2.3.1";

    private static final String TSP_DEFAULT_SERVER = "http://acsk.privatbank.ua/services/tsp/";

    static {
        CryptoniteXJnr.init();
    }

    private static byte[] request(final String url, final byte[] data) throws IOException {
        final CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();

        try {
            httpclient.start();

            final HttpPost request = new HttpPost(url);
            request.setEntity(new ByteArrayEntity(data));
            request.setHeader("Content-type", "application/octet-stream");
            Future<HttpResponse> future = httpclient.execute(request, null);
            // and wait until a response is received

            HttpResponse response = null;
            byte[] tspAnswer = null;
            try {
                response = future.get();
                tspAnswer = IOUtils.toByteArray(response.getEntity().getContent());
            } catch (Exception e) {
                throw new RuntimeException("Error response for url:" + url, e);
            }

            return tspAnswer;
        } finally {
            httpclient.close();
        }
    }

    private static TimeStampRespPointer createTSP(final String url, final byte[] cert, final byte[] hash, final String polici) throws CryptoniteException {
       String tspUrl = "";
       byte[] tspResp = null;

        if ((url == null) || url.equals("")) {
            if (cert != null){
                final CertificatePointer ptrCert = CryptonitePkiJnr.certificateDecode(cert);
                try {
                    tspUrl = CryptonitePkiJnr.certificateGetTsp(ptrCert);
                } finally {
                    CryptonitePkiJnr.certificateFree(ptrCert);
                }
            }

            if (tspUrl == null || tspUrl.equals("")) {
                tspUrl = TSP_DEFAULT_SERVER;
            }
        } else {
            tspUrl = url;
        }

        final byte[] tspEncode = generateTspRequest(hash, polici, false);

        try {
            tspResp = request(tspUrl, tspEncode);
        } catch (IOException e) {
            throw new RuntimeException("Error TSP request for url:" + tspUrl, e);
        }

        return CryptonitePkiJnr.timeStampRespDecode(tspResp);
    }

    /**
     * Попередня ініціализація бібліотеки.
     */
    public static void init() {
        CryptoniteXJnr.init();
    }

    /**
     * Створити заявку на отримання сертифікату без уточнення особи та додаткових данних
     *
     * @param keyStore    контейнер захищенного ключа
     * @param subjectName ім'я суб'єкта у вигляді форматованого рядка, кожен атрибут імені
     *                    визначається фігурними дужками <code>{}</code>, ключ значення
     *                    кожного атрибуту імені розділяються через <code>=</code>
     * @param dns         рядок, який містить DNS
     * @param email       рядок, який містить адресу електронної пошти
     * @param subjectAttr атрибути суб'єкта у вигляді форматованого рядка, кожен атрибут
     *                    визначається фігурними дужками <code>{}</code>, ключ значення
     *                    кожного атрибуту імені розділяються через <code>=</code>
     *
     * @return байти заявки
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] getCertificateRequest(final KeyStore keyStore, final String subjectName, final String dns,
            final String email, final String subjectAttr) throws CryptoniteException {
        final SignAdapterPointer sa = keyStore.getSignAdapter();
        ByteArrayPointer request = null;
        byte[] encodedRequest = null;

        try {
            request = CryptoniteXJnr.cmsGetCertRequest(sa, subjectName, dns, email, subjectAttr);
            encodedRequest = CryptoniteJnr.byteArrayToByte(request);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
            CryptoniteJnr.freeByteArray(request);
        }

        return encodedRequest;
    }

    /**
     * Створити новий ключ в захищенному контейнері
     *
     * @param password пароль від захищенного контейнера ключа
     * @return байти захищенного контейнера ключа
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] generateDstuPrivateKey(final String password) throws CryptoniteException {
        return generateStorageKey(StorageType.CRYPTONITE_KEY, null, "Key1", password);
    }

    /**
     * Створити новий ключ в захищенному контейнері
     *
     * @param type     тип контейнеру, наприклад StorageType.STORAGE_PKCS12_WITH_SHA1
     * @param aid      ідентифікатор параметрів, можно використовувати свої, або готові з ДСТУ4145, наприклад CryptoniteX.AID_DSTU4145_PARAMS_ID_M257_PB
     * @param alias    назва ключа
     * @param password пароль від захищенного контейнера ключа
     *
     * @return байти захищенного контейнера ключа
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] generateStorageKey(StorageType type, final Algorithm aid, final String alias, final String password) throws CryptoniteException {
        final ByteArrayPointer aidPtr = CryptoniteJnr.byteToByteArray((aid != null) ? aid.getEncoded() : null);
        StoragePointer storage = null;
        final byte[] encoded;

        try {
            storage = CryptoniteXJnr.storageCreate(type, password, 0);

            CryptoniteXJnr.storageGenerateKey(storage, aidPtr, alias, password);

            encoded = CryptoniteXJnr.storageEncode(storage);
        } finally {
            CryptoniteJnr.freeByteArray(aidPtr);
            CryptoniteXJnr.storageFree(storage);
        }

        return encoded;
    }

    /**
     * Створити новий ключ в захищенному контейнері та заявку на отримання сертифікату
     *
     * @param password пароль від захищенного контейнера ключа
     * @return байти захищенного контейнера ключа та байти заявки
     * @throws CryptoniteException у випадку помилки
     */
    public static KeyAndRequest generateDstuPrivateKeyWithRequest(final String password) throws CryptoniteException {
        final KeyAndRequest result = new KeyAndRequest();

        result.key = generateDstuPrivateKey(password);
        result.request = CryptoniteX.getCertificateRequest(new KeyStore(result.key, password), "", null, null, null);

        return result;
    }

    /**
     * Створити заявку на отримання сертифікату без уточнення особи та додаткових данних
     *
     * @param keyStore контейнер захищенного ключа
     * @return байти заявки
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] getCertificateRequest(final KeyStore keyStore) throws CryptoniteException {
        return CryptoniteX.getCertificateRequest(keyStore, "", null, null, null);
    }

    private static byte[] gost34311Hash(final Gost28147SboxId sbox, final byte[] data) throws CryptoniteException {
        final Gost34311CtxPointer ctx = CryptoniteJnr.gost34311Alloc(sbox, new byte[32]);
        final byte[] hash;

        try {
            CryptoniteJnr.gost34311Update(ctx, data);
            hash = CryptoniteJnr.gost34311Final(ctx);
        } finally {
            CryptoniteJnr.gost34311Free(ctx);
        }

        return hash;
    }

    /**
     * Обчислити геш по ГОСТ 34.311 з ДКЕ №1
     *
     * @param data - данні від яких треба обчислити геш
     * @return значення гешу
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] hashData(final byte[] data) throws CryptoniteException {
        if (data == null) {
            return null;
        }

        return gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_1, data);
    }

    /**
     * Обчислити геш по ГОСТ 34.311
     *
     * @param data - данні від яких треба обчислити геш
     * @param mode - тип гешування,
     *             для гешування ГОСТ34.311 обирається - NativeCryptonite.GOST28147_SBOX_ID_1 .. NativeCryptonite.GOST28147_SBOX_ID_18
     *             для гешування DSTU 7564 NativeCryptonite.Kupyna_8 .. NativeCryptonite.Kupyna_512
     *             для гешування MD5 NativeCryptonite.MD5
     *             для гешування SHA-1 NativeCryptonite.SHA_1
     *             для гешування SHA-2 NativeCryptonite.SHA_224 .. NativeCryptonite.SHA_512
     *
     * @return значення гешу
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] hashData(final byte[] data, CryptoniteHashType mode) throws CryptoniteException {
        if (data == null) {
            return null;
        }

        final byte[] hash;

        switch (mode) {
        case GOST34311_SBOX_ID_1:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_1, data);
            break;

        case GOST34311_SBOX_ID_2:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_2, data);
            break;

        case GOST34311_SBOX_ID_3:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_3, data);
            break;

        case GOST34311_SBOX_ID_4:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_4, data);
            break;

        case GOST34311_SBOX_ID_5:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_5, data);
            break;

        case GOST34311_SBOX_ID_6:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_6, data);
            break;

        case GOST34311_SBOX_ID_7:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_7, data);
            break;

        case GOST34311_SBOX_ID_8:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_8, data);
            break;

        case GOST34311_SBOX_ID_9:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_9, data);
            break;

        case GOST34311_SBOX_ID_10:
            hash = gost34311Hash(Gost28147SboxId.GOST28147_SBOX_ID_10, data);
            break;

        case MD5: {
            final Md5CtxPointer ctx = CryptoniteJnr.md5Alloc();
            try {
                CryptoniteJnr.md5Update(ctx, data);
                hash = CryptoniteJnr.md5Final(ctx);
            } finally {
                CryptoniteJnr.md5Free(ctx);
            }
            break;
        }

        case SHA1: {
            final Sha1CtxPointer ctx = CryptoniteJnr.sha1Alloc();
            try {
                CryptoniteJnr.sha1Update(ctx, data);
                hash = CryptoniteJnr.sha1Final(ctx);
            } finally {
                CryptoniteJnr.sha1Free(ctx);
            }
            break;
        }

        case SHA224: {
            final Sha2CtxPointer ctx = CryptoniteJnr.sha2Alloc(Sha2Variant.SHA2_VARIANT_224);
            try {
                CryptoniteJnr.sha2Update(ctx, data);
                hash = CryptoniteJnr.sha2Final(ctx);
            } finally {
                CryptoniteJnr.sha2Free(ctx);
            }
            break;
        }

        case SHA256: {
            final Sha2CtxPointer ctx = CryptoniteJnr.sha2Alloc(Sha2Variant.SHA2_VARIANT_256);
            try {
                CryptoniteJnr.sha2Update(ctx, data);
                hash = CryptoniteJnr.sha2Final(ctx);
            } finally {
                CryptoniteJnr.sha2Free(ctx);
            }
            break;
        }

        case SHA384: {
            final Sha2CtxPointer ctx = CryptoniteJnr.sha2Alloc(Sha2Variant.SHA2_VARIANT_384);
            try {
                CryptoniteJnr.sha2Update(ctx, data);
                hash = CryptoniteJnr.sha2Final(ctx);
            } finally {
                CryptoniteJnr.sha2Free(ctx);
            }
            break;
        }

        case SHA512: {
            final Sha2CtxPointer ctx = CryptoniteJnr.sha2Alloc(Sha2Variant.SHA2_VARIANT_512);
            try {
                CryptoniteJnr.sha2Update(ctx, data);
                hash = CryptoniteJnr.sha2Final(ctx);
            } finally {
                CryptoniteJnr.sha2Free(ctx);
            }
            break;
        }

        default:
            throw new CryptoniteException(CryptoniteException.RET_UNSUPPORTED);
        }

        return hash;
    }

    /**
     * Підписати данні. В підпис включається сертифікат ключа, мітка часа та час підпису
     *
     * @param keyStore контейнер захищенного ключа
     * @param data     данні, які треба підписати
     *
     * @return підпис від даних
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] signData(final KeyStore keyStore, final byte[] data) throws CryptoniteException {
        final SignAdapterPointer sa = keyStore.getSignAdapter();
        final byte[] sign;

        try {
            sign = CryptoniteXJnr.signData(sa, data);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
        }

        return sign;
    }

    /**
     * Підписати геш. В підпис включається сертифікат ключа, мітка часа та час підпису
     *
     * @param keyStore контейнер захищенного ключа
     * @param hash     геш, який треба підписати
     *
     * @return підпис від геша
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] signHash(final KeyStore keyStore, final byte[] hash) throws CryptoniteException {
        final SignAdapterPointer sa = keyStore.getSignAdapter();
        final byte[] sign;

        try {
            sign = CryptoniteXJnr.signHash(sa, hash);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
        }

        return sign;
    }

    public static Boolean verifyData(final KeyStore keyStore, final byte[] data, final byte[] sign) throws CryptoniteException {
        final VerifyAdapterPointer va = keyStore.getVerifyAdapter();
        final Boolean status;

        try {
            status = CryptoniteXJnr.verifyData(va, data, sign);
        } finally {
            CryptonitePkiJnr.verifyAdapterFree(va);
        }

        return status;
    }

    public static Boolean verifyHash(final KeyStore keyStore, final byte[] hash, final byte[] sign) throws CryptoniteException {
        final VerifyAdapterPointer va = keyStore.getVerifyAdapter();
        final Boolean status;

        try {
            status = CryptoniteXJnr.verifyHash(va, hash, sign);
        } finally {
            CryptonitePkiJnr.verifyAdapterFree(va);
        }

        return status;
    }

    /**
     * Підписати геш. В підпис включається сертифікат ключа, мітка часа та час підпису
     *
     * @param keyStore    байти захищенного контейнера ключа
     * @param hash        геш, який треба підписати
     * @param certificate сертифікат ключа
     *
     * @return підпис від геша
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsSignHash(final KeyStore keyStore, final byte[] hash, final byte[] certificate)
            throws CryptoniteException {
        return cmsSignHash(keyStore, hash, certificate, true, "", true);
    }

    /**
     * Підписати геш. В підпис включається сертифікат ключа
     *
     * @param keyStore        контейнер захищенного ключа
     * @param hash            геш, який треба підписати
     * @param certificate     сертифікат ключа
     * @param tspURL          URL сервісу отримання мітки часу. Якщо = "" - брати з сертифікату, якщо = null, не включати мітку часу до до контейнеру підпису
     * @param includeCert     включати сертифікат до контейреру підпису
     * @param includeSignTime включати час підписання до контейреру підпису
     *
     * @return підпис від геша
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsSignHash(final KeyStore keyStore, final byte[] hash, final byte[] certificate, boolean includeCert, String tspURL, boolean includeSignTime) throws CryptoniteException {
        final SignAdapterPointer sa = keyStore.getSignAdapter();
        TimeStampRespPointer timeStampResp = null;
        final byte[] sign;

        try {
            if (tspURL != null) {
                timeStampResp = createTSP(tspURL, certificate, hash, TSP_POLICI_OID);
            }

            final byte[] signedAttrs = CryptoniteXJnr.cmsGenerateSignAttrs(timeStampResp, includeSignTime);
            sign = CryptoniteXJnr.cmsSignHash(sa, certificate, hash, includeCert, signedAttrs, null);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
            CryptonitePkiJnr.timeStampRespFree(timeStampResp);
        }

        return sign;
    }

    /**
     * Підписати данні. В підпис включається сертифікат ключа, мітка часа та час підпису
     *
     * @param keyStore        контейнер захищенного ключа
     * @param data            данні, які треба підписати
     * @param certificate     сертифікат ключа
     *
     * @return підпис від даних
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsSignData(final KeyStore keyStore, final byte[] data, final byte[] certificate) throws CryptoniteException {
        return cmsSignData(keyStore, data, true, certificate, true, "", true);
    }

    /**
     * Підписати данні. В підпис включається сертифікат ключа
     *
     * @param keyStore        контейнер захищенного ключа
     * @param data            данні, які треба підписати
     * @param certificate     сертифікат ключа
     * @param tspURL          URL сервісу отримання мітки часу. Якщо = "" - брати з сертифікату, якщо = null, не включати мітку часу до до контейнеру підпису
     * @param includeData     включати данні до контейреру підпису
     * @param includeCert     включати сертифікат до контейреру підпису
     * @param includeSignTime включати час підписання до контейреру підпису
     *
     * @return підпис від даних
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsSignData(final KeyStore keyStore, final byte[] data, boolean includeData, final byte[] certificate, boolean includeCert, String tspURL, boolean includeSignTime) throws CryptoniteException {
        final SignAdapterPointer sa = keyStore.getSignAdapter();
        TimeStampRespPointer timeStampResp = null;
        final byte[] hash;
        final byte[] sign;

        try {
            hash = CryptoniteX.hashData(data);

            if (tspURL != null) {
                timeStampResp = createTSP(tspURL, certificate, hash, TSP_POLICI_OID);
            }

            final byte[] signedAttrs = CryptoniteXJnr.cmsGenerateSignAttrs(timeStampResp, includeSignTime);
            sign = CryptoniteXJnr.cmsSignData(sa, certificate, includeCert, data, includeData, signedAttrs, null);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
            CryptonitePkiJnr.timeStampRespFree(timeStampResp);
        }

        return sign;
    }

    /**
     * Підписати декілька гешів одним ключем. В підпис включається сертифікат ключа
     *
     * @param keyStore        байти захищенного контейнера ключа
     * @param password        пароль від захищенного контейнера ключа
     * @param hashes          перелік гешів, які треба підписати
     * @param certificate     сертифікат ключа
     * @param tspURL          URL сервісу отримання мітки часу. Якщо = "" - брати з сертифікату, якщо = null, не включати мітку часу до до контейреру підпису
     * @param includeCert     включати сертифікат до контейреру підпису
     * @param includeSignTime включати час підписання до контейреру підпису
     *
     * @return мапу відносих гешу та підпису від кожного геша
     * @throws CryptoniteException у випадку помилки
     */
    public static Map<byte[], byte[]> cmsSignHashBatch(final KeyStore keyStore, final String password, List<byte[]> hashes, final byte[] certificate, String tspURL, boolean includeCert, boolean includeSignTime) throws CryptoniteException {
        HashMap<byte[], byte[]> results = new HashMap<byte[], byte[]>(hashes.size());
        for (byte[] hash : hashes) {
            results.put(hash, cmsSignHash(keyStore, hash, certificate, includeCert, tspURL, includeSignTime));
        }

        return results;
    }

    public static byte[] cmsEncrypt(final KeyStore keyStore, final byte[] data,
            final byte[] srcCert, final byte[] destCert, final String chipherOid, Boolean includeCert) throws CryptoniteException {
        final DhAdapterPointer dha = keyStore.getDhAdapterPointer();
        final byte[] envelopedData;

        try {
            byte[] cert = srcCert;
            if (srcCert == null) {
                cert = keyStore.getCetificate(1 << 4);
            }
            envelopedData = CryptoniteXJnr.cmsEncrypt(dha, data, cert, destCert, chipherOid, includeCert);
        } finally {
            CryptonitePkiJnr.dhAdapterPointerFree(dha);
        }

        return envelopedData;
    }

    public static byte[] cmsDecrypt(final KeyStore keyStore, final byte[] envelopedData, final byte[] encryptData,
            final byte[] receiverCert, final byte[] senderCert) throws CryptoniteException {
        final DhAdapterPointer dha = keyStore.getDhAdapterPointer();
        final byte[] data;

        try {
            data = CryptoniteXJnr.cmsDecrypt(dha, envelopedData, encryptData,
                    receiverCert, senderCert);
        } finally {
            CryptonitePkiJnr.dhAdapterPointerFree(dha);
        }

        return data;
    }

    /**
     * Витягнути данні з контейнеру підпису, якщо контейнер не їх не містить, поверне null
     *
     * @param cmsData CMS контейнер
     * @return данні або null
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsGetData(final byte[] cmsData) throws CryptoniteException {
        ContentInfoPointer ptrCinfo = null;
        SignedDataPointer ptrSdata = null;
        byte[] data = null;

        try {
            ptrCinfo = CryptonitePkiJnr.contentInfoDecode(cmsData);
            ptrSdata = CryptonitePkiJnr.contentInfoGetSignedData(ptrCinfo);
            data = CryptonitePkiJnr.signedDataGetData(ptrSdata);
        } finally {
            CryptonitePkiJnr.signedDataFree(ptrSdata);
            CryptonitePkiJnr.contentInfoFree(ptrCinfo);
        }

        return data;
    }

    /**
     * Встановити данні у контейнеру підпису.
     *
     * @param cmsData CMS контейнер
     * @param data данні
     *
     * @return новий CMS контейнер
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsSetData(final byte[] cmsData, final byte[] data) throws CryptoniteException {
        final ByteArrayPointer ptrData = CryptoniteJnr.byteToByteArray(data);
        ContentInfoPointer ptrCinfo = null;
        SignedDataPointer ptrSdata = null;
        final byte[] encoded;

        try {
            ptrCinfo = CryptonitePkiJnr.contentInfoDecode(cmsData);
            ptrSdata = CryptonitePkiJnr.contentInfoGetSignedData(ptrCinfo);

            CryptoniteXJnr.signedDataSetData(ptrSdata, ptrData);
            CryptonitePkiJnr.contentInfoInitBySignedData(ptrCinfo, ptrSdata);

            encoded = CryptonitePkiJnr.contentInfoEncode(ptrCinfo);
        } finally {
            CryptoniteJnr.freeByteArray(ptrData);
            CryptonitePkiJnr.signedDataFree(ptrSdata);
            CryptonitePkiJnr.contentInfoFree(ptrCinfo);
        }

        return encoded;
    }

    /**
     * Перевірити контейнер підпису
     *
     * @param cmsData CMS контейнер
     * @param certs сертіфікати
     *
     * @return данні підписчиків
     * @throws CryptoniteException у випадку помилки
     */
    public static List<SignInfo> cmsVerify(final byte[] cmsData, List<byte[]> certs) throws CryptoniteException {
        final List<SignInfo> viList = new ArrayList<SignInfo>();

        final VerifyInfosPointer vis = CryptoniteXJnr.cmsVerify(cmsData, null, certs);

        try {
            long count = CryptoniteXJnr.verifyInfosGetCount(vis);
            for (int i = 0; i < count; i++) {
                viList.add(new SignInfo(CryptoniteXJnr.verifyInfosGetElement(vis, i)));
            }
        } finally {
            CryptoniteXJnr.verifyInfosFree(vis);
        }

        return viList;
    }

    public static List<SignInfo> cmsVerify(final byte[] cmsData) throws CryptoniteException {
        return cmsVerify(cmsData, null);
    }

    /**
     * Видалити данні з контейнеру підпису та повернути підписи без данних
     *
     * @param CMSData CMS контейнер
     * @return CMS контейнер
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsTrimData(final byte[] CMSData) throws CryptoniteException {
        final ContentInfoPointer ptrCinfo = CryptonitePkiJnr.contentInfoDecode(CMSData);
        SignedDataPointer ptrSdata = null;
        final byte[] encoded;

        try {
            ptrSdata = CryptonitePkiJnr.contentInfoGetSignedData(ptrCinfo);

            CryptoniteXJnr.signedDataSetData(ptrSdata, null);
            CryptonitePkiJnr.contentInfoInitBySignedData(ptrCinfo, ptrSdata);

            encoded = CryptonitePkiJnr.contentInfoEncode(ptrCinfo);
        } finally {
            CryptonitePkiJnr.signedDataFree(ptrSdata);
            CryptonitePkiJnr.contentInfoFree(ptrCinfo);
        }

        return encoded;
    }

    /**
     * Розбити контейнер підписів на окремі контейрери по 1 підпису. Якщо контейнер має данні,
     * вони будуть міститсь у кожному єкземплярі підпису
     *
     * @param CMSData контейнер з декількома підписами
     * @return декілька контейнерів з окремими підписами
     * @throws CryptoniteException у випадку помилки
     */
    public static List<byte[]> cmsSplit(final byte[] CMSData) throws CryptoniteException {
        final ArrayList<byte[]> list = new ArrayList<byte[]>();
        final PointerArrayPointer ptrSplit = CryptoniteXJnr.CmsSplit(CMSData);

        try {
            long size = CryptoniteXJnr.pointerArrayGetCount(ptrSplit);
            for (long i = 0; i < size; i++) {
                final ByteArrayPointer sdata = CryptoniteXJnr.pointerArrayGetByteArrayElement(ptrSplit, i);
                list.add(CryptoniteJnr.byteArrayToByte(sdata));
            }
        } finally {
            CryptoniteXJnr.pointerArrayFree(ptrSplit);
        }

        return list;
    }

    /**
     * Об'єднати данні з підписом/ами або декілька підписів.
     *
     * @param CMS перелік підписів, які треба об'єднати, якщо перший елемент документ,
     *            який використовувався для підпису, вони будуть додані до результату
     *            (це корисно коли підписи не містять документ і потрібно додати документ до результату)
     *
     * @return контейнер з усіма підписами
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] cmsJoin(final byte[]... CMS) throws CryptoniteException {
        byte[] tmp = null;
        byte[] data = null;
        int i = 0;
        for (byte[] sign : CMS) {
            if (i == 0) {
                try {
                    ContentInfoPointer ptr = CryptonitePkiJnr.contentInfoDecode(sign);
                    CryptonitePkiJnr.contentInfoFree(ptr);
                    tmp = sign;
                } catch (CryptoniteException e) {
                    data = sign;
                }
            } else {
                final ByteArrayPointer result;
                if (data == null) {
                    result = CryptoniteXJnr.CmsJoin(null, sign, tmp);
                } else {
                    result = CryptoniteXJnr.CmsJoin(data, sign, null);
                    data = null;
                }

                tmp = CryptoniteJnr.byteArrayToByte(result);
                CryptoniteJnr.freeByteArray(result);
            }

            i++;
        }

        return tmp;
    }

    /**
     * Генерирует сертификат.
     *
     * @param caKey ключ СА
     * @param certRequest запрос на сертификат
     * @param serialNumber серийный номер сертификата
     * @param notBefore начало времени действия сертификата
     * @param notAfter конец времени действия сертификата
     * @param exts расширения
     *
     * @return сертификат
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] generateCertificate(KeyStore caKey, byte[] certRequest, byte[] serialNumber, Date notBefore,
            Date notAfter, List<ExtensionX> exts) throws CryptoniteException {
        final SignAdapterPointer sa = caKey.getSignAdapter();
        ByteArrayPointer certBa = null;
        final byte[] cert;

        try {
            certBa =  CryptoniteXJnr.engineGenerateCertificate(sa,
                    certRequest,
                    serialNumber,
                    notBefore, notAfter,
                    exts);

            cert = CryptoniteJnr.byteArrayToByte(certBa);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
            CryptoniteJnr.freeByteArray(certBa);
        }

        return cert;
    }

    /**
     * Генерирует частичный список отозванных сертификатов.
     *
     * @param caKey ключ СА
     * @param thisUpdate время формирования CRL
     * @param nextUpdate время формирования следующего CRL
     * @param crlNumber серийный номер CRL
     * @param revokedCertInfos список осозванных сертификатов
     * @param crlDistrPointsUrl URL точки доступа к списку отозванных сертификатов
     * @param freshestCrlUrl URL точки доступа к частичному списку отозванных сертификатов
     * @param deltaCrlIndicator серийный номер полного CRL, данные которого обновляются в частичном CRL
     *
     * @return частичный список отозванных сертификатов
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] generateCrlDelta(KeyStore caKey, Date thisUpdate, Date nextUpdate, byte[] crlNumber,
            List<RevokedInfoX> revokedCertInfos, String crlDistrPointsUrl, String freshestCrlUrl,
            byte[] deltaCrlIndicator) throws CryptoniteException {
        final SignAdapterPointer sa = caKey.getSignAdapter();
        CrlEngineXPointer crlEngine = null;
        final byte[] crl;

        try {
            crlEngine = CryptoniteXJnr.engineCrlDeltaAlloc(deltaCrlIndicator);

            for (RevokedInfoX revokedCertInfo : revokedCertInfos) {
                CryptoniteXJnr.engineCrlAddRevokedInfo(crlEngine, revokedCertInfo);
            }

            crl = CryptoniteXJnr.engineCrlGenerate(crlEngine, sa,
                    thisUpdate, nextUpdate,
                    crlNumber,
                    crlDistrPointsUrl, freshestCrlUrl);
        } finally {
            CryptoniteXJnr.engineCrlFree(crlEngine);
            CryptonitePkiJnr.signAdapterFree(sa);
        }

        return crl;
    }

    /**
     * Генерирует полный список отозванных сертификатов.
     *
     * @param caKey ключ СА
     * @param thisUpdate время формирования CRL
     * @param nextUpdate время формирования следующего CRL
     * @param crlNumber серийный номер CRL
     * @param revokedCertInfos список осозванных сертификатов
     * @param crlDistrPointsUrl URL точки доступа к списку отозванных сертификатов
     * @param freshestCrlUrl URL точки доступа к частичному списку отозванных сертификатов
     *
     * @return полный список отозванных сертификатов
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] generateCrlFull(KeyStore caKey, Date thisUpdate, Date nextUpdate, final byte[] crlNumber,
            List<RevokedInfoX> revokedCertInfos, String crlDistrPointsUrl, String freshestCrlUrl)
            throws CryptoniteException {
        final SignAdapterPointer sa = caKey.getSignAdapter();
        CrlEngineXPointer crlEngine = null;
        final byte[] crl;

        try {
            crlEngine = CryptoniteXJnr.engineCrlFullAlloc();

            for (RevokedInfoX revokedCertInfo : revokedCertInfos) {
                CryptoniteXJnr.engineCrlAddRevokedInfo(crlEngine, revokedCertInfo);
            }

            crl = CryptoniteXJnr.engineCrlGenerate(crlEngine,
                    sa,
                    thisUpdate, nextUpdate,
                    crlNumber,
                    crlDistrPointsUrl, freshestCrlUrl);
        } finally {
            CryptoniteXJnr.engineCrlFree(crlEngine);
            CryptonitePkiJnr.signAdapterFree(sa);
        }

        return crl;
    }

    /**
     * Возвращает информацию о сертификатах, статус которых запрашивается в OCSP запросе.
     *
     * @param ocspRequest OCSP запрос
     * @return информация о сертификатах, статус которых запрашивается в OCSP запросе
     * @throws CryptoniteException у випадку помилки
     */
    public static OCSPRequestInfo ocspRequestGetReqCertList(byte[] ocspRequest) throws CryptoniteException {
        return CryptoniteXJnr.ocspRequestGetCertId(ocspRequest);
    }

    /**
     * Генерирует OCSP ответ.
     *
     * @param ocspKey ключ OCSP
     * @param idType 0, если ResponderId формируется по хешу от ключа
     * @param responseList список сертификатов
     * @param nonce случайность
     * @param producedAt время формирования ответа
     * @return OCSP ответ
     * @throws CryptoniteException у випадку помилки
     */
    public static byte[] generateOcspResponse(KeyStore ocspKey, ResponderType idType,
            List<OCSPSingleResponse> responseList, final byte[] nonce, Date producedAt) throws CryptoniteException {
        final SignAdapterPointer sa = ocspKey.getSignAdapter();
        OcspResponseCtxPointer ctx = null;
        final byte[] response;

        try {
            ctx = CryptoniteXJnr.engineOCSPResponseAlloc(sa, idType.getValue());

            for (OCSPSingleResponse ocspSingleResponse : responseList) {
                switch (ocspSingleResponse.getCertStatus()) {
                case GOOD:
                    CryptoniteXJnr.engineOCSPResponseAddCertificateGood(ctx,
                            ocspSingleResponse.getCertID(),
                            ocspSingleResponse.getThisUpdate(),
                            ocspSingleResponse.getNextUpdate());
                    break;

                case REVOKED:
                    CryptoniteXJnr.engineOCSPResponseAddCertificateRevoked(ctx,
                            ocspSingleResponse.getCertID(),
                            ocspSingleResponse.getRevokedInfo().getRevocationDate(),
                            ocspSingleResponse.getRevokedInfo().getRevocationReason(),
                            ocspSingleResponse.getThisUpdate(),
                            ocspSingleResponse.getNextUpdate());
                case UNKNOWN:
                    CryptoniteXJnr.engineOCSPResponseAddCertificateUnknown(ctx,
                            ocspSingleResponse.getCertID(),
                            ocspSingleResponse.getThisUpdate(),
                            ocspSingleResponse.getNextUpdate());
                    break;
                default:
                    break;
                }
            }

            response = CryptoniteXJnr.engineOCSPResponseFinal(ctx, nonce, producedAt);
        } finally {
            CryptoniteXJnr.engineOCSPResponseFree(ctx);
            CryptonitePkiJnr.signAdapterFree(sa);
        }

        return response;
    }

    /**
     * Генерирует OCSP ответ о внутренней ошибке.
     *
     * @return OCSP ответ о внутренней ошибке
     */
    public static byte[] generateOcspResponseFormInternalError() {
        return OCSPResponseErrors.OCSP_RESP_STATUS_INTERNALERROR.getEncoded();
    }

    /**
     * Генерирует OCSP ответ о поврежденном или не допустимом запросе.
     *
     * @return OCSP ответ о поврежденном или не допустимом запросе.
     */
    public static byte[] generateOcspResponseFormMalformedReq() {
        return OCSPResponseErrors.OCSP_RESP_STATUS_MALFORMEDREQUEST.getEncoded();
    }

    /**
     * Генерирует OCSP ответ о невозможности обработки запроса в связи с перенагрузкой.
     *
     * @return OCSP ответ о невозможности обработки запроса в связи с перенагрузкой.
     */
    public static byte[] generateOcspResponseFormTryLater() {
        return OCSPResponseErrors.OCSP_RESP_STATUS_TRYLATER.getEncoded();
    }

    public static byte[] generateOcspResponseSigRequired() {
        return OCSPResponseErrors.OCSP_RESP_STATUS_SIGREQUIRED.getEncoded();
    }

    /**
     * Генерирует OCSP ответ о запросе от не авторизированого пользователя.
     *
     * @return OCSP ответ о запросе от не авторизированого пользователя.
     */
    public static byte[] generateOcspResponseFormUnauthorized() {
        return OCSPResponseErrors.OCSP_RESP_STATUS_UNAUTHORIZED.getEncoded();
    }

    /**
     * Создает OCSP запрос.
     *
     * @param keyStore ключ для подписания запроса (опционально)
     * @param rootCert корневой сертификат проверки подписи
     * @param ocspCert OCSP сертификат             (опционально)
     * @param includeNonce флаг наличия метки
     * @param serialNumbers серийные номера запрашеваемых сертификатов
     *
     * @return запрос
     */
    public static byte[] generateOCSPRequest(final KeyStore keyStore,
            final byte[] rootCert, final byte[] ocspCert, Boolean includeNonce, List<byte[]> serialNumbers) throws CryptoniteException {
        SignAdapterPointer sa = null;
        final byte[] encoded;

        try {
            sa = (keyStore != null) ? keyStore.getSignAdapter() : null;
            encoded = CryptonitePkiJnr.engineOCSPRequestGenerate(sa, rootCert, ocspCert, includeNonce, serialNumbers);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
        }

        return encoded;
    }

    public static byte[] generateTspRequest(final byte[] hash, final String polici, boolean certReq) throws CryptoniteException {
        final byte[] tspEncode;
        TimeStampReqPointer tsp = null;

        try {
            tsp = CryptonitePkiJnr.timeStampReqGenerate(hash, polici, certReq);
            tspEncode = CryptonitePkiJnr.timeStampReqEncode(tsp);
        } finally {
            CryptonitePkiJnr.timeStampReqFree(tsp);
        }

         return tspEncode;
     }

    /**
     * Генерирует TSP ответ.
     *
     * @param tspKey ключ TSP
     * @param tspRequest TSP запрос
     * @param date метка времени
     * @param serialNumber серийный номер метки времени
     * @param isSaveTspCert сохранять ли TSP сертификат в ответе
     * @param acceptablePolicies список разрешенных TSP Policy OID в виде строк или null, если разрешены все
     * @param defaultPolicy TSP Policy OID используемый по умолчанию
     * @return TSP ответ
     * @throws CryptoniteException у випадку помилки
     */
    public static TSPResponse generateTspResponse(KeyStore tspKey, byte[] tspRequest, Date date, byte[] serialNumber,
            boolean isSaveTspCert, String[] acceptablePolicies, String defaultPolicy) throws CryptoniteException {
        final SignAdapterPointer sa = tspKey.getSignAdapter();
        final TSPResponse tsp;

        try {
            tsp = CryptoniteXJnr.generateTsp(sa, tspRequest, date, serialNumber, isSaveTspCert,
                acceptablePolicies, defaultPolicy);
        } finally {
            CryptonitePkiJnr.signAdapterFree(sa);
        }

        return tsp;
    }

    public static boolean certVerify(final byte[] cert, final byte[] rootCert) throws CryptoniteException {
        return CryptonitePkiJnr.certificateVerify(cert, rootCert);
    }


    public static boolean certificateIsOcspExtKeyUsage(final byte[] cert) throws CryptoniteException {
        return CryptonitePkiJnr.certificateIsOcspExtKeyUsage(cert);
    }

    public static boolean ocspResponseVerify(final byte[] ocspResp, final byte[] cert) throws CryptoniteException {
        return CryptonitePkiJnr.ocspResponseVerify(ocspResp, cert);
    }

    /**
     * Генерирует TSP ответ.
     *
     * @return TSP ответ
     */
    public static byte[] generateTspResponseWaiting() {
        return new byte[] {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x03};
    }


    /**
     * Возвращает версию нативной библиотеки.
     *
     * @return версия
     */
    public String getVersion() {
        return CryptoniteXJnr.VERSION;
    }
}
