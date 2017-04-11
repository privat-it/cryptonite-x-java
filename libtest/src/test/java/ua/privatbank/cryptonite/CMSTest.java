package ua.privatbank.cryptonite;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

import ua.privatbank.cryptonite.helper.CRLReason;
import ua.privatbank.cryptonite.helper.CertStatus;
import ua.privatbank.cryptonite.helper.CryptoniteHashType;
import ua.privatbank.cryptonite.helper.ExtensionX;
import ua.privatbank.cryptonite.helper.KeyUsageBits;
import ua.privatbank.cryptonite.helper.OCSPCertId;
import ua.privatbank.cryptonite.helper.OCSPSingleResponse;
import ua.privatbank.cryptonite.helper.QcStatementX;
import ua.privatbank.cryptonite.helper.ResponderType;
import ua.privatbank.cryptonite.helper.RevokedInfoX;
import ua.privatbank.cryptonite.helper.SignInfo;
import ua.privatbank.cryptonite.helper.SignStatus;
import ua.privatbank.cryptonite.helper.TSPResponse;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * Test class created by Dmitrij Kovalevskij on 18.07.2016.
 */
public class CMSTest {

    private KeyStore key;
    private KeyStore keyOcsp;
    private byte[] certKey;
    private byte[] certTsp;
    private byte[] cms3Signs;
    private byte[] testHash;
    private byte[] cms1;
    private byte[] cms2;
    private byte[] cms3;
    private byte[] cms;
    private String password = "testPasswordРізнимиМовамиʼє1ʼ!№;%:?%Э\"";
    private String TSP_URL = "http://acsk.privatbank.ua/services/tsp/";

    @BeforeClass
    public void setUp() throws CryptoniteException {
        try {
            keyOcsp = new KeyStore("src/test/resources/ocsp(123456).key", "123456");
            key = new KeyStore("src/test/resources/ecdsa(123456).jks", "123456");
            certKey = Files.readAllBytes(Paths.get("src/test/resources/ecdsa.cer"));
            certTsp = Files.readAllBytes(Paths.get("src/test/resources/privat_tsp.cer"));
            cms3Signs = Files.readAllBytes(Paths.get("src/test/resources/3sign.pdf"));
            testHash = Files.readAllBytes(Paths.get("src/test/resources/hash.dat"));
            cms1 = Files.readAllBytes(Paths.get("src/test/resources/3sign_1.dat"));
            cms2 = Files.readAllBytes(Paths.get("src/test/resources/3sign_2.dat"));
            cms3 = Files.readAllBytes(Paths.get("src/test/resources/3sign_3.dat"));
            cms = Files.readAllBytes(Paths.get("src/test/resources/0000000726643853.1.0.pdf"));
            
            CryptoniteX.init();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void cmsSplitTest() throws CryptoniteException {
        List<byte[]> cmsList = CryptoniteX.cmsSplit(cms3Signs);

        Assert.assertNotNull(cmsList);
        Assert.assertEquals(cmsList.size(), 3);

        Assert.assertTrue(Arrays.equals(cmsList.get(0), cms1));
        Assert.assertTrue(Arrays.equals(cmsList.get(1), cms2));
        Assert.assertTrue(Arrays.equals(cmsList.get(2), cms3));
    }

    @Test
    public void cmsJoinTest() throws CryptoniteException {
        byte[] result = CryptoniteX.cmsJoin(cms1, cms2, cms3);
        Assert.assertNotNull(result);
        Assert.assertTrue(Arrays.equals(result, cms3Signs));
    }

    @Test
    public void testCreateKey() throws CryptoniteException {
        String password = "testPassword";

        final byte[] key = CryptoniteX.generateDstuPrivateKey(password);
        Assert.assertNotNull(key);

        byte[] request = CryptoniteX.getCertificateRequest(new KeyStore(key, password));
        Assert.assertNotNull(request);
    }

    @Test
    public void testCertificateRequestDSTU() throws CryptoniteException {
        byte[] request = CryptoniteX.getCertificateRequest(key);
        Assert.assertNotNull(request);
    }

    @Test
    public void testCertificateRequestRSA() throws CryptoniteException {
        byte[] request = CryptoniteX.getCertificateRequest(new KeyStore("src/test/resources/rsa(123456).pfx", "123456"));
        Assert.assertNotNull(request);
    }

    @Test
    public void testGenerateTspDSTU() throws IOException, CryptoniteException {
        byte[] tspRequest = Files.readAllBytes(Paths.get("src/test/resources/pki/tsp_request_dstu.der"));
        byte[] serialNumber = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        TSPResponse tspResponse = CryptoniteX.generateTspResponse(keyOcsp, tspRequest, new Date(), serialNumber, false, null, null);
        System.out.println(new Date() + ") tspResponse = " + Utils.byteToHex(tspResponse.getBytes()));
        Assert.assertNotNull(tspResponse.getBytes());
        Assert.assertEquals(0, tspResponse.getErrorCode());
        Assert.assertNull(tspResponse.getErrorMsg());
    }

    @Test
    public void testgenerateStorageKey() throws CryptoniteException {
        byte[] request = CryptoniteX.generateStorageKey(StorageType.PKCS12_WITH_SHA1, Algorithm.DSTU4145_257_PB, "key", "123456");
        Assert.assertNotNull(request);
    }

    @Test
    public void testCMSGetDataAndHash() throws CryptoniteException {
        byte[] data = CryptoniteX.cmsGetData(cms3Signs);
        Assert.assertNotNull(data);
        byte[] hash = CryptoniteX.hashData(data, CryptoniteHashType.GOST34311_SBOX_ID_1);
        Assert.assertTrue(Arrays.equals(testHash, hash));
    }

    @Test
    public void testCMSSignCryptonite() throws CryptoniteException {
        final List<byte[]> certs = new ArrayList<byte[]>();
        certs.add(certTsp);

        final byte[] data = CryptoniteX.cmsGetData(cms3Signs);
        Assert.assertNotNull(data);

        byte[] sign = CryptoniteX.cmsSignData(keyOcsp, data, true, null, true, TSP_URL, true);

        List<SignInfo> listSignInfo = CryptoniteX.cmsVerify(sign, certs);
        for (SignInfo signInfo : listSignInfo) {
            Assert.assertTrue(signInfo.getSignStatus() == SignStatus.VALID);
        }
    }

    @Test
    public void testCMSSetData() throws CryptoniteException {
        List<SignInfo> listSignInfo;
        final List<byte[]> certs = new ArrayList<byte[]>();
        certs.add(certTsp);

        final byte[] data = CryptoniteX.cmsGetData(cms3Signs);
        Assert.assertNotNull(data);

        byte[] sign = CryptoniteX.cmsSignData(keyOcsp, data, false, null, true, TSP_URL, true);

        listSignInfo = CryptoniteX.cmsVerify(sign, certs);
        for (SignInfo signInfo : listSignInfo) {
            Assert.assertTrue(signInfo.getSignStatus() == SignStatus.VALID_WITHOUT_DATA);
        }

        sign = CryptoniteX.cmsSetData(sign, data);

        listSignInfo = CryptoniteX.cmsVerify(sign, certs);
        for (SignInfo signInfo : listSignInfo) {
            Assert.assertTrue(signInfo.getSignStatus() == SignStatus.VALID);
        }
    }

    @Test
    public void testCMSVerify() throws CryptoniteException {
        List<SignInfo> listSignInfo = CryptoniteX.cmsVerify(cms);

        /* TODO: SIGN 1, 2 NOT VALID */
        SignInfo signInfo = listSignInfo.get(2);
        Assert.assertTrue(signInfo.getSignStatus() == SignStatus.VALID);
    }

    @Test
    public void testGenerateCert() throws CryptoniteException {
        byte[] certRequest = null;
        try {
            certRequest = Files.readAllBytes(Paths.get("src/test/resources/cert_request.csr"));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException("Invalid cert request path");
        }

        List<KeyUsageBits> keyUsagesList = new ArrayList<KeyUsageBits>();
        keyUsagesList.add(KeyUsageBits.DIGITAL_SIGNATURE);
        keyUsagesList.add(KeyUsageBits.KEY_AGREEMENT);

        byte[] serialNumber = new byte[20];
        new Random().nextBytes(serialNumber);
        Date notBefore = new java.util.Date();
        Date notAfter = new java.util.Date(notBefore.getTime() + 365L * 24 * 3600 * 1000);
        List<ExtensionX> exts = new ArrayList<ExtensionX>();
        exts.add(ExtensionX.createExtensionKeyUsage(keyUsagesList));
        /* ЭЦП как печать. */
        exts.add(ExtensionX.createExtensionExtKeyUsage(new String[] {"1.2.804.2.1.1.1.3.9"}));
        exts.add(ExtensionX.createExtensionCertPolicies(new String[] {"1.1.1.1.1.1"}));
        exts.add(ExtensionX.createExtensionBasicConstraints(false, 2));

        List<QcStatementX> qcStatements = new ArrayList<QcStatementX>();
        qcStatements.add(new QcStatementX());
        qcStatements.add(new QcStatementX("UAH", 10, 1));
        exts.add(ExtensionX.createExtensionQcStatements(qcStatements));

        exts.add(ExtensionX.createExtensionCrlDistrPointsUrl("http://crl_distr_point.org/"));
        exts.add(ExtensionX.createExtensionFreshestCrlUrl("http://freshest_crl_url.org/"));

        byte[] cert = CryptoniteX.generateCertificate(keyOcsp, certRequest, serialNumber, notBefore, notAfter, exts);

        System.out.println(new Date() + ") cert = " + Utils.byteToHex(cert));
    }

    @Test
    public void testGenerateCrl() throws CryptoniteException {

        Date thisUpdate = new Date();
        Date nextUpdate = new Date(thisUpdate.getTime() + 1L * 24 * 3600 * 1000);
        byte[] serialNumber = new byte[20];
        Arrays.fill(serialNumber, (byte) 2);

        byte[] deltaCrlIndicator = new byte[20];
        Arrays.fill(serialNumber, (byte) 1);

        List<RevokedInfoX> revokedCertInfo = new ArrayList<RevokedInfoX>();
        for (int i = 0; i < 1000; i++) {
            Date revocationDate = new Date(thisUpdate.getTime() - (long)i * 3600 * 1000);

            serialNumber[serialNumber.length - 1] += i % 256;
            serialNumber[serialNumber.length - 2] += (i / 256) % 256;
            revokedCertInfo.add(new RevokedInfoX(serialNumber, revocationDate, CRLReason.CERTIFICATEHOLD, revocationDate));
        }

        byte[] crl = CryptoniteX.generateCrlDelta(keyOcsp, thisUpdate, nextUpdate, serialNumber, revokedCertInfo,
                "http://crlDistrPointsUrl.com", "http://freshestCrlUrl.com", deltaCrlIndicator);

        System.out.println(new Date() + ") crl = " + Utils.byteToHex(crl));
    }

    @Test
    public void testGenerateCertEcdsa() throws CryptoniteException {
        byte[] certRequest = null;
        try {
            certRequest = Files.readAllBytes(Paths.get("src/test/resources/pki/cert_request_ecdsa256_sha256.der"));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException("Invalid cert request path");
        }

        List<KeyUsageBits> keyUsagesList = new ArrayList<KeyUsageBits>();
        keyUsagesList.add(KeyUsageBits.DIGITAL_SIGNATURE);
        keyUsagesList.add(KeyUsageBits.KEY_AGREEMENT);

        byte[] serialNumber = new byte[20];
        Arrays.fill(serialNumber, (byte) 1);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 3600 * 1000);
        List<ExtensionX> exts = new ArrayList<ExtensionX>();
        exts.add(ExtensionX.createExtensionKeyUsage(keyUsagesList));
        /* ЭЦП как печать. */
        exts.add(ExtensionX.createExtensionExtKeyUsage(new String[] {"1.2.804.2.1.1.1.3.9"}));
        exts.add(ExtensionX.createExtensionCertPolicies(new String[] {"1.1.1.1.1.1"}));
        exts.add(ExtensionX.createExtensionBasicConstraints(false, 2));

        List<QcStatementX> qcStatements = new ArrayList<QcStatementX>();
        qcStatements.add(new QcStatementX());
        qcStatements.add(new QcStatementX("UAH", 10, 1));
        exts.add(ExtensionX.createExtensionQcStatements(qcStatements));

        exts.add(ExtensionX.createExtensionCrlDistrPointsUrl("http://crl_distr_point.org/"));
        exts.add(ExtensionX.createExtensionFreshestCrlUrl("http://freshest_crl_url.org/"));

        KeyStore ecdsaKey = new KeyStore("src/test/resources/pki/pkcs12_521_sha256_sha256_des3_PBE-SHA1-3DES.p12", "123456");

        byte[] cert = CryptoniteX.generateCertificate(ecdsaKey, certRequest, serialNumber, notBefore, notAfter, exts);

        System.out.println(new Date() + ") ecdsa cert = " + Utils.byteToHex(cert));
    }

    @Test
    public void testGenerateOCSPResponse() throws CryptoniteException {
        final byte[] issuerNameHash = new byte[32];
        final byte[] issuerKeyHash = new byte[32];
        final byte[] serialNumber = new byte[20];

        Arrays.fill(issuerNameHash, (byte) 0x23);
        Arrays.fill(issuerKeyHash, (byte) 0x45);
        Arrays.fill(serialNumber, (byte) 0x01);

        List<OCSPSingleResponse> responseList = new ArrayList<OCSPSingleResponse>();

        responseList.add(new OCSPSingleResponse(new OCSPCertId(issuerNameHash, issuerKeyHash, serialNumber),
                                                CertStatus.GOOD, new Date()));

        final byte[] response = CryptoniteX.generateOcspResponse(new KeyStore("src/test/resources/ocsp(123456).key", "123456"),
                                                                 ResponderType.HASH_KEY,
                                                                 responseList,
                                                                 null,
                                                                 new Date());

        System.out.println(new Date() + ") ocsp response " + Utils.byteToHex(response));
    }

    @Test
    public void testMemoryUsages() throws CryptoniteException {
        int repeatCount = 50;
        OperatingSystemMXBean operatingSystemMXBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        byte[] privKey = CryptoniteX.generateDstuPrivateKey(password);
        CryptoniteX.getCertificateRequest(new KeyStore(privKey, password));
        System.gc();
        System.runFinalization();
        long allocatedMemory = operatingSystemMXBean.getCommittedVirtualMemorySize();
        long time = System.currentTimeMillis();
        for (int i = repeatCount; i > 0; i--) {
            privKey = CryptoniteX.generateDstuPrivateKey(password);
            CryptoniteX.getCertificateRequest(new KeyStore(privKey, password));
        }
        System.out.println("Час генерації 1 ключа та окремо заявки: "+(System.currentTimeMillis() - time)/repeatCount + "мс");
        time = System.currentTimeMillis();
        for (int i = repeatCount; i > 0; i--) {
            CryptoniteX.generateDstuPrivateKeyWithRequest(password);
        }
        System.out.println("Час генерації 1 ключа з заявкою:        "+(System.currentTimeMillis() - time)/repeatCount + "мс");

        time = System.currentTimeMillis();
        for (int i = repeatCount; i > 0; i--) {
            CryptoniteX.cmsSignHash(key, new byte[32], certKey, true, null, true);
        }
        System.out.println("Час формування ЕЦП:                     "+(System.currentTimeMillis() - time)/repeatCount + "мс");

        time = System.currentTimeMillis();
        for (int i = repeatCount/10; i > 0; i--) {
            CryptoniteX.cmsSignHash(key, new byte[32], certKey, true, TSP_URL, true);
        }
        System.out.println("Час формування ЕЦП з міткою часу:       "+(System.currentTimeMillis() - time)/repeatCount*10 + "мс");

        time = System.currentTimeMillis();
        for (int i = repeatCount; i > 0; i--) {
            CryptoniteX.cmsSplit(cms3Signs);
        }
        System.out.println("Час роз'єднання підпису та документу:   "+(System.currentTimeMillis() - time)/repeatCount + "мс");

        time = System.currentTimeMillis();
        for (int i = repeatCount; i > 0; i--) {
            CryptoniteX.cmsJoin(cms1, cms2, cms3);
        }
        System.out.println("Час об'єднання підпису та документу:    "+(System.currentTimeMillis() - time)/repeatCount + "мс");

        System.gc ();
        System.runFinalization ();
        long newAllocatedMemory = operatingSystemMXBean.getCommittedVirtualMemorySize();
        Assert.assertFalse(newAllocatedMemory > allocatedMemory, "За час виконання тестів збільшився обсяг споживаної пам'яті на "+(newAllocatedMemory-allocatedMemory)/1024 + "kB");
    }
}
