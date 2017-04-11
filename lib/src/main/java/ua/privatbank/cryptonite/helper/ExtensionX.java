/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import java.util.List;

import ua.privatbank.cryptonite.CryptoniteXJnr;
import ua.privatbank.cryptonite.CryptoniteException;
import ua.privatbank.cryptonite.CryptonitePkiJnr;
import ua.privatbank.cryptonite.jnr.pkix.ExtensionPointer;

public class ExtensionX {

    private byte[] encoded;

    private ExtensionX(ExtensionPointer ext) throws CryptoniteException {
        encoded = CryptoniteXJnr.extEncode(ext);
    }

    /*
     * Генерирует расширение сертификата.
     *
     * @param keyUsage битовая маска использования ключа
     * @return расширение сертификата
     */
    public static ExtensionX createExtensionKeyUsage(List <KeyUsageBits> keyUsagesList) throws CryptoniteException {
        int keyUsage = 0;
        for (KeyUsageBits keyUsageBits : keyUsagesList) {
            keyUsage |= keyUsageBits.getValue();
        }

        return new ExtensionX(CryptonitePkiJnr.extCreateKeyUsage(true, keyUsage));
    }

    /*
     * Генерирует расширение сертификата.
     *
     * @param extKeyUsage список OID уточненного использования ключа
     * @return расширение сертификата
     */
    public static ExtensionX createExtensionExtKeyUsage(String[] extKeyUsage) throws CryptoniteException {
        return new ExtensionX(CryptoniteXJnr.extCreateExtKeyUsage(true, extKeyUsage));
    }

    /*
     * Генерирует расширение сертификата.
     *
     * @param certPolicies OID политики сертификации
     * @return расширение сертификата
     */
    public static ExtensionX createExtensionCertPolicies(String[] certPolicies) throws CryptoniteException {
        return new ExtensionX(CryptoniteXJnr.extCreateCertPolicies(true, certPolicies));
    }

    /*
     * Генерирует расширение сертификата.
     *
     * @param basicConstraintsCA значение true, если сертификат сформированый для центра, false - для подписанта
     * @param basicConstraintsPathLenConstraint максимально допустимое количество промежуточных сертификатов
     * @return расширение сертификата
     */
    public static ExtensionX createExtensionBasicConstraints(boolean ca, int pathLenConstraint) throws CryptoniteException {
        return new ExtensionX(CryptonitePkiJnr.extCreateBasicConstraints(true, ca, pathLenConstraint));
    }

    /*
     * Генерирует расширение сертификата.
     *
     * @param qcStatements признаки усиленного сертификата
     * @return расширение сертификата
     */
    public static ExtensionX createExtensionQcStatements(List<QcStatementX> qcStatements) throws CryptoniteException {
        return new ExtensionX(CryptoniteXJnr.extCreateQcStatements(true, qcStatements));
    }

    /*
     * Генерирует расширение сертификата.
     *
     * @param crlDistrPointsUrl URL точки доступа к списку отозванных сертификатов
     * @return расширение сертификата
     */
    public static ExtensionX createExtensionCrlDistrPointsUrl(String crlDistrPointsUrl) throws CryptoniteException {
        return new ExtensionX(CryptoniteXJnr.extCreateCrlDistrPointsUrl(false, crlDistrPointsUrl));
    }

    /*
     * Генерирует расширение сертификата.
     *
     * @param freshestCrlUrl URL точки доступа к частичному списку отозванных сертификатов
     * @return расширение сертификата
     */
    public static ExtensionX createExtensionFreshestCrlUrl(String freshestCrlUrl) throws CryptoniteException {
        return new ExtensionX(CryptoniteXJnr.extCreateFreshestCrlUrl(false, freshestCrlUrl));
    }

    public static ExtensionX createExtensionNetscapeComment() throws CryptoniteException {
        return new ExtensionX(null);
    }

    public static ExtensionX createExtensionNetscapeCARevocationURL() throws CryptoniteException {
        return new ExtensionX(null);
    }

    public static ExtensionX createExtensionNetscapeCertType() throws CryptoniteException {
        return new ExtensionX(null);
    }

    public static ExtensionX createExtensionNetscapeRevocationURL() throws CryptoniteException {
        return new ExtensionX(null);
    }

    public static ExtensionX createExtensionAny(boolean critical, String oid, byte[] extensionValue) throws CryptoniteException {
        return new ExtensionX(CryptoniteXJnr.extCreateAny(critical, oid, extensionValue));
    }

    public byte[] getEncoded() {
        return encoded;
    }
}
