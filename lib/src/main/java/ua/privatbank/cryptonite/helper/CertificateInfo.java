/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import java.util.Date;
import java.util.HashMap;

import ua.privatbank.cryptonite.CryptoniteException;
import ua.privatbank.cryptonite.CryptonitePkiJnr;
import ua.privatbank.cryptonite.CryptoniteXJnr;
import ua.privatbank.cryptonite.Utils;
import ua.privatbank.cryptonite.jnr.pkix.CertificatePointer;

public class CertificateInfo {

    private final byte[] serialNumber;

    private final HashMap<SupportedCommonName, String> issuer;
    private final HashMap<SupportedCommonName, String> subject;

    private final Date notValidBefore;
    private final Date notValidAfter;

    private final byte[] publicKey;

    private final QcStatementX qcStatement;

    private final String inn;
    private final String egrpou;

    private final HashMap<String, String> subjectAltName;

    private final int keyUsage;

    private final byte[] encoded; 

    public CertificateInfo(final CertificatePointer cert) throws CryptoniteException {
        //TODO: проверить на возможные ошибки при получении различных полей, когда они отсутствуют
        this.serialNumber = CryptonitePkiJnr.certificateGetSerialNumber(cert);
        this.issuer = CryptoniteXJnr.certGetIssuerInfos(cert);
        this.subject = CryptoniteXJnr.certGetSubjectInfos(cert);
        this.subjectAltName = CryptoniteXJnr.certGetSubjectAltName(cert);

        this.inn = CryptoniteXJnr.certGetInn(cert);
        this.egrpou = CryptoniteXJnr.certGetEgrpou(cert);
        this.qcStatement = CryptoniteXJnr.certGetQcStatement(cert);

        this.notValidBefore = CryptoniteXJnr.certificateGetNotBefore(cert);
        this.notValidAfter = CryptoniteXJnr.certificateGetNotAfter(cert);
        this.publicKey = CryptonitePkiJnr.certificateGetSpki(cert);

        this.keyUsage = CryptonitePkiJnr.certificateGetKeyUsage(cert);

        this.encoded = CryptonitePkiJnr.certificateEncode(cert);
    }

    public HashMap<SupportedCommonName, String> getIssuer() {
        return issuer;
    }

    public HashMap<SupportedCommonName, String> getSubject() {
        return subject;
    }

    public String getInn() {
        return inn;
    }

    public Date getNotValidBefore() {
        return notValidBefore;
    }

    public Date getNotValidAfter() {
        return notValidAfter;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getSerialNumber() {
        return serialNumber;
    }

    public QcStatementX getQcStatement() {
        return qcStatement;
    }

    public String getEgrpou() {
        return egrpou;
    }

    public HashMap<String, String> getSubjectAltName() {
        return subjectAltName;
    }

    public int getKeyUsage() {
        return keyUsage;
    }

    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public String toString() {
        return "CertificateInfo [serialNumber=" + Utils.byteToHex(serialNumber) + ", issuer=" + issuer + ", subject="
                + subject + ", notValidBefore=" + notValidBefore + ", notValidAfter=" + notValidAfter + ", publicKey="
                + Utils.byteToHex(publicKey) + ", qcStatement=" + qcStatement + ", inn=" + inn + ", egrpou=" + egrpou
                + ", subjectAltName=" + subjectAltName + ", keyUsage=" + keyUsage + "]";
    }

}
