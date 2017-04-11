/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import java.util.Date;

import ua.privatbank.cryptonite.CryptoniteXJnr;
import ua.privatbank.cryptonite.CryptoniteException;
import ua.privatbank.cryptonite.CryptonitePkiJnr;
import ua.privatbank.cryptonite.jnr.cms.VerifyInfoPointer;
import ua.privatbank.cryptonite.jnr.pkix.CertificatePointer;
import ua.privatbank.cryptonite.jnr.pkix.TspStatus;

public class SignInfo {
    private final CertificateInfo certificateInfo;
    private final SignStatus signStatus;
    private final Date tsp;
    private final TspStatus tspStatus;
    private final Date signingTime;

    public SignInfo(final VerifyInfoPointer vi) throws CryptoniteException {
        signStatus = CryptoniteXJnr.verifyInfoGetSignStatus(vi);
        tsp = CryptoniteXJnr.verifyInfoGetTspValue(vi);
        tspStatus = CryptoniteXJnr.verifyInfoGetTspStatus(vi);
        signingTime = CryptoniteXJnr.verifyInfoGetSigningTime(vi);
        final CertificatePointer cert = CryptoniteXJnr.verifyInfoGetCertificate(vi);
        certificateInfo = (cert != null) ? new CertificateInfo(cert) : null;
        CryptonitePkiJnr.certificateFree(cert);
    }

    public SignStatus getSignStatus() {
        return signStatus;
    }

    public Date getTsp() {
        return tsp;
    }

    public TspStatus getTspStatus() {
        return tspStatus;
    }

    public Date getSigningTime() {
        return signingTime;
    }

    public CertificateInfo getCertificateInfo() {
        return certificateInfo;
    }

    @Override
    public String toString() {
        return "SignInfo [certificateInfo=" + certificateInfo + ", signStatus=" + signStatus + ", tsp=" + tsp
                + ", tspStatus=" + tspStatus + ", signingTime=" + signingTime + "]";
    }
}
