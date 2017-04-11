/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import java.util.Date;

public class OCSPSingleResponse {

    private final OCSPCertId certID;
    private final CertStatus certStatus;
    private final Date thisUpdate;
    private final Date nextUpdate;
    private final RevokedInfoX revokedInfo;

    public OCSPSingleResponse(final OCSPCertId certID, final RevokedInfoX revokedInfo, final Date thisUpdate, final Date nextUpdate) {
        this.certID = certID;
        this.certStatus = CertStatus.REVOKED;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.revokedInfo = revokedInfo;
    }

    public OCSPSingleResponse(final OCSPCertId certID, final CertStatus certStatu, final Date thisUpdate, final Date nextUpdate) {
        this.certID = certID;
        this.certStatus = certStatu;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.revokedInfo = null;
    }

    public OCSPSingleResponse(final OCSPCertId certID, final CertStatus certStatu, final Date thisUpdate) {
        this(certID, certStatu, thisUpdate, null);
    }

    public OCSPSingleResponse(final OCSPCertId certID, final RevokedInfoX revokedInfo, final Date thisUpdate) {
        this(certID, revokedInfo, thisUpdate, null);
    }

    public OCSPCertId getCertID() {
        return certID;
    }

    public CertStatus getCertStatus() {
        return certStatus;
    }

    public Date getThisUpdate() {
        return thisUpdate;
    }

    public Date getNextUpdate() {
        return nextUpdate;
    }

    public RevokedInfoX getRevokedInfo() {
        return revokedInfo;
    }
}
