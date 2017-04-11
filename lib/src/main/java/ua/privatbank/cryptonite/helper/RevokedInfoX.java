/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import java.util.Date;

public class RevokedInfoX {
    private final byte[] serialNumber;
    private final Date revocationDate;
    private final CRLReason revocationReason;
    private final Date invalidityDate;

    public RevokedInfoX(final byte[] serialNumber, Date revocationDate) {
        this(serialNumber, revocationDate, CRLReason.UNSPECIFIED, null);
    }

    public RevokedInfoX(final byte[] serialNumber, Date revocationDate, CRLReason revocationReason) {
        this(serialNumber, revocationDate, revocationReason, null);
    }

    public RevokedInfoX(final byte[] serialNumber, Date revocationDate, CRLReason revocationReason, Date invalidityDate) {
        this.serialNumber = serialNumber.clone();
        this.revocationDate = new Date(revocationDate.getTime());
        this.revocationReason = revocationReason;
        this.invalidityDate = (invalidityDate != null) ? new Date(invalidityDate.getTime()) : null;
    }

    public Date getRevocationDate() {
        return revocationDate;
    }

    public Date getInvalidityDate() {
        return invalidityDate;
    }

    public CRLReason getRevocationReason() {
        return revocationReason;
    }

    public byte[] getSerialNumber() {
        return serialNumber;
    }
}
