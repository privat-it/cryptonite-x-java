/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

import ua.privatbank.cryptonite.CryptoniteXJnr;
import ua.privatbank.cryptonite.CryptoniteException;
import ua.privatbank.cryptonite.CryptonitePkiJnr;
import ua.privatbank.cryptonite.jnr.pkix.QCStatementPointer;

public class QcStatementX {

    private String currencyCode;
    private long amount;
    private long exponent;

    public QcStatementX() {
    }

    public QcStatementX(String currencyCode, long amount, long exponent) {
        this.currencyCode = currencyCode;
        this.amount = amount;
        this.exponent = exponent;
    }

    public byte[] getEncoded() throws CryptoniteException {
        final QCStatementPointer qcStatement;

        if (currencyCode == null) {
            qcStatement = CryptonitePkiJnr.extCreateQcStatementCompliance();
        } else {
            qcStatement = CryptonitePkiJnr.extCreateQcStatementLimitValue(currencyCode, amount, exponent);
        }

        final byte[] encoded = CryptoniteXJnr.qcStatementEncode(qcStatement);
        CryptoniteXJnr.qcStatementFree(qcStatement);

        return encoded;
    }

    public String getCurrencyCode() {
        return currencyCode;
    }

    public long getAmount() {
        return amount;
    }

    public long getExponent() {
        return exponent;
    }

    @Override
    public String toString() {
        return "QcStatementX [currencyCode=" + currencyCode + ", amount=" + amount + ", exponent=" + exponent + "]";
    }
}
