/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public class SupportedCommonName {

    public static final SupportedCommonName KNOWLDGE_INFORMATION = new SupportedCommonName("2.5.4.2");
    public static final SupportedCommonName COMMON_NAME = new SupportedCommonName("2.5.4.3");
    public static final SupportedCommonName SURNAME = new SupportedCommonName("2.5.4.4");
    public static final SupportedCommonName SERIAL_NUMBER = new SupportedCommonName("2.5.4.5");
    public static final SupportedCommonName COUNTRY_NAME = new SupportedCommonName("2.5.4.6");
    public static final SupportedCommonName LOCALITY_NAME = new SupportedCommonName("2.5.4.7");
    public static final SupportedCommonName STATE_OR_PROVINCE_NAME = new SupportedCommonName("2.5.4.8");
    public static final SupportedCommonName STREET_ADDRESS = new SupportedCommonName("2.5.4.9");
    public static final SupportedCommonName ORGANIZATION_NAME = new SupportedCommonName("2.5.4.10");
    public static final SupportedCommonName ORGANIZATIONAL_UNIT_NAME = new SupportedCommonName("2.5.4.11");
    public static final SupportedCommonName TITLE = new SupportedCommonName("2.5.4.12");
    public static final SupportedCommonName DESCRIPTION = new SupportedCommonName("2.5.4.13");
    public static final SupportedCommonName BUSINESS_CATEGORY = new SupportedCommonName("2.5.4.15");
    public static final SupportedCommonName POSTAL_ADDRESS = new SupportedCommonName("2.5.4.16");
    public static final SupportedCommonName POSTAL_CODE = new SupportedCommonName("2.5.4.17");
    public static final SupportedCommonName POST_OFFICE_BOX = new SupportedCommonName("2.5.4.18");
    public static final SupportedCommonName PHYSICAL_DELIVERY_OFFICE_NAME = new SupportedCommonName("2.5.4.19");
    public static final SupportedCommonName TELEPHONE_NUMBER = new SupportedCommonName("2.5.4.20");
    public static final SupportedCommonName REGISTERED_ADDRESS = new SupportedCommonName("2.5.4.26");
    public static final SupportedCommonName GIVEN_NAME = new SupportedCommonName("2.5.4.42");
    public static final SupportedCommonName EMAIL = new SupportedCommonName("1.2.840.113549.1.9.1");

    private final String value;

    public SupportedCommonName(final String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        switch (value) {
        case "2.5.4.6":
            return "COUNTRY_NAME";
        case "2.5.4.5":
            return "SERIAL_NUMBER";
        case "2.5.4.2":
            return "KNOWLDGE_INFORMATION";
        case "2.5.4.3":
            return "COMMON_NAME";
        case "2.5.4.9":
            return "STREET_ADDRESS";
        case "2.5.4.7":
            return "LOCALITY_NAME";
        case "2.5.4.8":
            return "STATE_OR_PROVINCE_NAME";
        case "2.5.4.4":
            return "SURNAME";
        case "2.5.4.10":
            return "ORGANIZATION_NAME";
        case "2.5.4.11":
            return "ORGANIZATIONAL_UNIT_NAME";
        case "2.5.4.12":
            return "TITLE";
        case "2.5.4.13":
            return "DESCRIPTION";
        case "2.5.4.15":
            return "BUSINESS_CATEGORY";
        case "2.5.4.17":
            return "POSTAL_CODE";
        case "2.5.4.18":
            return "POST_OFFICE_BOX";
        case "2.5.4.19":
            return "PHYSICAL_DELIVERY_OFFICE_NAME";
        case "2.5.4.42":
            return "GIVEN_NAME";
        case "1.2.840.113549.1.9.1":
            return "EMAIL";
        case "2.5.4.16":
            return "POSTAL_ADDRESS";
        case "2.5.4.20":
            return "TELEPHONE_NUMBER";
        case "2.5.4.26":
            return "REGISTERED_ADDRESS";
        }

        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SupportedCommonName that = (SupportedCommonName) o;

        return value != null ? value.equals(that.value) : that.value == null;
    }

    @Override
    public int hashCode() {
        return value != null ? value.hashCode() : 0;
    }
}
