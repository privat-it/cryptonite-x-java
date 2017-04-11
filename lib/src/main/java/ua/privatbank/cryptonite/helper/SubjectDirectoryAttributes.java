/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

public class SubjectDirectoryAttributes {

        private String organizationalUnitName;
        private String commonName;
        private String serialNumber;
        private String countryName;
        private String localityName;
        private String stateOrProvinceName;
        private String organizationName;
        private String title;
        private String givenName;
        private String surname;
        private String streetAddress;
        private String postalCode;

    SubjectDirectoryAttributes() { }

    public String getOrganizationalUnitName() {
        return organizationalUnitName;
    }

    public String getCommonName() {
        return commonName;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getCountryName() {
        return countryName;
    }

    public String getLocalityName() {
        return localityName;
    }

    public String getStateOrProvinceName() {
        return stateOrProvinceName;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public String getTitle() {
        return title;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getSurname() {
        return surname;
    }

    public String getStreetAddress() {
        return streetAddress;
    }

    public String getPostalCode() {
        return postalCode;
    }

    void setOrganizationalUnitName(String organizationalUnitName) {
        this.organizationalUnitName = organizationalUnitName;
    }

    void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    void setCountryName(String countryName) {
        this.countryName = countryName;
    }

    void setLocalityName(String localityName) {
        this.localityName = localityName;
    }

    void setStateOrProvinceName(String stateOrProvinceName) {
        this.stateOrProvinceName = stateOrProvinceName;
    }

    void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    void setTitle(String title) {
        this.title = title;
    }

    void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    void setSurname(String surname) {
        this.surname = surname;
    }

    void setStreetAddress(String streetAddress) {
        this.streetAddress = streetAddress;
    }

    void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    @Override
    public String toString() {
        return "SubjectDirectoryAttributes [organizationalUnitName=" + organizationalUnitName + ", commonName="
                + commonName + ", serialNumber=" + serialNumber + ", countryName=" + countryName + ", localityName="
                + localityName + ", stateOrProvinceName=" + stateOrProvinceName + ", organizationName="
                + organizationName + ", title=" + title + ", givenName=" + givenName + ", surname=" + surname
                + ", streetAddress=" + streetAddress + ", postalCode=" + postalCode + "]";
    }
}
