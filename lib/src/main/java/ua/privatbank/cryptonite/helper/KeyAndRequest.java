/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite.helper;

/**
 * Додатковий класс для збереження зашифрованного ключа та заявки на отримання сертифікату
 */
public class KeyAndRequest {
    public byte[] key;
    public byte[] request;
}
