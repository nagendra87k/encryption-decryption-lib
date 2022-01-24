package com.nagendra.encryptiondecryption.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.AttributeConverter;
import java.security.Key;
import java.util.Base64;

@Component
@PropertySource({"classpath:/application.properties"})
public class AttributeConverterImpl implements AttributeConverter<String, String> {

    private static final String AES = "AES";

    public static String key;

    @Value("${key.enc}")
    public static void setKey(String key) {
        AttributeConverterImpl.key = key;
    }

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    public AttributeConverterImpl() throws Exception {
        byte[] encryptionKey = key.getBytes("UTF-8");
        Key key = new SecretKeySpec(encryptionKey, AES);
        encryptCipher = Cipher.getInstance(AES);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        decryptCipher = Cipher.getInstance(AES);
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        try {
            return Base64.getEncoder().encodeToString(encryptCipher.doFinal(attribute.getBytes()));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        try {
            return new String(decryptCipher.doFinal(Base64.getDecoder().decode(dbData)));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalArgumentException(e);
        }
    }

}