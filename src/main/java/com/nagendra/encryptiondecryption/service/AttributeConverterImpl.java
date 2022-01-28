package com.nagendra.encryptiondecryption.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.AttributeConverter;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import static com.nagendra.encryptiondecryption.constant.EncryptionConstant.*;

@Component
public class AttributeConverterImpl implements AttributeConverter<String, String> {

    Logger logger = LoggerFactory.getLogger(AttributeConverterImpl.class);

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    public AttributeConverterImpl(@Value("${encryption.key}")  String keyCode) throws Exception {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(keyCode.toCharArray(), salt, 65536, 256); // AES-256
        SecretKeyFactory f = SecretKeyFactory.getInstance(PBKDF2WITHHMACSHA1);
        byte[] key = f.generateSecret(spec).getEncoded();
        SecretKeySpec keySpec = new SecretKeySpec(key, AES);

        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        encryptCipher = Cipher.getInstance(PKCS5PADDING);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec,iv);
        decryptCipher = Cipher.getInstance(PKCS5PADDING);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec,iv);
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