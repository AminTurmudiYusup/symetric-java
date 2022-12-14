package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

/**
 * Hello world!
 *
 */
public class Symetric
{
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator aesKey = KeyGenerator.getInstance("AES");
        aesKey.init(256);
        SecretKey secretKey= aesKey.generateKey();
        return secretKey;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String palinText, SecretKey secretKey, String algorithm, IvParameterSpec iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] stringBytes= palinText.getBytes("UTF-8");
        byte[] raw= cipher.doFinal(stringBytes);
        return getEncoder().encodeToString(raw);
    }

    public static String decrypt(String cipherText, SecretKey secretKey, String algorithm, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] raw = getDecoder().decode(cipherText);
        byte[] stringBytes= cipher.doFinal(raw);
        String stringPlainText= new String(stringBytes, "UTF-8");
        return stringPlainText;
    }

    public static String encodeSecretKey(SecretKey secretKey){
        String encode = getEncoder().encodeToString(secretKey.getEncoded());
        return encode;
    }

    public static SecretKey decodeSecretKey(String secretKey){
        byte[] decodeKey = getDecoder().decode(secretKey);
        SecretKey secretKey1= new SecretKeySpec(decodeKey, 0, decodeKey.length, "AES");
        return secretKey1;
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        SecretKey secretKey= Symetric.generateKey();
//        SecretKey key2 = new SecretKeySpec(secretKey, 0, secretKey.length, "AES");
        String secretKeyEncode = encodeSecretKey(secretKey);
        System.out.println("Secret Key encode>>> "+ secretKeyEncode);
        SecretKey secretKeyDecode = decodeSecretKey(secretKeyEncode);
        System.out.println("Secret Key decode>>> "+ secretKeyDecode);
//        SecretKey secretKey1= new SecretKeySpec("AES");
        String plainText = "Amin Turmudi Yusup";
        String algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec= generateIv();
        String encryptedText = Symetric.encrypt(plainText, secretKeyDecode, algorithm, ivParameterSpec);
        System.out.println("Encrypted Text >>>"+ encryptedText);
        String decryptedText = Symetric.decrypt(encryptedText, secretKeyDecode, algorithm, ivParameterSpec);
        System.out.println("Decrypted Text >>>"+ decryptedText);
    }
}
