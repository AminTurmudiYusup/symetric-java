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
import java.util.Scanner;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

/**
 * Hello world!
 *
 */
public class SymetricEncrypt
{
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator aesKey = KeyGenerator.getInstance("AES");
        aesKey.init(256);
        SecretKey secretKey= aesKey.generateKey();
        return secretKey;
    }

    public static IvParameterSpec generateIvParameterSpec() {
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

    public static String encodeSecretKey(SecretKey secretKey){
        String encode = getEncoder().encodeToString(secretKey.getEncoded());
        return encode;
    }

    public static String encodeIVParameterSpec(IvParameterSpec ivParameterSpec){
        String encode = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
        return encode;
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
       //generate secret and salt
        SecretKey secretKey= SymetricEncrypt.generateSecretKey();
        IvParameterSpec ivParameterSpec= generateIvParameterSpec();

        Scanner input = new Scanner(System.in);
        System.out.println("Insert data to encrypt ...");
        String plainText = input.nextLine();
        String algorithm = "AES/CBC/PKCS5Padding";

        //encrypt plaintext to ciphertext
        String encryptedText = SymetricEncrypt.encrypt(plainText, secretKey, algorithm, ivParameterSpec);
        System.out.println("Encrypted Text >>> "+ encryptedText);

//        encode secret key
        String secretKeyEncode = encodeSecretKey(secretKey);
        System.out.println("Secret Key encode>>> "+ secretKeyEncode);

        //encode salt/or ivParameterSpec
        String ivEncode = SymetricEncrypt.encodeIVParameterSpec(ivParameterSpec);
        System.out.println("ivParameterSpec Encode>> "+ivEncode);


    }
}
