package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

public class SymetricEncryptData {
    public static SecretKey decodeSecretKey(String secretKey){
        byte[] decodeKey = getDecoder().decode(secretKey);
        SecretKey secretKey1= new SecretKeySpec(decodeKey, 0, decodeKey.length, "AES");
        return secretKey1;
    }
    public static IvParameterSpec decodeIVParameterSpec(String ivParameterString){
        byte [] decodedIV = Base64.getDecoder().decode(ivParameterString);
        return  new IvParameterSpec(decodedIV);
    }

    public static String encrypt(String palinText, SecretKey secretKey, String algorithm, IvParameterSpec iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] stringBytes= palinText.getBytes("UTF-8");
        byte[] raw= cipher.doFinal(stringBytes);
        return getEncoder().encodeToString(raw);
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String encodeKey ="CVrCuABDW0jSWN1SwwE/EBOzIThFPey923GM6BPZoVs=";//this is secret key which encode
        String encodeIvParameterSpec = "FQucujsS74/QIbfg4vuf5g==";//this is salt/ivParameterSpec which already encode
        String algorithm = "AES/CBC/PKCS5Padding";

        //decode secret key and ivParameterSpec
        SecretKey secretKey = SymetricDecryptData.decodeSecretKey(encodeKey);
        IvParameterSpec ivParameterSpec= SymetricDecryptData.decodeIVParameterSpec(encodeIvParameterSpec);

        Scanner input = new Scanner(System.in);
        System.out.println("Insert the phone number to encrypt ...");
        String data = input.nextLine();
        //decrypt cipher text into plaintext
        String cipherText = SymetricEncryptData.encrypt(data, secretKey, algorithm, ivParameterSpec);
        System.out.println("this is phone number which already decrypt >>> "+ cipherText);

        System.out.println("Insert the identity number to encrypt ...");
        String identity = input.nextLine();
        //decrypt cipher text into plaintext
        String cipherTextIdentity = SymetricEncryptData.encrypt(identity, secretKey, algorithm, ivParameterSpec);
        System.out.println("this is identity number which already decrypt >>> "+cipherTextIdentity);
    }
}
