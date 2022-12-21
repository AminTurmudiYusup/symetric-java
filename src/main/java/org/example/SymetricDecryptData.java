package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static java.util.Base64.getDecoder;

public class SymetricDecryptData {

    public static SecretKey decodeSecretKey(String secretKey){
        byte[] decodeKey = getDecoder().decode(secretKey);
        SecretKey secretKey1= new SecretKeySpec(decodeKey, 0, decodeKey.length, "AES");
        return secretKey1;
    }
    public static IvParameterSpec decodeIVParameterSpec(String ivParameterString){
        byte [] decodedIV = Base64.getDecoder().decode(ivParameterString);
        return  new IvParameterSpec(decodedIV);
    }

    public static String decrypt(String cipherText, SecretKey secretKey, String algorithm, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] raw = getDecoder().decode(cipherText);
        byte[] stringBytes= cipher.doFinal(raw);
        String stringPlainText= new String(stringBytes, "UTF-8");
        return stringPlainText;
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String encodeKey ="YUlqyf+7XV+fb29adQV3K9Cs44Q6l7huT2AoCd8XBUY=";//this is secret key which encode
        String encodeIvParameterSpec = "pptwLaru2bUnLCq2LbgFAg==";//this is salt/ivParameterSpec which already encode
        String cipherText="gDzEFOtNt/M1k/elLJ4tcw=="; //this is data which encrypt
        String algorithm = "AES/CBC/PKCS5Padding";

        //decode secret key and ivParameterSpec
        SecretKey secretKey = SymetricDecryptData.decodeSecretKey(encodeKey);
        IvParameterSpec ivParameterSpec= SymetricDecryptData.decodeIVParameterSpec(encodeIvParameterSpec);

        //decrypt cipher text into plaintext
        String plainText = SymetricDecryptData.decrypt(cipherText, secretKey, algorithm, ivParameterSpec);
        System.out.print(plainText);

    }
}
