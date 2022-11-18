import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Question2 {
	//QUESTION 2 - A
	public static SecretKey createAESKey(int bit) throws Exception {
		// Creating a new instance of SecureRandom class.
        SecureRandom securerandom = new SecureRandom();
        // Passing the string to KeyGenerator
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
        // Initializing the KeyGenerator with any bits.
        keygenerator.init(bit, securerandom);
        SecretKey key = keygenerator.generateKey();
        System.out.println ("-----AES KEY " + bit + "-----");
        System.out.println (Base64.getMimeEncoder().encodeToString( key.getEncoded()));
        return key;
        
	}
	public static String encrypt(String input, PublicKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(input.getBytes());
		System.out.println ("-----ENCRYPT-----");
		System.out.println(Base64.getEncoder().encodeToString(cipherText));
		return Base64.getEncoder().encodeToString(cipherText);
	}
	public static String decrypt(String cipherText, PrivateKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		System.out.println ("-----DECRYPT-----");
		return new String(plainText);
	}
}
