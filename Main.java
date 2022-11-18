import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Main {
	static PrivateKey privateKey; // holds the private key of RSA key pair
    static PublicKey publicKey;// holds the public key of RSA key pair
	public static void main(String[] args) throws Exception{
		// -------------QUESTION 1------------------
		Question1 question1 = new Question1();
		// PART A
		KeyPair pair = question1.generateKeyPair();
		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();
		/*System.out.println("-----PUBLIC KEY-----");
		System.out.println (Base64.getMimeEncoder().encodeToString( pair.getPublic().getEncoded()));
		System.out.println("-----PRIVATE KEY-----");
		System.out.println (Base64.getMimeEncoder().encodeToString( pair.getPrivate().getEncoded()));*/
		//END OF PART A
		//PART B
		//question1.question1_B();
		//END OF PART B
		//------------------------------------------
		
		// -------------QUESTION 2------------------
		// PART A
		Question2 question2 = new Question2();
		SecretKey AESkey1 = question2.createAESKey(128);
		String StringAESKey1 = Base64.getEncoder().encodeToString(AESkey1.getEncoded());
		SecretKey AESkey2 = question2.createAESKey(256);
		String StringAESKey2 = Base64.getEncoder().encodeToString(AESkey2.getEncoded());
		/*System.out.println("\n128 Bit K1 encrypt and decryption");
		String ciphertext = question2.encrypt(StringAESKey1, publicKey);
		String plaintext = question2.decrypt(ciphertext, privateKey);
		System.out.println (plaintext);
		System.out.println("\n256 Bit K2 encrypt and decryption");
		String ciphertext2 = question2.encrypt(StringAESKey2, publicKey);
		System.out.println (plaintext);
		String plaintext2 = question2.decrypt(ciphertext2, privateKey);
		System.out.println (plaintext2);*/
		// END OF PART A
		// PART B
		
		// END OF PART B
		//------------------------------------------
		
		// -------------QUESTION 3------------------
		//Question3 question3 = new Question3();
		//question3.question3(publicKey, privateKey);
		//------------------------------------------
		
		// -------------QUESTION 4------------------
		Question4 question4 = new Question4();
		long StartTime;
		long EndTime;
		IvParameterSpec iv = question4.generateIv();
		//128 bit CBC
		/*StartTime = System.nanoTime();
		question4.encryptFileWithCBC(AESkey1,iv);
		question4.decryptFileWithCBC(AESkey1, iv);
		EndTime = System.nanoTime();
		System.out.println("Total Time is : " + (EndTime - StartTime));*/
		//256 bit CBC
		/*StartTime = System.nanoTime();
		question4.encryptFileWithCBC(AESkey2,iv);
		question4.decryptFileWithCBC(AESkey2, iv);
		EndTime = System.nanoTime();
		System.out.println("Total Time is : " + (EndTime - StartTime));*/
		//256 bit CTR
		StartTime = System.nanoTime();
		question4.encryptFileWithCTR(AESkey2,iv);
		question4.decryptFileWithCTR(AESkey2, iv);
		EndTime = System.nanoTime();
		System.out.println("Total Time is : " + (EndTime - StartTime));
	}
}
