import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

public class Question3 {
	static byte[] digitalSignature;
	static byte[] encryptedMessageHash;
	static byte[] decryptedMessageHash;
	public static void question3(PublicKey publicKey,PrivateKey privateKey) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageBytes = Files.readAllBytes(Paths.get("src/text.txt"));
        byte[] messageHash = md.digest(messageBytes);

        encryptedMessageHash = encrypt(privateKey,messageHash);
        decryptedMessageHash = decrypt(publicKey);
        

        byte[] messageBytes2 = Files.readAllBytes(Paths.get("src/text.txt"));
        MessageDigest md2 = MessageDigest.getInstance("SHA-256");
        byte[] newMessageHash = md2.digest(messageBytes2);

        boolean isCorrect = Arrays.equals(decryptedMessageHash, newMessageHash);
        System.out.println("\n");
        System.out.println("Is the content of the file the same as the encrypted content? ----> "+isCorrect);
        System.out.println("\n");
        System.out.println("-----M(message)-----");
        System.out.println(new String(messageBytes, StandardCharsets.UTF_8));
        System.out.println("-----H(m)-----");
        System.out.println(Base64.getEncoder().encodeToString(messageHash));
        System.out.println("-----DIGITAL SIGNATURE-----");
        System.out.println(Base64.getEncoder().encodeToString(digitalSignature));

    }
	public static byte[] encrypt(PrivateKey privateKey,byte[] messageHash) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        digitalSignature = cipher.doFinal(messageHash);
        Files.write(Paths.get("digital_signature_1"), digitalSignature);
        encryptedMessageHash = Files.readAllBytes(Paths.get("digital_signature_1"));
        return encryptedMessageHash;
	}
	public static byte[] decrypt(PublicKey publicKey) throws Exception{
		Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedMessageHash = cipher2.doFinal(encryptedMessageHash);
        return decryptedMessageHash;
	}
}
