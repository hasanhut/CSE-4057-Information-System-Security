import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class Question4 {
	public static IvParameterSpec generateIv() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return new IvParameterSpec(iv);
	}
    public static void encryptFileWithCBC(SecretKey key,IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, key,iv);
        FileInputStream inputStream = new FileInputStream("deneme.txt");
        FileOutputStream outputStream = new FileOutputStream("denemeEncryptionCBC.txt");
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }
    public static void decryptFileWithCBC(SecretKey key,IvParameterSpec iv) throws Exception{
    	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    	cipher.init(Cipher.DECRYPT_MODE, key,iv);
    	FileInputStream inputStream = new FileInputStream("denemeEncryptionCBC.txt");
        FileOutputStream outputStream = new FileOutputStream("denemeDecryptionCBC.txt");
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    	
    }
    public static void encryptFileWithCTR(SecretKey key,IvParameterSpec iv) throws Exception {
    	SecureRandom secureRandom = new SecureRandom();
		// First, create the cipher
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		// Then generate the key. Can be 128, 192 or 256 bit
		byte[] keyByte = new byte[256 / 8];
		secureRandom.nextBytes(keyByte);
		// Now generate a nonce. You can also use an ever-increasing counter, which is even more secure. NEVER REUSE A NONCE!
		byte[] nonce = new byte[96 / 8];
		secureRandom.nextBytes(nonce);
		byte[] iv1 = new byte[128 / 8];
		System.arraycopy(nonce, 0, iv1, 0, nonce.length);
        cipher.init(Cipher.ENCRYPT_MODE, key,iv);
        FileInputStream inputStream = new FileInputStream("deneme.txt");
        FileOutputStream outputStream = new FileOutputStream("denemeEncryptionCTR.txt");
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }
    public static void decryptFileWithCTR(SecretKey key,IvParameterSpec iv) throws Exception{
    	SecureRandom secureRandom = new SecureRandom();
		// First, create the cipher
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		// Then generate the key. Can be 128, 192 or 256 bit
		byte[] keyByte = new byte[256 / 8];
		secureRandom.nextBytes(keyByte);
		// Now generate a nonce. You can also use an ever-increasing counter, which is even more secure. NEVER REUSE A NONCE!
		byte[] nonce = new byte[96 / 8];
		secureRandom.nextBytes(nonce);
		byte[] iv1 = new byte[128 / 8];
		System.arraycopy(nonce, 0, iv1, 0, nonce.length);
        cipher.init(Cipher.DECRYPT_MODE, key,iv);
        FileInputStream inputStream = new FileInputStream("denemeEncryptionCTR.txt");
        FileOutputStream outputStream = new FileOutputStream("denemeDecryptionCTR.txt");
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    	
    }
}
