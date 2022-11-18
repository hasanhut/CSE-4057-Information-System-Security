import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class Question1 {
	public static KeyPair generateKeyPair() throws Exception {
		// RSA Key Pair Generator Function
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); 
        KeyPair kp = kpg.generateKeyPair();

        return kp;
	}
	public static void question1_B() throws Exception{
		// Generate two Elliptic-Curve Diffie Helman public-private key pairs.
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
	    kpg.initialize(new ECGenParameterSpec("secp521r1"));;
	    KeyPair kp1 = kpg.generateKeyPair();
	    KeyPair kp2 = kpg.generateKeyPair();
	    System.out.println ("-----KB- BEGIN PRIVATE KEY-----");
        System.out.println (Base64.getMimeEncoder().encodeToString( kp1.getPrivate().getEncoded()));
        System.out.println ("-----END PRIVATE KEY-----");
        System.out.println ("-----KB+ BEGIN PUBLIC KEY-----");
        System.out.println (Base64.getMimeEncoder().encodeToString( kp1.getPublic().getEncoded()));
        System.out.println ("-----END PUBLIC KEY-----");
        System.out.println ("-----KC- BEGIN PRIVATE KEY-----");
        System.out.println (Base64.getMimeEncoder().encodeToString( kp2.getPrivate().getEncoded()));
        System.out.println ("-----END PRIVATE KEY-----");
        System.out.println ("-----KC+ BEGIN PUBLIC KEY-----");
        System.out.println (Base64.getMimeEncoder().encodeToString( kp2.getPublic().getEncoded()));
        System.out.println ("-----END PUBLIC KEY-----");
	}
}
