import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.MessageDigest;
import java.io.*;

import javax.crypto.Cipher;

public class RSA2
{
    
    public static void main(String[] args) throws Exception
    {
        
        // Get an instance of the RSA key generator
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        
        // Generate the KeyPair
        KeyPair kp = kpg.generateKeyPair();
        String text="";
        FileInputStream fin=new FileInputStream("file.txt");
        int c;
        while((c=fin.read())!=-1)
        text+=(char)c;
        byte[]ip=text.getBytes();
        Signature instance = Signature.getInstance("SHA1withRSA");
instance.initSign(kp.getPrivate());
instance.update(ip);
byte[] signature = instance.sign();
String sig=new String(signature);

MessageDigest sha1 = MessageDigest.getInstance("SHA1");
byte[] digest = sha1.digest(ip);
String dig=new String(digest);
// Encrypt digest
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.ENCRYPT_MODE,kp.getPublic());
cipher.update(ip);
byte[] cipherText = cipher.doFinal();
System.out.println("Digest: " + dig);
System.out.println("Signature: " + sig);
System.out.println(new String(cipherText,"UTF8"));
cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
byte[] decipherText = cipher.doFinal(cipherText);
System.out.println(new String(decipherText));
}
}
