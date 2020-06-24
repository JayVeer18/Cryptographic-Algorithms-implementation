import javax.crypto.spec.DESKeySpec;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;

import java.util.Scanner;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.math.BigInteger;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
public class ALGO
{SecretKey key;
 SecureRandom rand,saltrand;
 KeyGenerator gen;
 Cipher c;
 IvParameterSpec iv;
 String mode;
 int ivsize;
 String md5;
 byte[] salt = new byte[16];
 MessageDigest md;
 public ALGO(String mode,String algo,int size) throws Exception
 {this.mode = mode;
  rand = new SecureRandom();
  gen = KeyGenerator.getInstance(algo);
  gen.init(size,rand);
  key = gen.generateKey();
  md = MessageDigest.getInstance("MD5");
  /*byte[] theKey = hexToBytes("0F1571C947D9E859");
  KeySpec ks = new DESKeySpec(theKey);
  SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
  key = kf.generateSecret(ks);*/
  ivsize=algo.equals("AES")?16:8;
  System.out.println("IV Size in bytes:"+ivsize);
  iv = new IvParameterSpec(new byte[ivsize]);
  System.out.println("Key: "+key.toString());
  c = Cipher.getInstance(algo+"/"+mode+"/PKCS5Padding");	 
  saltrand = SecureRandom.getInstance("SHA1PRNG", "SUN");
  saltrand.nextBytes(salt);
 }
 public String encrypt(String text)throws Exception
 {if(mode.equals("ECB"))
	{c.init(Cipher.ENCRYPT_MODE,key);}
  else
	{c.init(Cipher.ENCRYPT_MODE,key,iv);}
  byte[] btext = text.getBytes();
  byte[] encbyte = c.doFinal(btext);
  //md.update(btext,0,btext.length);
  md.update(salt);
  md5 = new BigInteger(1,md.digest(btext)).toString(16);
 return new String(encbyte);  
 }
 public String decrypt(String text)throws Exception
 {if(mode.equals("ECB"))
	{c.init(Cipher.DECRYPT_MODE,key);}
  else
	{c.init(Cipher.DECRYPT_MODE,key,iv);}
  byte[] btext = text.getBytes();
  byte[] decbyte = c.doFinal(btext);
  md.update(salt);
  //md.update(decbyte,0,decbyte.length);
  String m5 = new BigInteger(1,md.digest(decbyte)).toString(16);
  if(md5.equals(m5))
  {System.out.println("Message is not corrupted...");}
  else
  {System.out.println("Message is corrupted!..");
   System.out.println("previous hash:"+md5);
   System.out.println("current hash:"+m5);
  }
 return new String(decbyte);	 
 }	
 /*public byte[] hexToBytes(String str) {
      if (str==null || str.length() < 2) {return null;}
	  else {
         int len = str.length() / 2;
         byte[] buffer = new byte[len];
         for (int i=0; i<len; i++) {
             buffer[i] = (byte) Integer.parseInt(str.substring(i*2,i*2+2),16);
         }
         return buffer;
      }
   }*/
 public static void main(String[] args)
 {Scanner sc = new Scanner(System.in);
  System.out.print("Enter the text: ");
  String text = sc.nextLine();
  System.out.print("Enter algorithm(DESede or TripleDES,DES,AES): ");
  String algo = sc.nextLine();
  int size=56;
  if(algo.equals("DESede")||algo.equals("TripleDES"))
	{
	 System.out.print("Enter keysize(112(for two different keys),168(for three different keys)): ");  
	 size = sc.nextInt();String dummy=sc.nextLine();
	}
  if(algo.equals("AES"))
	{
	 System.out.print("Enter keysize(128,192,256)): ");  
	 size = sc.nextInt();String dummy=sc.nextLine();
	}	
  System.out.print("Enter the mode of encryption(CBC/ECB/CFB/OFB): ");
  String mode = sc.nextLine();
  try{
	  ALGO a = new ALGO(mode,algo,size);
	  String enc = a.encrypt(text);
	  System.out.println("Encrypted(Cipher) Text: "+enc);
	  text = a.decrypt(enc);
	  System.out.println("Decrypted(DeCipher) Text: "+text);  
	 }catch(Exception e)
		{System.out.println("Exception: "+e);}
 }
}