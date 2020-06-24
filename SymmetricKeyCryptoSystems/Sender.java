import java.util.*;
import java.net.*;
import java.io.*;
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
import javax.crypto.spec.SecretKeySpec;
public class Sender
{
 DatagramSocket ds= new DatagramSocket();
 DatagramPacket dp;
 SecretKey SECkey;
 SecretKeySpec key;
 SecureRandom rand,saltrand;
 KeyGenerator gen;
 Cipher c;
 IvParameterSpec iv;
 String mode;
 int ivsize;
 String md5;
 byte[] salt = new byte[16];
 MessageDigest md;
 String keyString;
 
 public Sender(String algo,String mode,int size)throws Exception
 {gen = KeyGenerator.getInstance(algo);
  rand = new SecureRandom();
  gen.init(size,rand);
  SECkey = gen.generateKey();
  byte[] enCodeFormat = SECkey.getEncoded();
  key = new SecretKeySpec(enCodeFormat, algo);
  keyString = Base64.getEncoder().encodeToString(key.getEncoded());
	md = MessageDigest.getInstance("MD5"); 
    ivsize=algo.equals("AES")?16:8; 
	iv = new IvParameterSpec(keyString.getBytes(),0,ivsize);
  c = Cipher.getInstance(algo+"/"+mode+"/PKCS5Padding");
  if(mode.equals("ECB"))
   {c.init(Cipher.ENCRYPT_MODE,key);}
   else
   {c.init(Cipher.ENCRYPT_MODE,key,iv);}
 } 
 public void sendata(byte[] mssg)throws Exception
 {dp = new DatagramPacket(mssg,0,mssg.length,InetAddress.getByName("LocalHost"),1234);
  ds.send(dp); 
 }
 public String encrypt(String text)throws Exception
 { byte[] btext = keyString.getBytes();
   System.out.println("~~~~~~~~~~~~~~~~~~Transmitted Data~~~~~~~~~~~~~~~~~~");
   System.out.println("Key:"+keyString);   
   byte[] encbyte = c.doFinal(text.getBytes());
   md5 = new BigInteger(1,md.digest(btext)).toString(16);
   System.out.println("Message Digest:"+md5);	
   md5=encbyte.length+"."+md5;
   keyString = keyString+","+md5;
   btext = keyString.getBytes();
   sendata(btext);
   sendata(encbyte); 
  System.out.println("~~~~~~~~~~~~~~~~cipher text transmission successful~~~~~~~~~~~~~~~");
  ds.close();
 return Base64.getEncoder().encodeToString(encbyte);  
 } 
 public static void main(String args[ ]) throws Exception
 {int c;
  StringBuilder ms=new StringBuilder();
	FileInputStream fin = new FileInputStream("file.txt");
	while((c=fin.read())!=-1)
		{ms.append((char)c+"");}
 	Scanner sc=new Scanner(System.in);
  System.out.print("Enter algorithm(DESede or TripleDES,DES,AES): ");
  String algo = sc.nextLine();
  int size=56;
  if(algo.equals("DESede")||algo.equals("TripleDES"))
	{System.out.print("Enter keysize(112(for two different keys),168(for three different keys)): ");  
	 size = sc.nextInt();String dummy=sc.nextLine();
	}
  if(algo.equals("AES"))
	{System.out.print("Enter keysize(128,192,256)): ");  
	 size = sc.nextInt();String dummy=sc.nextLine();
	}	
  System.out.print("Enter the mode of encryption(CBC/ECB/CFB/OFB): ");
  String mode = sc.nextLine();	
  	try
	 { Sender s = new Sender(algo,mode,size);	
	  String enc = s.encrypt(ms.toString());
	 }catch(Exception e)
		{System.out.println("Exception: "+e);}	
  }	
}