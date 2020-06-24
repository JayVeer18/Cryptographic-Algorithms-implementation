import java.net.*;
import java.util.*;
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
import javax.crypto.spec.SecretKeySpec;

public class Receiver
{DatagramSocket ds=new DatagramSocket(1234);
 FileOutputStream fout= new FileOutputStream("output.txt");
 DatagramPacket dp;
 SecretKeySpec key;
 Cipher c;
 IvParameterSpec iv;
 String mode;
 int ivsize,msgsize;
 String msgd;
 MessageDigest md;
 
 public Receiver(String algo,String mode)throws Exception
 {msgsize =256;
  md = MessageDigest.getInstance("MD5");
  String keystring = getKey(algo).trim();
  ivsize=algo.equals("AES")?16:8;
  iv = new IvParameterSpec(keystring.getBytes(),0,ivsize);
  System.out.println("Message Digest: "+msgd);
  String dig = new BigInteger(1,md.digest(keystring.getBytes())).toString(16);
   if(!msgd.equals(dig))
   {System.out.println("Key has been corrupted!....");return;}
  key = new SecretKeySpec(Base64.getDecoder().decode(keystring),algo); 
  c = Cipher.getInstance(algo+"/"+mode+"/PKCS5Padding");
 }
 
 private String getKey(String algo)throws Exception
 {byte[] keybytes = receivedata();
  System.out.println("~~~~~~~~~~~~~~~~~~Received Data~~~~~~~~~~~~~~~~~~");
  String keystring = new String(keybytes).trim();
  msgd = getDigest(keystring.substring(keystring.indexOf(",")+1));
  keystring = keystring.substring(0,keystring.indexOf(","));
  System.out.println("Key:"+keystring);
  return keystring;  
 }
 private String getDigest(String mdigest)throws Exception
 {int index = mdigest.indexOf(".");
  String s = mdigest.substring(0,index);
  mdigest = mdigest.substring(index+1);
  msgsize = Integer.parseInt(s);
  return mdigest; 
 }
 private byte[] receivedata()throws Exception
 {byte data[]=new byte[msgsize];
  dp=new DatagramPacket(data,0,data.length);
  ds.receive(dp);
  return data;
 }
 public void decrypt(String mode)throws Exception
 {if(mode.equals("ECB"))
   {c.init(Cipher.DECRYPT_MODE,key);}
   else
   {c.init(Cipher.DECRYPT_MODE,key,iv);}
  byte[] btext = receivedata();
  byte[] decbyte = c.doFinal(btext);
   fout.write(decbyte);
  System.out.println("~~~~~~~~~~~~Data stored successfully~~~~~~~~~~~~~~");
  ds.close();	 
 } 
public static void main(String arg[])
 {Scanner sc=new Scanner(System.in);
  System.out.print("Enter algorithm(DESede or TripleDES,DES,AES): ");
  String algo = sc.nextLine();
  System.out.print("Enter the mode of encryption(CBC/ECB/CFB/OFB): ");
  String mode = sc.nextLine();	
  System.out.println("!!!!!!waiting for data!!!!!!!!");
   try
	 {Receiver r = new Receiver(algo,mode);
	  r.decrypt(mode);
	 }catch(Exception e)
		{System.out.println("Exception: "+e);}	
 }
}