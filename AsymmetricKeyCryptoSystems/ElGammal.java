import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Scanner;
import javax.crypto.spec.DHParameterSpec;

public class ElGammal{
    DHParameterSpec spec ;
    BigInteger prime,primitiveroot;
    BigInteger privateKey,publicKey;
    BigInteger c1,c2;
    int bitLength=512;    
    public ElGammal()throws Exception
    {SecureRandom rand = new SecureRandom();
     getDHParameterSpec(bitLength,rand);
     prime = spec.getP();
     primitiveroot = spec.getG();
      //check for primitive root
       String str ="1";
       BigInteger one=new BigInteger(str);
       BigInteger check = primitiveroot.modPow(prime.subtract(one), prime);
       System.out.println("Prime Modulus:"+prime+"\nPrimitive Root:"+primitiveroot);
      // System.out.println("primitive root:"+primitiveroot+"\ncheck:"+check);
     privateKey= BigInteger.probablePrime(128,rand);
     publicKey = primitiveroot.modPow(privateKey, prime);       
     System.out.println("privateKey:"+privateKey+"\nPublic Key:"+publicKey);
        
    }
    
    private BigInteger formatString(String mssg) {
     byte[] bytes = mssg.getBytes(Charset.forName("UTF-8"));
     BigInteger msg = new BigInteger(bytes);
     //System.out.println("Integer form of mssg:"+msg);
     return msg;   
    }
     public byte[] encrypt(String mssg)
     {SecureRandom rand = new SecureRandom();
      int k = rand.nextInt(bitLength);
      BigInteger M  = formatString(mssg);
      BigInteger K = publicKey.modPow(BigInteger.valueOf(k), prime);
     // System.out.println("K value:"+K);
      c2 = K.multiply(M);
      c1 = primitiveroot.modPow(BigInteger.valueOf(k), prime);
      c2 = c2.mod(prime);
      System.out.println("Cipher Sent:"+c2);
      return c2.toByteArray();
     }
     public void decrypt(byte[] cipher)
     {BigInteger K = c1.modPow(privateKey,prime);
      //System.out.println("K value:"+K);
      K = K.modInverse(prime);//K^-1
      BigInteger M = new BigInteger(cipher);
      //System.out.println("Cipher Received:"+M);
      M = M.multiply(K);
      M = M.mod(prime);
      byte[] bytes = M.toByteArray();
      String plainText = new String(bytes, Charset.forName("UTF-8"));
      System.out.println("PlainText obtained from decryption:\n\t"+plainText);
     }
    public void  getDHParameterSpec(int keyLength,SecureRandom random)
        throws NoSuchAlgorithmException, InvalidParameterSpecException 
    {AlgorithmParameterGenerator gen =  AlgorithmParameterGenerator.getInstance("DH");
     gen.init(keyLength, random);
     AlgorithmParameters params = gen.generateParameters();
    spec = params.getParameterSpec(DHParameterSpec.class);
    }
 
    public static void main(String[] args)throws Exception
    {ElGammal p =new ElGammal();
     System.out.print("Enter the message: "); 
     Scanner sc = new Scanner(System.in);
     String mssg = sc.nextLine();
     byte[] cipher= p.encrypt(mssg);
     p.decrypt(cipher);
    }

    
}