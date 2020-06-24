//first run Sender
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Scanner;
import javax.crypto.spec.DHParameterSpec;
public class ElGammalReceiver extends Frame implements ActionListener
{DHParameterSpec spec ;
 BigInteger prime,primitiveroot,privateKey,publicKey;
 BigInteger c1,c2;
 int bitLength=512;
 Label head,l1,l2,l3,l4,l5;
 TextField t1,t2,t3,t4,t5;
 Button b1;
 Socket s;
 File f = new File("repository.txt");
 public ElGammalReceiver()
 {setBackground(Color.gray);
  setLayout(new BorderLayout());
  head=new Label("Receiver using ElGammal Encryption",Label.CENTER);
  Panel p=new Panel();p.add(head);
  Panel p1=new Panel();
  p1.setLayout(new GridLayout(8,2));
    
  l2= new Label("Private Key:",Label.LEFT);
  t2= new TextField(1024);p1.add(l2);p1.add(t2);
  
  l1= new Label("Cipher Text:",Label.LEFT);
  t1= new TextField(2058);p1.add(l1);p1.add(t1);
  
  l3= new Label("Decrypted Text:",Label.LEFT);  
  t3= new TextField(256); p1.add(l3);p1.add(t3);
  
  l4= new Label("C1:",Label.LEFT);  
  t4= new TextField(1024); p1.add(l4);p1.add(t4);
  
  l5= new Label("C2:",Label.LEFT);  
  t5= new TextField(1024); p1.add(l5);p1.add(t5);
  
  b1= new Button("Receive&Decrypt");p1.add(b1);
  b1.addActionListener(this);
  add(p,BorderLayout.NORTH);
  add(p1,BorderLayout.CENTER);
  addWindowListener(new WindowAdapter()
  {public void windowClosing(WindowEvent we)
	  {setVisible(false);dispose();
	   try{s.close();}catch(Exception e){System.out.println(e);}
	  }
  });
  setSize(600,400);
  setVisible(true);
  try{s =new Socket(InetAddress.getLocalHost(),8585);}catch(Exception e){System.out.println(e);}
  generateKeys();
 }
 public void actionPerformed(ActionEvent ae)
 {if(ae.getSource()==b1)
	 {decrypt();}
 }
 public void generateKeys()
 {try{
  SecureRandom rand = new SecureRandom();
  AlgorithmParameterGenerator gen =  AlgorithmParameterGenerator.getInstance("DH");
  gen.init(bitLength, rand);
  AlgorithmParameters params = gen.generateParameters();
  spec = params.getParameterSpec(DHParameterSpec.class);
  prime = spec.getP();
  primitiveroot = spec.getG();
  privateKey= BigInteger.probablePrime(128,rand);
  publicKey = primitiveroot.modPow(privateKey, prime);
  FileOutputStream fos = new FileOutputStream(f); 
  String s =prime+"\n"+primitiveroot+"\n"+publicKey+"\n";
   fos.write(s.getBytes());
   }catch(Exception e){System.out.println(e);}	 
   t2.setText(""+privateKey);	
 }
 public void decrypt()
 {receive();
  String s=t1.getText().trim();
  int index = s.indexOf(",");
  String cs1 = s.substring(1,index);
 String cs2 = s.substring(index+1,s.lastIndexOf("}"));
  c1 = new BigInteger(cs1);
  t4.setText(""+c1);
  BigInteger K = c1.modPow(privateKey,prime);
  K = K.modInverse(prime);//K^-1
  c2 = new BigInteger(cs2);
  t5.setText(""+c2);
  BigInteger M = c2.multiply(K);
  M = M.mod(prime);
  byte[] bytes = M.toByteArray();
      String plainText = new String(bytes, Charset.forName("UTF-8"));
  t3.setText(plainText);  
 }
 public void receive()
 {String msg=new String();
  try{int read;byte[] con=new byte[2058];  
      InputStream is =s.getInputStream();
	  is.read(con);msg=new String(con).trim();	  
	  t1.setText(msg);	  
	 }catch(Exception e){System.out.println(e);}
 }
 public static void main(String[] args)
 {ElGammalReceiver g = new ElGammalReceiver();}
}