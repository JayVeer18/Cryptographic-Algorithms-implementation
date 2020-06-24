import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.io.*;
import java.util.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.Cipher;
public class RSAReceiver extends Frame implements ActionListener
{KeyPairGenerator kpg;
 KeyPair kp;
 MessageDigest sha1;
 PublicKey publicKey;
 PrivateKey privateKey; 
 Label head,l1,l2,l3,l4,l5;
 TextField t1,t2,t3,t4,t5,t6;
 Button b1,b2;
 Socket s;
 File f = new File("repository.txt");
 byte[] digest;
 public RSAReceiver()
 {setBackground(Color.gray);
  setLayout(new BorderLayout());
  head=new Label("Receiver Using RSA with SHA",Label.CENTER);
  Panel p=new Panel();p.add(head);
  Panel p1=new Panel();
  p1.setLayout(new GridLayout(8,2));
    
  l2= new Label("Private Key:",Label.LEFT);
  t2= new TextField(1024);p1.add(l2);p1.add(t2);
  
  l1= new Label("Cipher Text:",Label.LEFT);
  t1= new TextField(2058);p1.add(l1);p1.add(t1);
  
  l3= new Label("Decrypted Text:",Label.LEFT);  
  t3= new TextField(256); p1.add(l3);p1.add(t3);
  l4= new Label("SHA value:",Label.LEFT);  
  t4= new TextField(1024); p1.add(l4);p1.add(t4);
  
  l5= new Label("Integrity Check:",Label.LEFT);  
  t5= new TextField(1024); p1.add(l5);p1.add(t5);
  
  b1= new Button("Receive data&Decrypt");p1.add(b1);
  b1.addActionListener(this);
  b2= new Button("Receive Digest");p1.add(b2);
  b2.addActionListener(this);
  t6= new TextField(1024);p1.add(t6);
  
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
  if(ae.getSource()==b2)
	 {getDigest();}
 }
 public void generateKeys()
 {try{
  kpg = KeyPairGenerator.getInstance("RSA");
  kpg.initialize(512);
  kp = kpg.generateKeyPair();	
  sha1 = MessageDigest.getInstance("SHA1");
  privateKey = kp.getPrivate();  
  publicKey = kp.getPublic();
  byte[] pkey = publicKey.getEncoded();
  System.out.println(publicKey+"\n");
  FileOutputStream fos = new FileOutputStream(f); 
   fos.write(pkey);
   }catch(Exception e){System.out.println(e);}	 
   //t2.setText(""+privateKey);	
  t2.setText(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
 }
 public void decrypt()
 {try{byte[] a;
  a=receive();t6.setText("Cipher received successfully...");
  Cipher cipher = Cipher.getInstance("RSA");
  //t1.setText(""+a);
  t1.setText(Base64.getEncoder().encodeToString(a));
  cipher.init(Cipher.DECRYPT_MODE,privateKey);
  byte[] cipherText = cipher.doFinal(a);
  t3.setText(new String(cipherText)); 
  System.out.println("Decrypt:"+cipherText);
  byte[] dig = sha1.digest(cipherText);
  String dig0=new String(dig);
  String dig1=new String(digest);
  //t4.setText(""+dig);
  t4.setText(Base64.getEncoder().encodeToString(dig));
  if(dig0.equals(dig1)){t5.setText("Message recieved is not tampered...");}
  else{t5.setText("Message recieved is tampered...");}
  }catch(Exception e){System.out.println(e);}	 
 }
 public void getDigest()
 {byte[] con=new byte[20];
  try{int read;  
      DataInputStream dis = new DataInputStream(s.getInputStream());
	  dis.read(con);
	 }catch(Exception e){System.out.println(e);}
	 System.out.println("Digest:"+con);
  digest = con;	
 t6.setText("Digest received successfully...");  
 }
 public byte[] receive()
 {byte[] con=new byte[64];
  try{int read;  
      DataInputStream dis = new DataInputStream(s.getInputStream());
	  dis.read(con);
	 }catch(Exception e){System.out.println(e);}
	 System.out.println("Cipher length:"+con.length+"cipher:"+con);
  return con;
 }
 public static void main(String[] args)
 {RSAReceiver g = new RSAReceiver();}
}