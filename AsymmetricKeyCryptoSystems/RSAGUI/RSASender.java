/*
1.first run sender then receiver
2.give message and get public key
3.press encrypt
4.send sha and receive digest
5.send cipher and receive cipher
*/
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.io.*;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.KeyFactory;
import javax.crypto.Cipher;
import java.security.spec.X509EncodedKeySpec;
public class RSASender extends Frame implements ActionListener
{
 Label head,l1,l2,l3,l4,l5;
 TextField t1,t2,t3,t4,t5,t6;
 Button b1,b2,b3,b4;
 ServerSocket ss;
 Socket s;
 PublicKey publicKey;
 MessageDigest sha1;
 byte[] cipherText,digest;
 public RSASender()
 {setBackground(Color.gray);
  setLayout(new BorderLayout());
  head=new Label("Sender Using RSA with SHA",Label.CENTER);
  Panel p=new Panel();p.add(head);
  Panel p1=new Panel();
  p1.setLayout(new GridLayout(8,2));
  l1= new Label("Enter Message:",Label.LEFT);
  t1= new TextField(256);p1.add(l1);p1.add(t1);
  
  b1= new Button("Get Public Key");p1.add(b1);
  b2= new Button("Encrypt");p1.add(b2);
  
  l2= new Label("Public Key:",Label.LEFT);
  t2= new TextField(2058);p1.add(l2);p1.add(t2);
  
  l3= new Label("SHA Value:",Label.LEFT);  
  t3= new TextField(1024); p1.add(l3);p1.add(t3);
  
  l4= new Label("CipherText:",Label.LEFT);  
  t4= new TextField(2058); p1.add(l4);p1.add(t4);
  
  b3= new Button("Send cipher");  p1.add(b3);
  b4 = new Button("Send SHA"); p1.add(b4);
  t6= new TextField(2058); p1.add(t6);
  
  b1.addActionListener(this);
  b2.addActionListener(this);
  b3.addActionListener(this);
  b4.addActionListener(this);
  add(p,BorderLayout.NORTH);
  add(p1,BorderLayout.CENTER);
  addWindowListener(new WindowAdapter()
  {public void windowClosing(WindowEvent we)
	  {setVisible(false);dispose();
	   try{ss.close();}catch(Exception e){System.out.println(e);}
	  }
  });
  setSize(600,400);
  setVisible(true);
  try{ss = new ServerSocket(8585);
 s =ss.accept();}catch(Exception e){System.out.println(e);}
 
 }
 public void actionPerformed(ActionEvent ae)
 {if(ae.getSource()==b1)
	 {getdata();}
  if(ae.getSource()==b2)
     {encrypt();}
  if(ae.getSource()==b3)
     {send();}
  if(ae.getSource()==b4)
	 {sendSha();} 
 }
 public void getdata()
 {try{sha1 = MessageDigest.getInstance("SHA1"); 
  RandomAccessFile f = new RandomAccessFile("repository.txt", "r");
  byte[] publicKeyBytes = new byte[(int)f.length()];
  f.readFully(publicKeyBytes);  
  KeyFactory kf = KeyFactory.getInstance("RSA");
  publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
  System.out.println(publicKey+"\n");
 }catch(Exception e){System.out.println(e);}
  byte[] pu = publicKey.getEncoded();
    t2.setText(Base64.getEncoder().encodeToString(pu));
  //t2.setText(""+publicKey);   
 }
 public void encrypt()
 {try{
  String mssg=t1.getText().trim();
  Cipher cipher = Cipher.getInstance("RSA");
  cipher.init(Cipher.ENCRYPT_MODE,publicKey);
  cipherText = cipher.doFinal(mssg.getBytes());
  //t4.setText(""+cipherText); 
  t4.setText(Base64.getEncoder().encodeToString(cipherText));
  digest = sha1.digest(mssg.getBytes());
  //t3.setText(""+digest);
  t3.setText(Base64.getEncoder().encodeToString(digest));
  }catch(Exception e){System.out.println(e);}  
  
 }
 public void sendSha()
 {try{OutputStream os =s.getOutputStream();
	  os.write(digest);
	  os.flush();
	  System.out.println("Digest length:"+digest.length+"Digest:"+digest);
	  t6.setText("Digest transmitted successfully...");
	  }catch(Exception e){System.out.println(e);}	 
 }
 public void send()
 {try{OutputStream os =s.getOutputStream();
	  os.write(cipherText);
	  os.flush();
	  System.out.println("Cipher length:"+cipherText.length+"cipher:"+cipherText);
	  t6.setText("cipher Text transmitted successfully...");
	  }catch(Exception e){System.out.println(e);}
 }
 public static void main(String[] args)
 {RSASender g = new RSASender();}
}