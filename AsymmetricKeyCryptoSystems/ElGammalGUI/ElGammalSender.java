//first run the Sender
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
public class ElGammalSender extends Frame implements ActionListener
{
 Label head,l1,l2,l3,l4,l5;
 TextField t1,t2,t3,t4,t5,t6;
 Button b1,b2,b3;
 ServerSocket ss;
 Socket s;
 BigInteger prime,primitiveroot,publicKey;
 BigInteger c1,c2,K;
 File f = new File("repository.txt");
 int bitLength=512;  
 public ElGammalSender()
 {setBackground(Color.gray);
  setLayout(new BorderLayout());
  head=new Label("Sender using ElGammal Encryption",Label.CENTER);
  Panel p=new Panel();p.add(head);
  Panel p1=new Panel();
  p1.setLayout(new GridLayout(8,2));
  l1= new Label("Enter Message:",Label.LEFT);
  t1= new TextField(256);p1.add(l1);p1.add(t1);
  
  b1= new Button("Get Public Key");p1.add(b1);
  b2= new Button("Encrypt");p1.add(b2);
  
  l2= new Label("Public Key:",Label.LEFT);
  t2= new TextField(256);p1.add(l2);p1.add(t2);
  
  l3= new Label("C1:",Label.LEFT);  
  t3= new TextField(1024); p1.add(l3);p1.add(t3);
  
  l4= new Label("C2:",Label.LEFT);  
  t4= new TextField(1024); p1.add(l4);p1.add(t4);
  
  
  l5= new Label("Cipher Text:",Label.LEFT);
  t5= new TextField(2058); p1.add(l5);p1.add(t5);
  
  b3= new Button("Send");  p1.add(b3);
  t6= new TextField(2058); p1.add(t6);
  
  b1.addActionListener(this);
  b2.addActionListener(this);
  b3.addActionListener(this);
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
 }
 public void getdata()
 {
  try{ 
  BufferedReader fin = new BufferedReader(new FileReader(f));
  prime = new BigInteger(fin.readLine().trim());
  primitiveroot = new BigInteger(fin.readLine().trim());
  publicKey = new BigInteger(fin.readLine().trim());
  }catch(Exception e){System.out.println(e);}
    t2.setText(""+publicKey);  
  SecureRandom rand = new SecureRandom();
  int k = rand.nextInt(bitLength);
  c1 = primitiveroot.modPow(BigInteger.valueOf(k), prime);
  K = publicKey.modPow(BigInteger.valueOf(k), prime);
 }
 public void encrypt()
 {String mssg=t1.getText().trim();
  byte[] bytes = mssg.getBytes(Charset.forName("UTF-8"));
  BigInteger M = new BigInteger(bytes);
  c2 = K.multiply(M);	
  c2 = c2.mod(prime);  
  t3.setText(""+c1); t4.setText(""+c2);
  t5.setText("{"+c1+","+c2+"}");  
 }
 public void send()
 {String msg=t5.getText().trim();
  try{
	  OutputStream os =s.getOutputStream();
	  os.write(msg.getBytes());
	  os.flush();
	  t6.setText("cipher Text transmitted successfully...");
	  }catch(Exception e){System.out.println(e);}
 }
 public static void main(String[] args)
 {ElGammalSender g = new ElGammalSender();}
}