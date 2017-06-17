package server;

import java.io.*;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.net.*;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


class Server{
	
	public void RSAEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024); 
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();     
        Charset charset = Charset.forName("UTF-8");
        
        System.out.println("=== RSA Ű���� ===");
        byte[] pubk = publicKey.getEncoded();
        byte[] prik = privateKey.getEncoded(); 
        System.out.println(" ����Ű ���� : "+publicKey.getFormat());
        System.out.println(" ����Ű ���� : "+privateKey.getFormat());
        System.out.println(" ����Ű : "+bytesToHex(pubk));
        System.out.println(" ����Ű ���� : "+pubk.length+ " byte" );	
        System.out.println(" ����Ű : "+bytesToHex(prik));
        System.out.println(" ����Ű ���� : "+prik.length+ " byte" );
        System.out.println();
        
        System.out.println("=== RSA ��ȣȭ ===");
        Scanner s = new Scanner(System.in);
        System.out.print("��ȣȭ�� ���� �Է����ּ��� >>> ");
        String text = s.next();  
        byte[] t0 = text.getBytes(charset);
        System.out.println(" Plaintext : "+text);
        System.out.println(" Plaintext : "+bytesToHex(t0));
        System.out.println(" Plaintext Length : "+t0.length+ " byte" );	

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] b0 = cipher.doFinal(t0);
        System.out.println(" Ciphertext : "+bytesToHex(b0));
        System.out.println(" Ciphertext Length : "+b0.length+ " byte" );	
        System.out.println();
        
        System.out.println("=== RSA ��ȣȭ ===");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] b1 = cipher.doFinal(b0);
        System.out.println(" Recovered Plaintext : "+ bytesToHex(b1)); 
        System.out.println(" Recovered Plaintext Length : "+b1.length+ " byte" );	
        System.out.println(" Recovered Plaintext : "+ new String(b1, charset));
        
	    		        
	}
   
	public static String bytesToHex(byte[] bytes) {
	    StringBuilder sb = new StringBuilder(bytes.length * 2);
	 
	    @SuppressWarnings("resource")
		Formatter formatter = new Formatter(sb);
	    for (byte b : bytes) {
	        formatter.format("%02x", b);
	    }
	 
	    return sb.toString();
	}
	private static String name;
	private static String ID;
	private static String password;
	
	private static String lohin_ID;
	private static String lohin_password;
	
	private static String login_succ = "�α��� ����";
	private static String login_fail = "�α��� ����";
	
	public static void main(String[] args) throws IOException{
	
		ServerSocket serverSocket = null;
		serverSocket = new ServerSocket(8010);
		
		System.out.println("Server strating");
		
		while(true){	
			Socket socket = null;
		
			socket = serverSocket.accept();
			
			OutputStream check = socket.getOutputStream();
			BufferedWriter check_login = new BufferedWriter(new OutputStreamWriter(check));
			
			InputStream get_type = socket.getInputStream();
			BufferedReader save_type = new BufferedReader(new InputStreamReader(get_type));
		
			System.out.println(socket.getInetAddress()+ " Connect");
			
			name = save_type.readLine();
			
			if(name.equals("login")){
				
				lohin_ID = save_type.readLine();
				
				lohin_password = save_type.readLine();
				
				if(ID == null || password == null){
					System.out.println("��ϵ� ����ڰ� �������� �ʽ��ϴ�.");
				}
				
				else if(lohin_ID.equals(ID) && lohin_password.equals(password)){
					
					check_login.write(login_succ + "\n"); // Ŭ���̾�Ʈ�� ���� �ѱ�
					check_login.flush();
					
				}
				else{
					check_login.write(login_fail + "\n"); // Ŭ���̾�Ʈ�� ���� �ѱ�
					check_login.flush();
				}
			}
			
			
			else{
				
				ID = save_type.readLine();
				
				password = save_type.readLine();
			}
	
			socket.close();
		}
	}
}
