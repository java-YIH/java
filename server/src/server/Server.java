package server;

import java.io.*;
import java.util.*;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.net.*;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


class Server{
	
	public static class Key
	{
		byte[] publicKey;
		byte[] privateKey;
	}
	public static void MakeRSAKey(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024); 
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();     
        Charset charset = Charset.forName("UTF-8");
        
        System.out.println("=== RSA Ű���� ===");
        key.publicKey = publicKey.getEncoded();
        key.privateKey = privateKey.getEncoded(); 
        
        /*
        System.out.println(" ����Ű ���� : "+publicKey.getFormat());
        System.out.println(" ����Ű ���� : "+privateKey.getFormat());
        System.out.println(" ����Ű : "+bytesToHex(key.publicKey));
        System.out.println(" ����Ű ���� : "+key.publicKey.length+ " byte" );	
        System.out.println(" ����Ű : "+bytesToHex(key.privateKey));
        System.out.println(" ����Ű ���� : "+key.privateKey.length+ " byte" );
        System.out.println();
       */
        /*
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
     */
        /*
        System.out.println("=== RSA ��ȣȭ ===");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] b1 = cipher.doFinal(b0);
        System.out.println(" Recovered Plaintext : "+ bytesToHex(b1)); 
        System.out.println(" Recovered Plaintext Length : "+b1.length+ " byte" );	
        System.out.println(" Recovered Plaintext : "+ new String(b1, charset));
        */
	    		        
	}
   
	public static byte[] decrypt(PrivateKey privateKey, byte[] encryptData) throws GeneralSecurityException {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] plainData = cipher.doFinal(encryptData);
			return plainData;
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
	private static String ID;
	private static String password;
	
	private static String lohin_ID;
	private static String lohin_password;
	
	private static String login_succ = "�α��� ����";
	private static String login_fail = "�α��� ����";
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
	
		
		//Ű���� ������ �ִ� class ����
		Key key = new Key();
		MakeRSAKey(key); //Ű ����
		
		System.out.println(" ����Ű : "+bytesToHex(key.publicKey));
		
		//��Ʈ ����
		ServerSocket serverSocket = new ServerSocket(8013);

		
		System.out.println("Listening...");
		Socket socket = serverSocket.accept();
		System.out.println("Client("+socket.getInetAddress()+") Connect!");
		
		//��� ��Ʈ�� ����
		OutputStream OutputClient = socket.getOutputStream();
		BufferedWriter WriteToClient = new BufferedWriter(new OutputStreamWriter(OutputClient));
		
		//�Է� ��Ʈ�� ����
		InputStream InputClient = socket.getInputStream();
		BufferedReader ReadFromClient = new BufferedReader(new InputStreamReader(InputClient));
	
	
		//������ ���� ����Ű�� Base64Ÿ������ ���ڵ�
		Encoder encoder = Base64.getEncoder();
		String publicKey = encoder.encodeToString(key.publicKey);
			
		//����Ű ����
	//	WriteToClient.write(publicKey);
	//	WriteToClient.flush();
		

		String recvMsg=null;
		//��� �κ� 
		while(true){	
			
			
			//Ű �Է� ����
			recvMsg=ReadFromClient.readLine();
			System.out.println("Recv Msg : " + recvMsg);
			

			if(recvMsg.equals("exit"))
			{
				socket.close();
			}
			/*
			if(recvMsg.equals(1)){
				
				lohin_ID = ReadFromClient.readLine();
				
				lohin_password = ReadFromClient.readLine();
				
				if(ID == null || password == null){
					System.out.println("��ϵ� ����ڰ� �������� �ʽ��ϴ�.");
				}
				
				else if(lohin_ID.equals(ID) && lohin_password.equals(password)){
					
					WriteToClient.write(login_succ + "\n"); // Ŭ���̾�Ʈ�� ���� �ѱ�
					WriteToClient.flush();
					
				}
				else{
					WriteToClient.write(login_fail + "\n"); // Ŭ���̾�Ʈ�� ���� �ѱ�
					WriteToClient.flush();
				}
			}else{
				
				ID = ReadFromClient.readLine();
				
				password = ReadFromClient.readLine();
			}
			*/

		}

	}
}
