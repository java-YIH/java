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
        
        System.out.println("=== RSA 키생성 ===");
        key.publicKey = publicKey.getEncoded();
        key.privateKey = privateKey.getEncoded(); 
        
        /*
        System.out.println(" 공개키 포맷 : "+publicKey.getFormat());
        System.out.println(" 개인키 포맷 : "+privateKey.getFormat());
        System.out.println(" 공개키 : "+bytesToHex(key.publicKey));
        System.out.println(" 공개키 길이 : "+key.publicKey.length+ " byte" );	
        System.out.println(" 개인키 : "+bytesToHex(key.privateKey));
        System.out.println(" 개인키 길이 : "+key.privateKey.length+ " byte" );
        System.out.println();
       */
        /*
        System.out.println("=== RSA 암호화 ===");
        Scanner s = new Scanner(System.in);
        System.out.print("암호화할 평문을 입력해주세요 >>> ");
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
        System.out.println("=== RSA 복호화 ===");
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
	
	private static String login_succ = "로그인 성공";
	private static String login_fail = "로그인 실패";
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
	
		
		//키쌍을 가지고 있는 class 생성
		Key key = new Key();
		MakeRSAKey(key); //키 생성
		
		System.out.println(" 공개키 : "+bytesToHex(key.publicKey));
		
		//포트 개방
		ServerSocket serverSocket = new ServerSocket(8013);

		
		System.out.println("Listening...");
		Socket socket = serverSocket.accept();
		System.out.println("Client("+socket.getInetAddress()+") Connect!");
		
		//출력 스트림 생성
		OutputStream OutputClient = socket.getOutputStream();
		BufferedWriter WriteToClient = new BufferedWriter(new OutputStreamWriter(OutputClient));
		
		//입력 스트림 생성
		InputStream InputClient = socket.getInputStream();
		BufferedReader ReadFromClient = new BufferedReader(new InputStreamReader(InputClient));
	
	
		//전송을 위해 공개키를 Base64타입으로 인코딩
		Encoder encoder = Base64.getEncoder();
		String publicKey = encoder.encodeToString(key.publicKey);
			
		//공개키 전송
	//	WriteToClient.write(publicKey);
	//	WriteToClient.flush();
		

		String recvMsg=null;
		//통신 부분 
		while(true){	
			
			
			//키 입력 받음
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
					System.out.println("등록된 사용자가 존재하지 않습니다.");
				}
				
				else if(lohin_ID.equals(ID) && lohin_password.equals(password)){
					
					WriteToClient.write(login_succ + "\n"); // 클라이언트로 성공 넘김
					WriteToClient.flush();
					
				}
				else{
					WriteToClient.write(login_fail + "\n"); // 클라이언트로 실패 넘김
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
