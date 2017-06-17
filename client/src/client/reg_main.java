package client;


import java.io.*;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.*;
import java.util.*;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;

import java.net.*;

public class reg_main {

   public static void main(String[] args) throws IOException, GeneralSecurityException {
	   BufferedReader num = new BufferedReader(new InputStreamReader(System.in));
	   Socket sok = new Socket("10.1.1.149",8013);
       InputStream in = null;
	   register register = null;   //객체등록?
	   login login = null;
	   certlogin certlogin = null;
	   
	   OutputStream reg_type = sok.getOutputStream();
	   BufferedWriter trans_reg_type = new BufferedWriter(new OutputStreamWriter(reg_type));
	   InputStream get_type = sok.getInputStream();
		BufferedReader login_type = new BufferedReader(new InputStreamReader(get_type));
		
		String publickey = login_type.readLine();

		Decoder decoder= Base64.getDecoder();
		byte[] decodeByte = decoder.decode(publickey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubkey = keyFactory.generatePublic(new X509EncodedKeySpec(decodeByte));
		System.out.println(" 공개키 : " + bytesToHex(decodeByte));
		
		BufferedReader stin = new BufferedReader(new InputStreamReader(System.in));
  		OutputStream outMessage = sok.getOutputStream();
  		BufferedWriter SendMessage = new BufferedWriter(new OutputStreamWriter(outMessage));
		


      while(true) {

    	  
    	  System.out.println();
          System.out.println("1.신규가입");
          System.out.println("2.로그인");
          System.out.println("3.인증서로그인");
          System.out.println("4.종료");
  		String send;
  		send = stin.readLine();
  		System.out.println(send);
  		
		byte[] encryptData = encrypt(pubkey, send.getBytes());
		Encoder encoder= Base64.getEncoder();
		String encodestring = encoder.encodeToString(encryptData);
		int ott = Integer.parseInt(send);
  		if (ott < 5){
  		SendMessage.write(encodestring + "\n");
  		SendMessage.flush();
  		System.out.println(bytesToHex(encryptData));
  		}
  		
      


    	 
         

         
      
         
         if(send.equalsIgnoreCase("1")){
       	 register = new register(sok, pubkey);  // 이 파일 (register)실행
        	 
         }
       
         if(send.equalsIgnoreCase("2")){
       	 login = new login(sok, pubkey);  // 이 파일 (login)실행
        	 
         }
         if(send.equalsIgnoreCase("3")){
        	 certlogin = new certlogin(sok, pubkey);
         }
          if(send.equalsIgnoreCase("4")){
         	 System.out.println("종료되었습니다.");      	 
        	 System.exit(0);
      	 
         }
      

         
//         else {
//        	 int send1 = Integer.parseInt(send);
//       		if (send1 > 3){
//             System.out.println("잘못 입력 하셨습니다.");
//       		}
//         }
      }
   }
   public static byte[] encrypt(PublicKey pubkey, byte[] plainData)
			throws GeneralSecurityException {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, pubkey);
				byte[] encryptData = cipher.doFinal(plainData);
				return encryptData;
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
   }


   

