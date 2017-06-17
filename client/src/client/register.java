package client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import java.util.Base64.Encoder;

public class register extends reg_main{
	
	private String name;
	private String ID;
	private String password;
	private String certificationpw;

	
	public register(Socket sok, PublicKey pubkey) throws IOException, GeneralSecurityException{
		
		
		
		BufferedReader type = new BufferedReader(new InputStreamReader(System.in));
		BufferedReader type1 = new BufferedReader(new InputStreamReader(sok.getInputStream()));
		OutputStream reg_type = sok.getOutputStream();
		BufferedWriter trans_reg_type = new BufferedWriter(new OutputStreamWriter(reg_type));
		


	    System.out.println("== 신규 가입 ==");
	    
	    //
	    System.out.print("ID = ");
	    
	    ID = type.readLine();
		byte[] encryptData = encrypt(pubkey, ID.getBytes());
		System.out.println(bytesToHex(encryptData));
		Encoder encoder= Base64.getEncoder();
		String encodestring = encoder.encodeToString(encryptData);
	    trans_reg_type.write(encodestring + "\n");
	    trans_reg_type.flush();
	    
	    
	    System.out.print("Password = ");
	    
	    password = type.readLine();
	    byte[] encryptData1 = encrypt(pubkey, password.getBytes());
	    System.out.println(bytesToHex(encryptData1));
	    Encoder encoder1= Base64.getEncoder();
	    String encodestring1 = encoder1.encodeToString(encryptData1);
	    trans_reg_type.write(encodestring1 + "\n");
	    trans_reg_type.flush();
	    
	    System.out.print("인증서 비밀번호 = ");

	    certificationpw = type.readLine();
	    byte[] encryptData2 = encrypt(pubkey, certificationpw.getBytes());
	    System.out.println(bytesToHex(encryptData2));
	    Encoder encoder2= Base64.getEncoder();
	    String encodestring2 = encoder2.encodeToString(encryptData2);
	    trans_reg_type.write(encodestring2 + "\n");
	    trans_reg_type.flush();
	    
	    
	    String ment = type1.readLine();
	    System.out.println(ment);
	    
	    
	}

    
}
