package client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import java.util.Base64.Encoder;


public class login extends reg_main{
	
	private String ID;
	private String password;
	private String check = "login";

	

	
	public login(Socket sok, PublicKey pubkey) throws UnknownHostException, IOException, GeneralSecurityException{
		
		BufferedReader type = new BufferedReader(new InputStreamReader(System.in));
		BufferedReader type1 = new BufferedReader(new InputStreamReader(sok.getInputStream()));

		
		OutputStream reg_type = sok.getOutputStream();
		BufferedWriter trans_login_type = new BufferedWriter(new OutputStreamWriter(reg_type));
		
		InputStream get_type = sok.getInputStream();
		BufferedReader login_type = new BufferedReader(new InputStreamReader(get_type));
				
		System.out.print("ID = ");
		
		ID = type.readLine();
		byte[] encryptData = encrypt(pubkey, ID.getBytes());
		System.out.println(bytesToHex(encryptData));
		Encoder encoder= Base64.getEncoder();
		String encodestring = encoder.encodeToString(encryptData);
		trans_login_type.write(encodestring+ "\n");
		trans_login_type.flush();
	    
		System.out.print("PW = ");
		
		password = type.readLine();
		byte[] encryptData1 = encrypt(pubkey, password.getBytes());
		System.out.println(bytesToHex(encryptData1));
		Encoder encoder1= Base64.getEncoder();
		String encodestring1 = encoder1.encodeToString(encryptData1);
		System.out.println(encodestring1);
		trans_login_type.write(encodestring1+ "\n");
		trans_login_type.flush();
		
		String ment = type1.readLine();
	    System.out.println(ment);
		
		
	    
	}
		
}
