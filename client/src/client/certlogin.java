package client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Base64.Encoder;

public class certlogin extends reg_main{
	
	
	private String ID;
	private String certificationpw;
	
	public certlogin(Socket sok, PublicKey pubkey) throws UnknownHostException, IOException, GeneralSecurityException{
		BufferedReader type = new BufferedReader(new InputStreamReader(System.in));
		OutputStream reg_type = sok.getOutputStream();
		BufferedWriter trans_login_type = new BufferedWriter(new OutputStreamWriter(reg_type));
		BufferedReader type1 = new BufferedReader(new InputStreamReader(sok.getInputStream()));
		
        System.out.print("ID = ");
		
		ID = type.readLine();
		byte[] encryptData = encrypt(pubkey, ID.getBytes());
		System.out.println(bytesToHex(encryptData));
		Encoder encoder= Base64.getEncoder();
		String encodestring = encoder.encodeToString(encryptData);
		trans_login_type.write(encodestring+ "\n");
		trans_login_type.flush();
		
		System.out.println("인증서 비밀번호 = ");
		
		certificationpw = type.readLine();
	    byte[] encryptData2 = encrypt(pubkey, certificationpw.getBytes());
	    System.out.println(bytesToHex(encryptData2));
	    Encoder encoder2= Base64.getEncoder();
	    String encodestring2 = encoder2.encodeToString(encryptData2);
	    trans_login_type.write(encodestring2 + "\n");
	    trans_login_type.flush();

	    String ment = type1.readLine();
	    System.out.println(ment);
	}

}
