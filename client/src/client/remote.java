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

public class remote extends reg_main{

	private String message;
	
	public remote(Socket sok, PublicKey pubkey) throws UnknownHostException, IOException, GeneralSecurityException{

		BufferedReader type = new BufferedReader(new InputStreamReader(System.in));
		OutputStream reg_type = sok.getOutputStream();
		BufferedWriter trans_login_type = new BufferedWriter(new OutputStreamWriter(reg_type));
		BufferedReader type1 = new BufferedReader(new InputStreamReader(sok.getInputStream()));
		OutputStream outMessage = sok.getOutputStream();
  		BufferedWriter SendMessage = new BufferedWriter(new OutputStreamWriter(outMessage));
  		BufferedReader stin = new BufferedReader(new InputStreamReader(System.in));
  		
  		String send="4";
  
		byte[] encryptData = encrypt(pubkey, send.getBytes());
		Encoder encoder= Base64.getEncoder();
		String encodestring = encoder.encodeToString(encryptData);
		SendMessage.write(encodestring + "\n");
  		SendMessage.flush();
		System.out.println(encodestring);
		while(true){
		
		System.out.print("message = ");
		
		message = type.readLine();
		byte[] encryptData1 = encrypt(pubkey, message.getBytes());
		System.out.println(bytesToHex(encryptData1));
		Encoder encoder1= Base64.getEncoder();
		String encodestring1 = encoder1.encodeToString(encryptData1);
		trans_login_type.write(encodestring1+ "\n");
		trans_login_type.flush();
		
		
		String Receive;
		while((Receive = type1.readLine()) != null)
		{
			if(Receive.equalsIgnoreCase("null"))
				break;
			System.out.println(Receive); 
		}

}
	}
	}
