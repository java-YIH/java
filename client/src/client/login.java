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
import java.util.Scanner;


public class login extends reg_main{
	
	private String ID;
	private String password;
	private String check = "login";
	private String login_succ;
	

	
	public login(Socket sok) throws UnknownHostException, IOException{
		
		BufferedReader type = new BufferedReader(new InputStreamReader(System.in));
		

		
		OutputStream reg_type = sok.getOutputStream();
		BufferedWriter trans_login_type = new BufferedWriter(new OutputStreamWriter(reg_type));
		
		InputStream get_type = sok.getInputStream();
		BufferedReader login_type = new BufferedReader(new InputStreamReader(get_type));
		
		trans_login_type.write(check+ "\n"); //로그인인지 아닌지 체크
		trans_login_type.flush();
		
		System.out.print("ID = ");
		
		ID = type.readLine();
		trans_login_type.write(ID+ "\n");
		trans_login_type.flush();
	    
		System.out.print("PW = ");
		
		password = type.readLine();
		trans_login_type.write(password+ "\n");
		trans_login_type.flush();
		
		login_succ = login_type.readLine();
		
		if(login_succ == null){
			System.out.println("사용자 없음");
		}
		
		System.out.println(login_succ);
	    
	}
		
}
