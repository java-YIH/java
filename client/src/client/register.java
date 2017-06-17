package client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.Scanner;

public class register extends reg_main{
	
	private String name;
	private String ID;
	private String password;
	
	private String hostname = "127.0.0.1";
	private int port = 8000;
	
	public register() throws IOException{
		
		Socket sok = new Socket(hostname,port);
		BufferedReader type = new BufferedReader(new InputStreamReader(System.in));
		
		OutputStream reg_type = sok.getOutputStream();
		BufferedWriter trans_reg_type = new BufferedWriter(new OutputStreamWriter(reg_type));
		
	    System.out.println("== �ű� ���� ==");
	    
	    
	    
	    
	    name = type.readLine();
	    trans_reg_type.write(name+ "\n");
	    trans_reg_type.flush();
	    
	    System.out.print("ID = ");
	    
	    ID = type.readLine();
	    trans_reg_type.write(ID + "\n");
	    trans_reg_type.flush();
	    
	    
	    System.out.print("Password = ");
	    
	    password = type.readLine();
	    trans_reg_type.write(password);
	    trans_reg_type.flush();

	    sok.close();
	}

    
}
