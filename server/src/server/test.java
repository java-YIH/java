package server;

import java.io.*;
import java.util.*;
import java.net.*;

class test{
	private static String name;
	private static String ID;
	private static String password;
	
	private static String lohin_ID;
	private static String lohin_password;
	
	private static String login_succ = "�α��� ����";
	private static String login_fail = "�α��� ����";
	
	public static void main(String[] args) throws IOException{
	
		ServerSocket serverSocket = null;
		serverSocket = new ServerSocket(8000);
		
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
