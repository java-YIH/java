package client;


import java.io.*;
import java.net.Socket;
import java.text.*;
import java.util.*;
import java.net.*;

public class reg_main {
	
   public static void main(String[] ar) throws IOException {
	   
	   BufferedReader num = new BufferedReader(new InputStreamReader(System.in));
	   
	   register register = null;   //��ü���?
	   login login = null;  

      while(true) {
    	 System.out.println();
         System.out.println("1.�ű԰���");
         System.out.println("2.�α���");
         System.out.println("3.����");
         
         int pos = Integer.parseInt(num.readLine());
         
         if(pos == 1){
        	 register = new register();  // �� ���� (register)����
        	 
         }

         
         else if(pos == 2){

        		login = new login(); // �� ���� (login)����
        	 
         }

         
         else if(pos == 3){
        	 
        	 System.exit(0);
        	 
         }

         
         else {
             System.out.println("�߸� �Է� �ϼ̽��ϴ�.");
          }
      }
   }
   
   
   
}
