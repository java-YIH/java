package client;


import java.io.*;
import java.net.Socket;
import java.text.*;
import java.util.*;
import java.net.*;

public class reg_main {
	
   public static void main(String[] ar) throws IOException {
	   
	   BufferedReader num = new BufferedReader(new InputStreamReader(System.in));
	   
	   register register = null;   //객체등록?
	   login login = null;  

      while(true) {
    	 System.out.println();
         System.out.println("1.신규가입");
         System.out.println("2.로그인");
         System.out.println("3.종료");
         
         int pos = Integer.parseInt(num.readLine());
         
         if(pos == 1){
        	 register = new register();  // 이 파일 (register)실행
        	 
         }

         
         else if(pos == 2){

        		login = new login(); // 이 파일 (login)실행
        	 
         }

         
         else if(pos == 3){
        	 
        	 System.exit(0);
        	 
         }

         
         else {
             System.out.println("잘못 입력 하셨습니다.");
          }
      }
   }
   
   
   
}
