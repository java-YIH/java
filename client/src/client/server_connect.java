package client;

import java.io.*;
import java.util.*;
import java.net.*;


public class server_connect {
	
	private String hostname = "127.0.0.1";
	private int port = 8000;
	
	public server_connect() throws IOException {
		
		Socket sok = new Socket(hostname,port);
		
		
	}
	
}
