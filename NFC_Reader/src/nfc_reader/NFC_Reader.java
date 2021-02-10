package nfc_reader;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.smartcardio.*;

public class NFC_Reader {
	
	static String bin2hex(byte[] data) {
	    return String.format("%0" + (data.length * 2) + "X", new BigInteger(1,data));
	}
	
	static String login = "101012";
	static String password = "ybevpqzehviad";
	static String intranet_url = "https://intranet.reidhall.com/Annuaire/RFID/post.php";
	static String action = "record";
	static String USER_AGENT = "Mozilla/5.0";
	static String current_status = "";
	static String last_status = "";
	static String uid = "";
	
	public static void main(String[] args) {
		System.out.println("Hello");

		try {
			TerminalFactory factory = TerminalFactory.getDefault();
			List<CardTerminal> terminals = factory.terminals().list();
			CardTerminal terminal = terminals.get(0);
			
			boolean waitForCard = true;
			while(waitForCard) {
				waitForCard = terminal.waitForCardPresent(0);
				
				System.out.println("Card inserted");

				Card card = terminal.connect("*");
				CardChannel channel = card.getBasicChannel();
				
				// Disable the buzzer
				ResponseAPDU response1 = channel.transmit(new CommandAPDU( new byte[] { (byte) 0xFF, (byte) 0x00, (byte) 0x52, (byte) 0x00, (byte) 0x00 }));
				
				// Get UID
				ResponseAPDU response = channel.transmit(new CommandAPDU( new byte[] { (byte) 0xFF, (byte) 0xCA, (byte) 0x00, (byte) 0x00, (byte) 0x00 }));
				current_status = response.toString();
				uid = bin2hex(response.getData());

				uid = uid.replaceAll("([0-9A-F]{2})", "$1:");
				uid = uid.replaceAll("(:)$", "");

				System.out.println("UID: " + uid);				

				// Intranet connection
				URL url;
				try {
					url = new URL(intranet_url);
					HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
					
					//add reuqest header
				    con.setRequestMethod("POST");
				    con.setRequestProperty("User-Agent", USER_AGENT);
				    con.setRequestProperty("Accept-Language", "en-US,en;q=0.5");

				    String urlParameters = "login="+login+"&password="+password+"&action="+action+"&tag="+uid;

				    // Send post request
				    con.setDoOutput(true);
				    DataOutputStream wr = new DataOutputStream(con.getOutputStream());
				    wr.writeBytes(urlParameters);
				    wr.flush();
				    wr.close();

					// print_https_cert(con);
			         print_content(con);
			         
			         
				} catch (MalformedURLException e) {
					e.printStackTrace();
			    } catch (IOException e) {
			    	e.printStackTrace();
			    }				
				
				card.disconnect(false);
				waitForCard = terminal.waitForCardAbsent(0);
				System.out.println("Card removed");				
				
			}
			
		} catch(Exception e) {
		}

	}

	private static void print_https_cert(HttpsURLConnection con){
	     
		if(con!=null){
	            
			try {
	                
			    System.out.println("Response Code : " + con.getResponseCode());
			    System.out.println("Cipher Suite : " + con.getCipherSuite());
			    System.out.println("\n");
			                
			    Certificate[] certs = con.getServerCertificates();
			    for(Certificate cert : certs){
			    	System.out.println("Cert Type : " + cert.getType());
			    	System.out.println("Cert Hash Code : " + cert.hashCode());
			    	System.out.println("Cert Public Key Algorithm : " 
			                                    + cert.getPublicKey().getAlgorithm());
			    	System.out.println("Cert Public Key Format : " 
			                                    + cert.getPublicKey().getFormat());
			    	System.out.println("\n");
			    }
		     
		    } catch (SSLPeerUnverifiedException e) {
		    	e.printStackTrace();
		    } catch (IOException e){
		        e.printStackTrace();
		    }
		}
    }
	    
   private static void print_content(HttpsURLConnection con){
	   if(con!=null){
	            
		   	try {
	        
		   		System.out.println("****** Content of the URL ********");			
		   		BufferedReader br = 
		   				new BufferedReader(
		   						new InputStreamReader(con.getInputStream()));
	                
		   		String input;
	                
		   		while ((input = br.readLine()) != null){
		   			System.out.println(input);
		   		}
		   		br.close();
	                
		   	} catch (IOException e) {
		   		e.printStackTrace();
		   	}    
       }        
   }

}