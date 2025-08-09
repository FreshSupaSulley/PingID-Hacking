package org.example;

import java.io.File;

public class Main {
	
	public static void main(String[] args) throws Exception
	{
		// First activate the device
		// This creates a file containing the serialized PingID device data in the cd
		var ping = new PingID("2644 9963 3447", "I HATE YOU PINGID2");
		
		// Alternatively, you can read the file that's already created
		// This just gets the first one it finds
		//		var ping = new PingID(new File(System.getProperty("user.dir")).listFiles(file -> file.getName().startsWith("pingid_"))[0].toPath());
		
		// Now you can start getting TOTPs to login through PingID
		for(int i = 0; i < 10; i++)
		{
			System.out.println("Latest TOTP: " + ping.generateOTP(6, true));
			// PingID HOTPs last 15s
			Thread.sleep(15000);
		}
	}
}
