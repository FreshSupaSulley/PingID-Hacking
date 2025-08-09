package org.example;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.jsonwebtoken.Jwts;
import com.google.gson.Gson;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class PingID {
	
	private static final String serverPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvotTwKvoqyuXgL/IFiHbc0twX55BNh4u/+l0Yz/ieVE81A+S2dhSggVloXuCKz355+jKiDOYQgeGkEuYZnBqK3jbkYpxS83YNED7zAOxGjX6EtalHuJcmqvosrNlcpMj0DbPsfUTw/yLr7VMEqX97suZXMDNiwxQzD5FiiIjcOgVIlyrKKkRIVl3HfaPr+9Dg+dRLveHPK9M869FokounL8iWy7uYINqGwadT28nHCK1sVUjnEj1/UGkkq+/DHpmiRhM2C6GsHcsE1IEC9pBiC8prTVcRXlxBfIJwoqOjGPpWE+VpmFOP2VF4wFRadhB5zJB7L73cKvOyaOdMO0IawIDAQAB";
	
	private static final Gson gson = new Gson();
	private static final BouncyCastleProvider bc = new BouncyCastleProvider();
	
	/** Generated during the "provision" request and is meant to be stored on the device */
	private KeyPair deviceKeyPair;
	/** Some sort of unique identifier for the device? Not sure how it's generated but can probably be random */
	private String fingerprint;
	/** Stored per-device and needs to be saved to allow for further communication */
	// ... is session_id just for provisioning?
	private String id, session_id, enc_sid;
	
	/**
	 * Starts at the system time and increments by 1 each time it's used (it's HOTP after all). Technically loops around
	 * eventually
	 */
	private long otpCounter;
	
	/** Used in every request. Identifies the device */
	private static final LinkedHashMap<String, Object> metaHeader;
	
	static
	{
		Security.setProperty("crypto.policy", "unlimited"); // do we need this? random tut said to include it
		
		Security.addProvider(bc);
		Security.insertProviderAt(bc, 1); // pingid has this too, but this doesn't seem to do anything
		
		// Edit these as you see fit
		metaHeader = new LinkedHashMap<>();
		metaHeader.put("api_version", "18.0");
		metaHeader.put("app_version", "1.23.0(13063)");
		metaHeader.put("is_device_lock", true);
		metaHeader.put("device_type", "Android");
		metaHeader.put("is_biometrics_supported", false); // wtf does this mean? fingerprint?
		metaHeader.put("locale", "en-US");
		metaHeader.put("disabled_location", true);
		metaHeader.put("pingid_mdm_token", "");
		metaHeader.put("model", "YOU GOT FUCKING TROLLED");
		metaHeader.put("network_type", "mobile");
		metaHeader.put("networks_info", "base64:d3M6e3dlOiBbXX0sbXM6e2E6IG0sIHBUOiBHU00sbmNzOiB7fX0="); // no clue what this means, probably has 0 impact for our purposes
		metaHeader.put("os_version", "9");
		metaHeader.put("pretty_model", "cybersecurity best get on this one");
		metaHeader.put("is_root", true);
		metaHeader.put("vendor", "Google");
	}
	
	public static void main(String[] args)
	{
		// First activate the device
		var ping = new PingID("6103 9493 9309");
	}
	
	/**
	 * Initializes a new PingID device from an activation code.
	 *
	 * @param activationCode 12 digit activation code (spaces are removed)
	 */
	public PingID(String activationCode)
	{
		// Remove any spaces
		activationCode = activationCode.replace(" ", "");
		
		// First activate the device
		JsonObject data = verifyActivationCode(activationCode);
		this.id = data.get("id").getAsString();
		this.session_id = data.get("session_id").getAsString();
		data = provision();
		
		try
		{
			var cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, deviceKeyPair.getPrivate());
			this.enc_sid = new String(cipher.doFinal(Base64.getDecoder().decode(data.get("enc_sid").getAsString())));
		} catch(Exception e)
		{
			throw new RuntimeException(e);
		}
		
		data = testOTP();
		
		if(data.get("response_status").getAsInt() != 0)
			throw new RuntimeException("test_otp failed");
		
		/*
		 * Increments OTP counter by creating a useless HOTP
		 * Apparently you need to do this, which makes me think it's used somewhere else in the app
		 * ... or the app is just coded terribly (even though I saw crumby decompilation, I would believe it)
		 */
		System.out.println("BOUTTA");
		generateOTP(6, false);
		
		data = finalizeOnboarding(data);
		data = getUserInfo(data);
		
		System.out.println(data);
		
		// Write the device data to a file
		JsonObject toFile = new JsonObject();
		toFile.addProperty("fingerprint", fingerprint);
		toFile.addProperty("enc_sid", enc_sid);
		toFile.addProperty("otpCounter", otpCounter);
		toFile.addProperty("publicKey", Base64.getEncoder().encodeToString(deviceKeyPair.getPublic().getEncoded()));
		toFile.addProperty("privateKey", Base64.getEncoder().encodeToString(deviceKeyPair.getPrivate().getEncoded()));
		
		try
		{
			Files.writeString(Path.of("pingid_" + fingerprint), toFile.toString());
		} catch(IOException e)
		{
			System.err.println("Failed to write device data to file");
			throw new RuntimeException(e);
		}
	}
	
	public PingID(Path deviceData)
	{
	
	}
	
	public String generateOTP(int otpLength, boolean isTotp)
	{
		String strN = blendFingerprintAndSID();
		long counter = getTOTPNow();
		
		if(!isTotp)
		{
			// Increment OTP
			// This limit was ripped from the app. It's also used as a mask elsewhere in the app
			if(++otpCounter > 72057594037927935L)
			{
				otpCounter = 0;
			}
			
			System.out.println("INCREMENTING OTP" + otpCounter);
			counter = otpCounter;
		}
		
		try
		{
			return OTP.generateOTP(strN.getBytes(StandardCharsets.UTF_8), counter, otpLength, false, -1);
		} catch(Exception e)
		{
			System.err.println("Failed to generate OTP");
			// lazily wrapping as runtime exception (because this error should never happen)
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Ripped straight from the decompilation. Some sort of obfuscated logic that's used for OTP generation.
	 *
	 * @return a hybrid of fingerprint and <code>enc_sid</code>
	 */
	private String blendFingerprintAndSID()
	{
		byte[] bytes = fingerprint.getBytes();
		byte b2 = bytes[0];
		int length = b2 % fingerprint.length();
		byte b3 = bytes[length];
		int i = (b3 % 30) + 30;
		int iMin = (Math.min(fingerprint.length(), enc_sid.length()) * i) / 100;
		String strSubstring = fingerprint.substring(0, iMin);
		int length2 = strSubstring.length() % enc_sid.length();
		String str = strSubstring.substring(0, length2) + enc_sid.substring(length2);
		//		p().debug("Generate SID: firstByte: %c; ByteNumber: %d; criteria: %d; percentage: %d; length of Part1: %d; part1: %s; relativeLength: %d; result:%s", Byte.valueOf(b2), Integer.valueOf(length), Integer.valueOf(b3), Integer.valueOf(i), Integer.valueOf(iMin), strSubstring, Integer.valueOf(length2), str);
		// ^ was also straight from decompilation. Might tell us more about what this is supposed to be
		return str;
	}
	
	/**
	 * Generates the TOTP that's valid for this moment. This changes every 15 seconds.
	 *
	 * @return the newest TOTP value
	 */
	public synchronized long getTOTPNow()
	{
		return System.currentTimeMillis() / 15000;
	}
	
	private Map<String, Object> getSecurityHeader(JsonObject data)
	{
		LinkedHashMap<String, Object> securityHeader = new LinkedHashMap<>();
		securityHeader.put("local_fallback_data_hash", "");
		securityHeader.put("finger_print", fingerprint);
		securityHeader.put("id", id);
		securityHeader.put("otp", generateOTP(8, false));
		securityHeader.put("ts", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"))); // i assume this is time now?
		securityHeader.put("tz", OffsetDateTime.now().getOffset().getId().replace("Z", "+0000").replace(":", ""));
		securityHeader.put("totp", generateOTP(8, true));
		return securityHeader;
	}
	
	// FIRST STEP
	public JsonObject verifyActivationCode(String activationCode)
	{
		fingerprint = Base64.getEncoder().encodeToString(newFingerprint().getBytes());
		// Build the JSON payload using org.json
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("activation_code", activationCode);
		body.put("finger_print", fingerprint);
		body.put("device_type", "Android");
		body.put("is_primary", false);
		body.put("meta_header", metaHeader);
		body.put("request_type", "verify_activation_code");
		
		Map<String, Object> payload = new LinkedHashMap<>();
		payload.put("body", body);
		payload.put("signature", "no_signature");
		
		String fullPayload = gson.toJson(payload);
		System.out.println("Sending for activation: " + fullPayload);
		// Build request
		// removed the gzip header
		// jwt true or false doesn't seem to make a difference
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Content-Type", "application/json; charset=utf-8").header("jwt", "false").POST(HttpRequest.BodyPublishers.ofString(fullPayload.toString(), StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// SECOND STEP
	// Sends as encoeded JWT
	public JsonObject provision()
	{
		try
		{
			// Generate a random key to be stored on this device
			var generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(2048);
			deviceKeyPair = generator.generateKeyPair();
		} catch(Exception e)
		{
			throw new RuntimeException(e);
		}
		
		PrivateKey privateKey = deviceKeyPair.getPrivate();
		PublicKey publicKey = deviceKeyPair.getPublic();
		
		// enc_count_reg_id
		byte[] rawServerPubKey = Base64.getDecoder().decode(serverPubKey.getBytes(StandardCharsets.UTF_8));
		
		// Update the otpCounter
		otpCounter = getTOTPNow();
		// Now use it to fill in the weird ass hex value
		String totpString = Long.toHexString(otpCounter);
		String otpCounterHex = totpString.length() < 15 ? generateOTP(totpString, '0', 16) : totpString.substring((totpString.length() - 16) - 1, totpString.length() - 1);
		
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<String, Object>();
		hashMap.put("finger_print", fingerprint);
		hashMap.put("id", id);
		hashMap.put("device_type", "Android");
		hashMap.put("enc_count_reg_id", createEncCountRegID(rawServerPubKey, otpCounterHex));
		hashMap.put("public_key", new String(Base64.getEncoder().encode(publicKey.getEncoded()))); // seems right
		hashMap.put("pushless", true); // because registrationId is null, pushless is true
		hashMap.put("session_id", session_id);
		hashMap.put("meta_header", metaHeader);
		hashMap.put("request_type", "provision");
		
		String toJSON = gson.toJson(hashMap);
		System.out.println(toJSON);
		// registration ID, might need to be filled idk. Worth logging in smali to find out
		//		sb.append("");
		//		Instant now = Instant.now();
		
		/*
		 * The JWT is signed by the same keypair generated for provisioning (working)
		 * The signature might still be goofed up though.
		 */
		String jwt = Jwts.builder().header().and()
				// They also include a signature within the JWT
				.claims(hashMap)
				.claim("signature", createSignature("SHA1withRSA", toJSON.getBytes(), privateKey)) // app key or private key??
				.signWith(privateKey)
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Accept-Encoding", "gzip").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// THIRD STEP
	// test_otp
	public JsonObject testOTP()
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<>();
		hashMap.put("finger_print", fingerprint);
		hashMap.put("id", id);
		hashMap.put("otp", generateOTP(6, true)); // HOTP!!
		hashMap.put("session_id", session_id);
		hashMap.put("meta_header", metaHeader);
		hashMap.put("request_type", "test_otp");
		
		String toJSON = gson.toJson(hashMap);
		System.out.println(toJSON);
		
		/*
		 * The JWT is signed by the same keypair generated for provisioning (working)
		 * The signature might still be goofed up though.
		 */
		String jwt = Jwts.builder().header().and()
				// They also include a signature within the JWT
				.claims(hashMap)
				.claim("signature", createSignature("SHA1withRSA", toJSON.getBytes(), deviceKeyPair.getPrivate())) // app key or private key??
				.signWith(deviceKeyPair.getPrivate())
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Accept-Encoding", "gzip").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// FOURTH STEP
	// finalize_onboarding
	public JsonObject finalizeOnboarding(JsonObject data)
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<>();
		hashMap.put("finger_print", fingerprint);
		hashMap.put("id", id);
		hashMap.put("nickname", "base64:" + Base64.getEncoder().encodeToString("MY AWESOME FUCKING NICKNAME".getBytes()));
		hashMap.put("session_id", session_id);
		hashMap.put("meta_header", metaHeader);
		hashMap.put("request_type", "finalize_onboarding");
		
		// All steps bayond test_otp require this
		hashMap.put("security_header", getSecurityHeader(data));
		
		String toJSON = gson.toJson(hashMap);
		System.out.println(toJSON);
		
		/*
		 * The JWT is signed by the same keypair generated for provisioning (working)
		 * The signature might still be goofed up though.
		 */
		String jwt = Jwts.builder().header().and()
				// They also include a signature within the JWT
				.claims(hashMap)
				.claim("signature", createSignature("SHA1withRSA", toJSON.getBytes(), deviceKeyPair.getPrivate())) // app key or private key??
				.signWith(deviceKeyPair.getPrivate())
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Accept-Encoding", "gzip").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// FIFTH (and last) OPTIONAL STEP
	// get_user_info
	public JsonObject getUserInfo(JsonObject data)
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<>();
		hashMap.put("id", id);
		hashMap.put("meta_header", metaHeader);
		hashMap.put("request_type", "get_user_info");
		hashMap.put("security_header", getSecurityHeader(data));
		
		String toJSON = gson.toJson(hashMap);
		System.out.println(toJSON);
		
		/*
		 * The JWT is signed by the same keypair generated for provisioning (working)
		 * The signature might still be goofed up though.
		 */
		String jwt = Jwts.builder().header().and()
				// They also include a signature within the JWT
				.claims(hashMap)
				.claim("signature", createSignature("SHA1withRSA", toJSON.getBytes(), deviceKeyPair.getPrivate())) // app key or private key??
				.signWith(deviceKeyPair.getPrivate())
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Accept-Encoding", "gzip").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// fingerprint is random
	public static String newFingerprint()
	{
		// a\a\j\d0.smali
		final int length = 20;
		final String CHAR_POOL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		StringBuilder sb = new StringBuilder(length); // for .M suffix
		var random = new Random();
		
		for(int i = 0; i < length; i++)
		{
			int idx = random.nextInt(CHAR_POOL.length());
			sb.append(CHAR_POOL.charAt(idx));
		}
		
		return sb.toString();
	}
	
	public static String createSignature(String algorithm, byte[] bytesTotal, PrivateKey privateKey)
	{
		try
		{
			Signature signature = Signature.getInstance(algorithm, bc);
			signature.initSign(privateKey);
			signature.update(bytesTotal);
			return new String(Base64.getEncoder().encode(signature.sign()), StandardCharsets.UTF_8);
		} catch(Exception e)
		{
			throw new RuntimeException(e);
		}
	}
	
	private static String generateOTP(String strNextLong, char c2, int length)
	{
		while(strNextLong.length() < length)
		{
			strNextLong = c2 + strNextLong;
		}
		return strNextLong;
	}
	
	public static String createEncCountRegID(byte[] publicKeyBytes, String encryptionCandidate)
	{
		try
		{
			PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			Cipher cipher = Cipher.getInstance(key.getAlgorithm(), "BC");
			cipher.init(1, key);
			return Base64.getEncoder().encodeToString(cipher.doFinal(encryptionCandidate.getBytes()));
		} catch(Exception e)
		{
			throw new RuntimeException(e);
		}
	}
	
	private JsonObject sendRequest(HttpRequest request)
	{
		// Send request asynchronously
		HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).connectTimeout(Duration.ofSeconds(10)).build();
		try
		{
			HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
			int statusCode = response.statusCode();
			System.out.println("Response code: " + statusCode);
			
			String encoding = response.headers().map().getOrDefault("content-encoding", List.of("hi")).get(0);
			
			String responseBody;
			
			if(encoding.equals("gzip"))
			{
				responseBody = new String(new java.util.zip.GZIPInputStream(response.body()).readAllBytes(), StandardCharsets.UTF_8);
			}
			else
			{
				responseBody = new String(response.body().readAllBytes(), StandardCharsets.UTF_8);
			}
			
			System.out.println("Raw response body: " + responseBody);
			
			// Decode JWT payload
			String[] parts = responseBody.split("\\.");
			if(parts.length == 3)
			{
				String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
				System.out.println("Decoded JWT payload: " + payloadJson);
				return JsonParser.parseString(payloadJson).getAsJsonObject();
			}
			else
			{
				throw new Exception("Response is not a valid JWT");
			}
		} catch(Exception e)
		{
			throw new RuntimeException(e);
		}
	}
}
