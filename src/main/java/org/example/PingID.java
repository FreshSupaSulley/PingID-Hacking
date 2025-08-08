package org.example;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.jsonwebtoken.Jwts;
import com.google.gson.Gson;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class PingID {
	
	private static final String serverPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvotTwKvoqyuXgL/IFiHbc0twX55BNh4u/+l0Yz/ieVE81A+S2dhSggVloXuCKz355+jKiDOYQgeGkEuYZnBqK3jbkYpxS83YNED7zAOxGjX6EtalHuJcmqvosrNlcpMj0DbPsfUTw/yLr7VMEqX97suZXMDNiwxQzD5FiiIjcOgVIlyrKKkRIVl3HfaPr+9Dg+dRLveHPK9M869FokounL8iWy7uYINqGwadT28nHCK1sVUjnEj1/UGkkq+/DHpmiRhM2C6GsHcsE1IEC9pBiC8prTVcRXlxBfIJwoqOjGPpWE+VpmFOP2VF4wFRadhB5zJB7L73cKvOyaOdMO0IawIDAQAB";
	
	private static Gson gson = new Gson();
	private static BouncyCastleProvider bc = new BouncyCastleProvider();
	
	/** Generated during the "provision" request and is meant to be stored on the device */
	private KeyPair deviceKeyPair;
	/** Some sort of unique identifier for the device? Not sure how it's generated but can probably be random */
	private String fingerprint;
	/** Stored per-device and needs to be saved to allow for further communication */
	private String id, session_id, enc_sid;
	
	/**
	 * Starts at the system time and increments by 1 each time it's used (it's HOTP after all). Technically loops around
	 * eventually
	 */
	private long otpCounter;
	
	/** Used in every request. Identifies the device */
	private static LinkedHashMap<String, Object> metaHeader;
	
	/** The activation code, given to you as 3 4-digit segments */
	private static final String activationCode = "4531 7263 7700".replace(" ", "");
	
	static
	{
		Security.setProperty("crypto.policy", "unlimited"); // do we need this? random tut said to include it
		
		Security.addProvider(bc);
		Security.insertProviderAt(bc, 1); // pingid has this too, but this doesn't seem to do anything
		
		// Edit these as you see fit
		metaHeader = new LinkedHashMap<String, Object>();
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
	
	public String generateOTP(int otpLength, boolean isHotp)
	{
		String strN = blendFingerprintAndSID();
		if(!isHotp)
		{
			String strA = a(strN, otpCounter, otpLength);
			this.otpCounter = incrementOTPCounter(otpCounter);
			System.err.println("BUMPING OTP");
			System.out.println(isHotp + " RESULT " + strA);
			return strA;
		}
		// Use time??
		long jY0 = getTOTPNow();
		String strA2 = a(strN, Long.valueOf(jY0), otpLength);
		System.out.println(isHotp + " RESULT " + strA2);
		return strA2;
	}
	
	/**
	 * Ripped straight from the decompilation. Some sort of obfuscated logic that's used for OTP generation.
	 *
	 * @return a hybrid of fingerprint and <code>enc_sid</code>
	 */
	public String blendFingerprintAndSID()
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
	
	public long incrementOTPCounter(long otpCounter)
	{
		long j = otpCounter + 1;
		// This limit was ripped from the app. It's also used as a mask elsewhere in the app
		if(j > 72057594037927935L)
		{
			return 0L;
		}
		
		return j;
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
	
	public String a(String secret, Long counter, int codeDigits)
	{
		try {
			return OTP.generateOTP(secret.getBytes(StandardCharsets.UTF_8), counter, codeDigits, false, -1);
		} catch(Exception e) {
			System.err.println("Failed to generate OTP");
			// lazily wrapping as runtime exception (because this error should never happen)
			throw new RuntimeException(e);
		}
	}
	
	public Map<String, Object> getSecurityHeader(JsonObject data) throws Exception
	{
		LinkedHashMap<String, Object> securityHeader = new LinkedHashMap<>();
		securityHeader.put("local_fallback_data_hash", "");
		securityHeader.put("finger_print", fingerprint);
		securityHeader.put("id", id);
		
		//
		securityHeader.put("otp", generateOTP(8, false));
		
		securityHeader.put("ts", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"))); // i assume this is time now?
		securityHeader.put("tz", OffsetDateTime.now().getOffset().getId().replace("Z", "+0000").replace(":", ""));
		securityHeader.put("totp", generateOTP(8, true));
		return securityHeader;
	}
	
	// FIRST STEP
	public JsonObject verifyActivationCode(String activationCode) throws Exception
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
	public JsonObject provision(JsonObject data) throws Exception
	{
		// I assume the device generates a random key
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		generator.initialize(2048); // Key size
		deviceKeyPair = generator.generateKeyPair();
		PrivateKey privateKey = deviceKeyPair.getPrivate();
		PublicKey publicKey = deviceKeyPair.getPublic();
		
		// enc_count_reg_id
		byte[] bArrDecode = Base64.getDecoder().decode(serverPubKey.getBytes(StandardCharsets.UTF_8));
		otpCounter = getTOTPNow(); // NOT m0(). This is TOTP, not HOTP
		String sb = w(otpCounter);
		
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<String, Object>();
		hashMap.put("finger_print", fingerprint);
		hashMap.put("id", id);
		hashMap.put("device_type", "Android");
		hashMap.put("enc_count_reg_id", g(bArrDecode, sb));
		hashMap.put("public_key", x(publicKey)); // seems right
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
				.claim("signature", f("SHA1withRSA", toJSON.getBytes(), privateKey)) // app key or private key??
				.signWith(privateKey)
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Accept-Encoding", "gzip").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// THIRD STEP
	// test_otp
	public JsonObject testOTP(JsonObject data) throws Exception
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<String, Object>();
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
				.claim("signature", f("SHA1withRSA", toJSON.getBytes(), deviceKeyPair.getPrivate())) // app key or private key??
				.signWith(deviceKeyPair.getPrivate())
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Accept-Encoding", "gzip").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// FOURTH STEP
	// finalize_onboarding
	public JsonObject finalizeOnboarding(JsonObject data) throws Exception
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<String, Object>();
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
				.claim("signature", f("SHA1withRSA", toJSON.getBytes(), deviceKeyPair.getPrivate())) // app key or private key??
				.signWith(deviceKeyPair.getPrivate())
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Accept-Encoding", "gzip").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// FIFTH (and last) OPTIONAL STEP
	// get_user_info
	public JsonObject getUserInfo(JsonObject data) throws Exception
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<String, Object>();
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
				.claim("signature", f("SHA1withRSA", toJSON.getBytes(), deviceKeyPair.getPrivate())) // app key or private key??
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
		
		System.out.println(sb);
		return sb.toString();
	}
	
	public static String f(String algorithm, byte[] bytesTotal, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException
	{
		Signature signature = Signature.getInstance(algorithm, bc);
		signature.initSign(privateKey);
		signature.update(bytesTotal);
		return new String(Base64.getEncoder().encode(signature.sign()), StandardCharsets.UTF_8);
	}
	
	public static String x(PublicKey publicKey)
	{
		return new String(Base64.getEncoder().encode(publicKey.getEncoded()));
	}
	
	public static String w(long number)
	{
		String hexString = Long.toHexString(number);
		return hexString.length() < 15 ? generateOTP(hexString, '0', 16) : hexString.substring((hexString.length() - 16) - 1, hexString.length() - 1);
	}
	
	private static String generateOTP(String strNextLong, char c2, int length)
	{
		while(strNextLong.length() < length)
		{
			strNextLong = c2 + strNextLong;
		}
		return strNextLong;
	}
	
	public static String g(byte[] publicKeyBytes, String encryptionCandidate) throws Exception
	{
		return e(u(publicKeyBytes), encryptionCandidate);
	}
	
	public static String e(PublicKey publicKey, String encryptionCandidate) throws Exception
	{
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm(), "BC");
		cipher.init(1, publicKey);
		return Base64.getEncoder().encodeToString(cipher.doFinal(encryptionCandidate.getBytes()));
	}
	
	public static PublicKey u(byte[] publicKeyBytes) throws Exception
	{
		return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
	}
	
	private JsonObject sendRequest(HttpRequest request) throws Exception
	{
		// Send request asynchronously
		HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).connectTimeout(Duration.ofSeconds(10)).build();
		HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
		int statusCode = response.statusCode();
		System.out.println("Response code: " + statusCode);
		
		String encoding = response.headers()
				.map()
				.getOrDefault("content-encoding", List.of("hi"))
				.get(0);
		
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
	}
	
	public static void main(String[] args) throws Exception
	{
		// (new) OTP algorithm is fine
		// 2 things we need to figure out
		// 1. PARAM_SECRET? <-- harder probably because it has to do with cipher bs
		// 2. PARAM_COUNTER??
		// how are these generated
		//		System.out.println(n("QWZieTBjcFl6d0NyRE9MQ2hDUU8=", "QdbHq7VN20v8wMUNPGhl"));
		//		System.exit(0);
		
		// First activate the device
		var ping = new PingID();
		JsonObject init = ping.verifyActivationCode(activationCode);
		ping.id = init.get("id").getAsString();
		ping.session_id = init.get("session_id").getAsString();
		init = ping.provision(init);
		// Now do enc_sid stuff
		//		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		//		generator.initialize(2048); // Key size
		//		var deviceKeyPair = generator.generateKeyPair();
		//		PrivateKey privateKey = deviceKeyPair.getPrivate();
		//		PublicKey publicKey = deviceKeyPair.getPublic();
		var privateKey = ping.deviceKeyPair.getPrivate();
		System.out.println(privateKey.getClass().getName());
		//		String test = "PCy4sU4TMDILwU2/nGPsWPfl5W51Smrvuac2kBX4HY4si+hpD/8pFW6zexRsXLd6dkXQfxVBNIeBDMw/9LaI5rlvJnPVHCD1XuGVLjilOjn1Bo1weqmDdhuTfT/ux0UFg2z8eMgcjW2S3VLi4DQSNlUGeIcMP5brPqFdSaq52ppBYHLIAnct6ZmuljiLqXfJH8We3EWQ1yMi1bgJ2pO4mXc5NAY4hAZ74ZrQKSund0iSESQbFKHyBVisghxvZbkMSvMjy2om+3jHI9t2bhuWdjYusj1EMNGQO1Jpx5JfuioZCreRIC19P0Fhr1z6uWSXcBpob7jSLUBSBaPl9Ys1Kw==";
		Cipher cipher = Cipher.getInstance("RSA", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		System.out.println(privateKey.getAlgorithm() + " " + init.get("enc_sid").getAsString());
		//		new String(cipher.doFinal(Base64.getDecoder().decode(test)));
		ping.enc_sid = new String(cipher.doFinal(Base64.getDecoder().decode(init.get("enc_sid").getAsString())));
		init = ping.testOTP(init);
		if(init.get("response_status").getAsInt() != 0)
			throw new Exception("test_otp failed");
		ping.otpCounter = ping.incrementOTPCounter(ping.otpCounter);
		
		init = ping.finalizeOnboarding(init);
		init = ping.getUserInfo(init);
	}
}
