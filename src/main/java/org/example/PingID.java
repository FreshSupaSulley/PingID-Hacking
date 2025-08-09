package org.example;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.jsonwebtoken.Jwts;
import com.google.gson.Gson;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.zip.GZIPInputStream;

public class PingID {
	
	private static final String serverPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvotTwKvoqyuXgL/IFiHbc0twX55BNh4u/+l0Yz/ieVE81A+S2dhSggVloXuCKz355+jKiDOYQgeGkEuYZnBqK3jbkYpxS83YNED7zAOxGjX6EtalHuJcmqvosrNlcpMj0DbPsfUTw/yLr7VMEqX97suZXMDNiwxQzD5FiiIjcOgVIlyrKKkRIVl3HfaPr+9Dg+dRLveHPK9M869FokounL8iWy7uYINqGwadT28nHCK1sVUjnEj1/UGkkq+/DHpmiRhM2C6GsHcsE1IEC9pBiC8prTVcRXlxBfIJwoqOjGPpWE+VpmFOP2VF4wFRadhB5zJB7L73cKvOyaOdMO0IawIDAQAB";
	
	private static final Gson gson = new Gson();
	private static final BouncyCastleProvider bc = new BouncyCastleProvider();
	
	/** Generated during the "provision" request and is meant to be stored on the device */
	private KeyPair deviceKeyPair;
	/** Some sort of unique identifier for the device? Not sure how it's generated but can probably be random */
	private String fingerprint;
	/** Stored per-device and needs to be saved to allow for further communication */
	// ... is session_id just for provisioning? Probably
	private String id, enc_sid, session_id;
	/** Our user data. Not needed for functionality */
	private JsonObject userInfo;
	/**
	 * Starts at the system time and increments by 1 each time it's used (it's HOTP after all). Technically loops around
	 * eventually
	 */
	private long hotpCounter;
	
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
		metaHeader.put("model", "Seemingly useless property");
		metaHeader.put("network_type", "mobile");
		metaHeader.put("networks_info", "base64:d3M6e3dlOiBbXX0sbXM6e2E6IG0sIHBUOiBHU00sbmNzOiB7fX0="); // no clue what this means, probably has 0 impact for our purposes
		metaHeader.put("os_version", "9");
		metaHeader.put("pretty_model", "Our pretty model name");
		metaHeader.put("is_root", false); // indicates a rooted device
		metaHeader.put("vendor", "Google");
	}
	
	/**
	 * Initializes a new PingID device from an activation code.
	 *
	 * @param activationCode 12 digit activation code (spaces are removed)
	 * @param name           name of your new device that will appear on the PingID device manager site (i.e. iPhone 13
	 *                       Mini)
	 * @throws RuntimeException if something goes wrong, like the activation code being expired (which returns a
	 *                          <code>response_status</code> of -9)
	 */
	public PingID(String activationCode, String name)
	{
		// This is the entire PingID onboarding flow
		verifyActivationCode(activationCode.replace(" ", "")); // remove any spaces
		// This is the main naming property that APPEARS to have server-side effects
		// The nickname defined in finalizeOnboarding might do something server-side too but I haven't discovered that yet
		metaHeader.put("pretty_model", name);
		
		// Begin onboarding
		provision();
		testOTP();
		finalizeOnboarding();
		
		// ... and we're done and our device is registered
		// Let's grab our info just for fun
		this.userInfo = getUserInfo();
		
		// Now let's write our device to a file so we can use it later
		writeToFile();
	}
	
	/**
	 * Writes this PingID instance data to a file.
	 */
	public void writeToFile()
	{
		try
		{
			JsonObject toSave = new JsonObject();
			toSave.addProperty("id", id);
			toSave.addProperty("fingerprint", fingerprint);
			toSave.addProperty("enc_sid", enc_sid);
			toSave.addProperty("hotp_counter", hotpCounter);
			toSave.addProperty("publicKey", Base64.getEncoder().encodeToString(deviceKeyPair.getPublic().getEncoded()));
			toSave.addProperty("privateKey", Base64.getEncoder().encodeToString(deviceKeyPair.getPrivate().getEncoded()));
			// Why not
			toSave.add("user_info", userInfo);
			// Serializes our data to a file
			Files.writeString(Path.of("pingid_" + Base64.getEncoder().encodeToString(id.getBytes()) + ".json"), gson.toJson(toSave));
		} catch(IOException e)
		{
			System.err.println("Failed to write device data to file");
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Deserializes a PingID data file.
	 *
	 * <p>See {@link #writeToFile()}.</p>
	 *
	 * @param dataFile path to file
	 * @throws Exception if something goes wrong
	 */
	public PingID(Path dataFile) throws Exception
	{
		var data = gson.fromJson(Files.readString(dataFile, StandardCharsets.UTF_8), JsonObject.class);
		this.id = data.get("id").getAsString();
		this.fingerprint = data.get("fingerprint").getAsString();
		this.enc_sid = data.get("enc_sid").getAsString();
		
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(data.get("publicKey").getAsString()));
		PublicKey publicKey = KeyFactory.getInstance("RSA", "BC").generatePublic(pubSpec);
		
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(data.get("privateKey").getAsString()));
		PrivateKey privateKey = KeyFactory.getInstance("RSA", "BC").generatePrivate(privSpec);
		
		this.deviceKeyPair = new KeyPair(publicKey, privateKey);
	}
	
	public String generateOTP(int otpLength, boolean isTotp)
	{
		long counter = getCurrentTimestep();
		
		if(!isTotp)
		{
			// Increment OTP
			// This limit was ripped from the app. It's also used as a mask elsewhere in the app
			if(++hotpCounter > 72057594037927935L)
			{
				hotpCounter = 0;
			}
			
			counter = hotpCounter;
		}
		
		try
		{
			return OTP.generateOTP(blendFingerprintAndSID().getBytes(StandardCharsets.UTF_8), counter, otpLength, false, -1);
		} catch(Exception e)
		{
			System.err.println("Failed to generate OTP");
			// lazily wrapping as runtime exception (because this error should never happen)
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Ripped from decompilation. Some sort of obfuscated logic that's used for OTP generation.
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
		//		p().debug("Generate SID: firstByte: %c; ByteNumber: %d; criteria: %d; percentage: %d; length of Part1: %d; part1: %s; relativeLength: %d; result:%s", Byte.valueOf(b2), Integer.valueOf(length), Integer.valueOf(b3), Integer.valueOf(i), Integer.valueOf(iMin), strSubstring, Integer.valueOf(length2), str);
		// ^ was also straight from decompilation. Might tell us more about what this is supposed to be
		return strSubstring.substring(0, length2) + enc_sid.substring(length2);
	}
	
	/**
	 * Generates the TOTP that's valid for this moment. This changes every 15 seconds.
	 *
	 * @return the newest TOTP value
	 */
	private long getCurrentTimestep()
	{
		return System.currentTimeMillis() / 15000;
	}
	
	private Map<String, Object> getSecurityHeader()
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
	private void verifyActivationCode(String activationCode)
	{
		fingerprint = Base64.getEncoder().encodeToString(generateFingerprint().getBytes());
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
		
		// Only request during onboarding where there's no JWT
		JsonObject response = sendRequest(fullPayload);
		// Fill our per device variables
		this.id = response.get("id").getAsString();
		// I think session ID is just for onboarding...
		this.session_id = response.get("session_id").getAsString();
	}
	
	/**
	 * Generates a random device fingerprint to identify itself to PingID. Not sure what would happen if multiple
	 * devices of the same fingerprint were created.
	 *
	 * <p>If I were to guess, I'd imagine if a PingID device was already registered and a new device was created with
	 * the same fingerprint, the old one will be deleted... needs tested.</p>
	 *
	 * @return the newly randomized device fingerprint
	 */
	public static String generateFingerprint()
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
	
	// SECOND STEP
	// Sends as encoeded JWT
	private void provision()
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
		
		// For enc_count_reg_id
		byte[] rawServerPubKey = Base64.getDecoder().decode(serverPubKey.getBytes(StandardCharsets.UTF_8));
		
		// Update the otpCounter
		hotpCounter = getCurrentTimestep();
		// Now use it to fill in the weird ass hex value
		String totpString = Long.toHexString(hotpCounter);
		String otpCounterHex = String.format("%16s", totpString).replace(' ', '0');
		
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
		claims.put("finger_print", fingerprint);
		claims.put("id", id);
		claims.put("device_type", "Android");
		claims.put("enc_count_reg_id", createEncCountRegID(rawServerPubKey, otpCounterHex));
		// Attach the device's public key that we just generated
		claims.put("public_key", new String(Base64.getEncoder().encode(deviceKeyPair.getPublic().getEncoded())));
		claims.put("pushless", true); // because registrationId is null, pushless is true
		claims.put("session_id", session_id);
		claims.put("meta_header", metaHeader);
		claims.put("request_type", "provision");
		
		// We need the response to create our enc_sid
		JsonObject response = sendJWT(claims);
		
		try
		{
			var cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, deviceKeyPair.getPrivate());
			this.enc_sid = new String(cipher.doFinal(Base64.getDecoder().decode(response.get("enc_sid").getAsString())));
		} catch(Exception e)
		{
			throw new RuntimeException(e);
		}
	}
	
	private static String createEncCountRegID(byte[] publicKeyBytes, String encryptionCandidate)
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
	
	// THIRD STEP
	// test_otp (you're testing HOTP not TOTP in this endpoint)
	private void testOTP()
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
		claims.put("finger_print", fingerprint);
		claims.put("id", id);
		claims.put("otp", generateOTP(6, true)); // HOTP!!
		claims.put("session_id", session_id);
		claims.put("meta_header", metaHeader);
		claims.put("request_type", "test_otp");
		
		// We don't need the response for this particular endpoint
		sendJWT(claims);
		
		/*
		 * IMPORTANT!
		 * Increments the HOTP counter by creating a useless HOTP
		 * Apparently you need to do this, which makes me think it's used somewhere else in the app
		 * ... or the app is just coded terribly (even though I only saw crumby decompilation, I could believe it)
		 */
		generateOTP(6, false);
	}
	
	// FOURTH STEP
	// finalize_onboarding
	private void finalizeOnboarding()
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
		claims.put("finger_print", fingerprint);
		claims.put("id", id);
		claims.put("nickname", "base64:" + Base64.getEncoder().encodeToString("My epic device nickname".getBytes())); // this doesn't appear to do anything server-side
		claims.put("session_id", session_id);
		claims.put("meta_header", metaHeader);
		claims.put("request_type", "finalize_onboarding");
		// All steps bayond test_otp require this, which contains the OTPs
		claims.put("security_header", getSecurityHeader());
		
		// We also don't care about the response for this endpoint either
		sendJWT(claims);
	}
	
	// Optional endpoint but fun
	// get_user_info
	public JsonObject getUserInfo()
	{
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
		claims.put("id", id);
		claims.put("meta_header", metaHeader);
		claims.put("request_type", "get_user_info");
		claims.put("security_header", getSecurityHeader());
		return sendJWT(claims);
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
	
	/**
	 * Sends the API request to PingID.
	 *
	 * <p>You'll notice that for REST APIs, this is fairly unconventional (ot least in my experience). The app by
	 * default uses gzip encoding (except on activation), then it wraps it into a JWT that's self-signed by the device's
	 * private key. On top of this, most requests have signature fields attached to them where you take the entire JSON
	 * body of the request, sign it, and place it as an additional property. Incredibly over-engineered.</p>
	 *
	 * @return JSON object representing the response from the server
	 * @throws RuntimeException if something goes wrong
	 */
	private JsonObject sendRequest(String body, String... headers)
	{
		// Collect headers
		Map<String, String> map = new HashMap<>();
		
		// Default headers, can be overridden
		map.put("Accept", "application/json");
		map.put("Content-Type", "application/json; charset=utf-8");
		map.put("jwt", "false");
		
		for(int i = 0; i < headers.length; i += 2)
		{
			map.put(headers[i], headers[i + 1]);
		}
		
		var builder = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access"));
		map.forEach(builder::header);
		
		// Everything we're using PingID for uses POST requests
		// Send request asynchronously
		HttpRequest request = builder.POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
		
		try(HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).connectTimeout(Duration.ofSeconds(10)).build())
		{
			HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
			
			String encoding = response.headers().firstValue("content-encoding").orElse("").toLowerCase();
			InputStream bodyStream = encoding.equals("gzip") ? new GZIPInputStream(response.body()) : response.body();
			
			String responseBody = new String(bodyStream.readAllBytes(), StandardCharsets.UTF_8);
			
			// Decode JWT payload
			String[] parts = responseBody.split("\\.");
			
			if(parts.length != 3)
			{
				throw new IOException("Response is not a valid JWT: \"" + responseBody + "\"");
			}
			
			String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
			JsonObject jsonResponse = JsonParser.parseString(payloadJson).getAsJsonObject();
			
			System.out.println("Response: " + jsonResponse);
			
			if(jsonResponse.get("response_status").getAsInt() != 0)
				throw new IOException("Server responded with an error: " + jsonResponse);
			
			return jsonResponse;
		} catch(Exception e)
		{
			// lazily wrap
			throw new RuntimeException(e);
		}
	}
	
	private JsonObject sendJWT(HashMap<String, Object> claims)
	{
		String jwt = Jwts.builder().header().and()
				// PingID also includes a separate signature within the JWT which baffles me
				// This app has a ridiculous amount of client-side protections
				.claims(claims)
				.claim("signature", createSignature("SHA1withRSA", gson.toJson(claims).getBytes(), deviceKeyPair.getPrivate()))
				.signWith(deviceKeyPair.getPrivate())
				.compact();
		
		return sendRequest(jwt, "Accept", "application/json", "Accept-Encoding", "gzip", "Content-Type", "application/json; charset=utf-8", "jwt", "true");
	}
}
