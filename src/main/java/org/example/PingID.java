package org.example;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.SystemTimeProvider;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.json.JSONObject;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class PingID {
	
	private static final BigInteger MODULUS = new BigInteger("31699142174809458850082382402788043663106991194823033018937598360175543864008929147299064252168453738943971427430573724299451532315792264426805566434465462934418283232907859404393018571514608788370423091472983586618753610753267691204574928448208043716881455949580766738255691280349814402624986309907947002933353231849001791191635190937132539826983405101078519868057148135558938382459177989299888762060399149632192621098665680524371521279226055278689674546320728943602920232032098494228433554236457762609352311775484579991903198376092701627874966808866193660346730954051618204007340985917068527050534376051268966999771");
	private static final BigInteger EXPONENT = new BigInteger("8390693331667715754486841459516999365942117120896479321543860529977649986738710932492645637036975315262074009145244330413121373527140490213833553011610077029080079472402903566194789045414798906819901957357333762132365354876517253966024742836188550565002991548062199230845028067898567303195705479517343037267195140328879700808761291392618146199430046719804491789584673789462898476730059543679735181586708922509533904621815010091105621437823269586493885296838942592259446770902301835233439160257329392427991032084412600737879553876421234934024950683990086122360023203904332094142305147536789666403169204321784566223333");
	
	private static final String serverPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvotTwKvoqyuXgL/IFiHbc0twX55BNh4u/+l0Yz/ieVE81A+S2dhSggVloXuCKz355+jKiDOYQgeGkEuYZnBqK3jbkYpxS83YNED7zAOxGjX6EtalHuJcmqvosrNlcpMj0DbPsfUTw/yLr7VMEqX97suZXMDNiwxQzD5FiiIjcOgVIlyrKKkRIVl3HfaPr+9Dg+dRLveHPK9M869FokounL8iWy7uYINqGwadT28nHCK1sVUjnEj1/UGkkq+/DHpmiRhM2C6GsHcsE1IEC9pBiC8prTVcRXlxBfIJwoqOjGPpWE+VpmFOP2VF4wFRadhB5zJB7L73cKvOyaOdMO0IawIDAQAB";
	
	private static LinkedHashMap<String, Object> metaHeader;
	
	private KeyPair deviceKeyPair;
	
	static
	{
		// Build the JSON payload using org.json
		metaHeader = new LinkedHashMap<String, Object>();
		metaHeader.put("api_version", "18.0");
		metaHeader.put("app_version", "1.23.0(13063)");
		metaHeader.put("is_device_lock", true);
		metaHeader.put("device_type", "Android");
		metaHeader.put("is_biometrics_supported", false); // wtf does this mean? fingerprint?
		metaHeader.put("locale", "en-US");
		metaHeader.put("disabled_location", true);
		metaHeader.put("pingid_mdm_token", "");
		metaHeader.put("model", "AOSP on IA Emulator");
		metaHeader.put("network_type", "wifi");
		metaHeader.put("networks_info", "base64:d3M6e2E6IHcsIHdkOnt7c3NpZDo8dW5rbm93biBzc2lkPixoc3NpZDp0cnVlLG1hYzoiMDI6MDA6MDA6MDA6MDA6MDAiLHJzc2k6LTUwLGlwOjQ4ODAxOTg0LGxzOjEzfX0sd2U6IFtdfSxtczp7cFQ6IEdTTSxuY3M6IHt9fQ==");
		metaHeader.put("os_version", "9");
		metaHeader.put("pretty_model", "google AOSP on IA Emulator");
		metaHeader.put("is_root", false);
		metaHeader.put("vendor", "Google");
	}
	
	public static void writePEMFile() throws Exception
	{
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(MODULUS, EXPONENT);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		
		byte[] encoded = publicKey.getEncoded();
		
		String base64Encoded = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded);
		String pem = "-----BEGIN PUBLIC KEY-----\n" + base64Encoded + "\n-----END PUBLIC KEY-----";
		
		try(FileWriter writer = new FileWriter("pingid.pem"))
		{
			writer.write(pem);
		}
		
		System.out.println("PEM public key written to pingid.pem");
	}
	
	// FIRST STEP
	public JSONObject verifyActivationCode(String activationCode) throws Exception
	{
		// Build the JSON payload using org.json
		JSONObject body = new JSONObject();
		body.put("activation_code", activationCode);
		body.put("finger_print", "ZXVFM29LWEF5WmdONlAxbWxKVkE=");
		body.put("device_type", "Android");
		body.put("is_primary", false);
		body.put("meta_header", metaHeader);
		body.put("request_type", "verify_activation_code");
		
		JSONObject fullPayload = new JSONObject();
		fullPayload.put("body", body);
		fullPayload.put("signature", "no_signature");
		
		// Build request
		// removed the gzip header
		// jwt true or false doesn't seem to make a difference
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Content-Type", "application/json; charset=utf-8").header("jwt", "false").POST(HttpRequest.BodyPublishers.ofString(fullPayload.toString(), StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	// SECOND STEP
	// Sends as encoeded JWT
	public JSONObject provision(JSONObject data) throws Exception
	{
		// I assume the device generates a random key
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048); // Key size
		deviceKeyPair = generator.generateKeyPair();
		PrivateKey privateKey = deviceKeyPair.getPrivate();
		PublicKey publicKey = deviceKeyPair.getPublic();
		
		// enc_count_reg_id
		byte[] bArrDecode = Base64.getDecoder().decode(serverPubKey.getBytes(StandardCharsets.UTF_8));
		StringBuilder sb = new StringBuilder();
		sb.append(w(m()));
		
		// Build the JSON payload using org.json
		LinkedHashMap<String, Object> hashMap = new LinkedHashMap<String, Object>();
		hashMap.put("finger_print", "ZXVFM29LWEF5WmdONlAxbWxKVkE=");
		hashMap.put("id", data.get("id"));
		hashMap.put("device_type", "Android");
		hashMap.put("enc_count_reg_id", g(bArrDecode, sb.toString()));
		hashMap.put("public_key", x(publicKey)); // is this right?
		hashMap.put("pushless", true);
		hashMap.put("session_id", data.get("session_id"));
		hashMap.put("meta_header", metaHeader);
		hashMap.put("request_type", "provision");
		
		// registration ID, might need to be filled idk. Worth logging in smali to find out
		//		sb.append("");
		//		Instant now = Instant.now();
		String jwt = Jwts.builder().header().and()
				// They also include a signature within the JWT
				.claims(hashMap)
				.claim("signature", f("SHA1withRSA", new JSONObject(hashMap).toString().getBytes(), getAppKey()))
				.signWith(privateKey)
				.compact();
		
		System.out.println("Sending " + jwt);
		
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Content-Type", "application/json; charset=utf-8").header("jwt", "true").POST(HttpRequest.BodyPublishers.ofString(jwt, StandardCharsets.UTF_8)).build();
		return sendRequest(request);
	}
	
	public static String f(String algorithm, byte[] bytesTotal, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException
	{
		Signature signature = Signature.getInstance(algorithm);
		signature.initSign(privateKey);
		signature.update(bytesTotal);
		return new String(Base64.getEncoder().encode(signature.sign()), StandardCharsets.UTF_8);
	}
	
	public static String x(PublicKey publicKey)
	{
		return new String(Base64.getEncoder().encode(publicKey.getEncoded()));
	}
	
	public static final long f9881b = 72057594037927935L;
	
	public static long m() throws Exception
	{
		return SecureRandom.getInstance("SHA1PRNG").nextLong() & f9881b;
	}
	
	public static String w(long number)
	{
		String hexString = Long.toHexString(number);
		return hexString.length() < 15 ? h(hexString, '0', 16) : hexString.substring((hexString.length() - 16) - 1, hexString.length() - 1);
	}
	
	private static String h(String strNextLong, char c2, int length)
	{
		while(strNextLong.length() < length)
		{
			strNextLong = c2 + strNextLong;
		}
		return strNextLong;
	}
	
	public static String g(byte[] paramArrayOfbyte, String paramString) throws Exception
	{
		return e(u(paramArrayOfbyte), paramString);
	}
	
	public static String e(PublicKey publicKey, String encryptionCandidate) throws Exception
	{
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());//, "BC");
		cipher.init(1, publicKey);
		return new String(Base64.getEncoder().encode(cipher.doFinal(encryptionCandidate.getBytes())));
	}
	
	public static PublicKey u(byte[] publicKeyBytes) throws Exception
	{
		return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
	}
	
	public void finalizeOnboarding() throws CodeGenerationException
	{
		JSONObject body = new JSONObject();
		body.put("finger_print", "ZXVFM29LWEF5WmdONlAxbWxKVkE=");
		body.put("id", "uuid:07d837fc-f5e6-d7f0-07d8-37fcf5e6d7f0");
		body.put("nickname", "base64:aW0gZ29ubmEgdG91Y2ggeW91");
		body.put("session_id", "acts_ohi_FHgxNh5WgZBYypww6WonLM4F8S2r8BjrP7d5hVU4KV0");
		
		body.put("meta_header", metaHeader);
		
		JSONObject securityHeader = new JSONObject();
		securityHeader.put("local_fallback_data_hash", "");
		securityHeader.put("finger_print", "WWN2NlJ0V0xUZ2xJT2Y5bWFXRGc=");
		securityHeader.put("id", "uuid:07d837fc-f5e6-d7f0-07d8-37fcf5e6d7f0");
		securityHeader.put("ts", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"))); // i assume this is time now?
		securityHeader.put("tz", OffsetDateTime.now().getOffset().getId().replace("Z", "+0000").replace(":", ""));
		
		CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA256); // or SHA256, SHA512
		SystemTimeProvider timeProvider = new SystemTimeProvider();
		
		String secret = "BP26TDZUZ5SVPZJRIHCAUVREO5EWMHHV";
		long time = timeProvider.getTime();
		
		String totpCode = codeGenerator.generate(secret, time); // typically 6-digit string
		
		body.put("security_header", securityHeader);
		body.put("request_type", "finalize_onboarding");
		
		JSONObject fullPayload = new JSONObject();
		fullPayload.put("body", body);
		fullPayload.put("signature", "no_signature");
		
		// Create HTTP client with redirect handling
		HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).connectTimeout(Duration.ofSeconds(10)).build();
		
		// Build request
		// removed the gzip header
		// jwt true or false doesn't seem to make a difference
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://idpxnyl3m.pingidentity.com/AccellServer/phone_access")).header("Accept", "application/json").header("Content-Type", "application/json; charset=utf-8").header("jwt", "false").POST(HttpRequest.BodyPublishers.ofString(fullPayload.toString(), StandardCharsets.UTF_8)).build();
		
		// Send request asynchronously
		CompletableFuture<Void> future = client.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream()).thenAcceptAsync(response ->
		{
			int statusCode = response.statusCode();
			System.out.println("Response code: " + statusCode);
			
			try(var is = response.body())
			{
				String responseBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
				System.out.println("Raw response body: " + responseBody);
				
				// Decode JWT payload
				String[] parts = responseBody.split("\\.");
				if(parts.length == 3)
				{
					String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
					System.out.println("Decoded JWT payload: " + payloadJson);
				}
				else
				{
					System.out.println("Response is not a valid JWT");
				}
				
			} catch(Exception e)
			{
				System.err.println("Failed to read or decode response: " + e.getMessage());
			}
		});
		
		// Wait (optional if you're in a main method)
		future.join();
		
	}
	
	private JSONObject sendRequest(HttpRequest request) throws Exception
	{
		// Send request asynchronously
		HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).connectTimeout(Duration.ofSeconds(10)).build();
		HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
		int statusCode = response.statusCode();
		System.out.println("Response code: " + statusCode);
		
		try(var is = response.body())
		{
			String responseBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
			System.out.println("Raw response body: " + responseBody);
			
			// Decode JWT payload
			String[] parts = responseBody.split("\\.");
			if(parts.length == 3)
			{
				String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
				System.out.println("Decoded JWT payload: " + payloadJson);
				return new JSONObject(payloadJson);
			}
			else
			{
				throw new Exception("Response is not a valid JWT");
			}
		}
	}
	
	public PublicKey getAppKeyFromFile(String pemFilePath) throws Exception
	{
		// Read all bytes from the PEM file
		String pem = new String(Files.readAllBytes(new File(pemFilePath).toPath()));
		
		// Remove PEM headers and decode Base64
		String base64 = pem
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");
		
		byte[] keyBytes = Base64.getDecoder().decode(base64);
		
		// Generate public key from X.509 encoded key spec
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}
	
	private PrivateKey getAppKey() throws Exception
	{
		return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(MODULUS, EXPONENT));
	}
	
	public static void main(String[] args) throws Exception
	{
		String activationCode = "3106 8538 5722".replace(" ", "");
		
		// First activate the device
		var ping = new PingID();
		JSONObject init = ping.verifyActivationCode(activationCode);
		ping.provision(init);
		// Now
	}
}
