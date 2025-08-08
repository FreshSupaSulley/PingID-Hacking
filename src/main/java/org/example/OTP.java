package org.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class OTP {
	
	private static final long[] f9897b = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};
	
	/* renamed from: c, reason: collision with root package name */
	public static final byte f7523c = -1;
	
	public static final byte f7868c = Byte.MAX_VALUE;
	
	public static String a(byte[] secret, long movingFactor, int codeDigits) throws Exception {
		// Weirdly random thing I found online works but the reverse apk code doesn't
		// actually that's not that weird lmao
		return OTP2.generateOTP(secret, movingFactor, codeDigits, false, -1);
//		return b(secret, movingFactor, codeDigits, false, -1);
	}
	
	public static String b(byte[] secret, long movingFactor, int codeDigits, boolean addChecksum, int truncationOffset) throws Exception {
		String string;
		int i = addChecksum ? codeDigits + 1 : codeDigits;
		byte[] bArr = new byte[8];
		long j = movingFactor;
		for (int i2 = 7; i2 >= 0; i2--) {
			bArr[i2] = (byte) (j & 255);
			j >>= 8;
		}
		byte[] bArrV = v(secret, bArr);
		int i4 = bArrV[bArrV.length - 1] & 15;
		if (truncationOffset >= 0 && truncationOffset < bArrV.length - 4) {
			i4 = truncationOffset;
		}
		int i5 = (bArrV[i4 + 3] & f7523c) | ((bArrV[i4] & f7868c) << 24) | ((bArrV[i4 + 1] & f7523c) << 16) | ((bArrV[i4 + 2] & f7523c) << 8);
		int iA = (int) ((i5 % f9897b[codeDigits]) & (-1));
		if (addChecksum) {
			iA = addChecksum(iA, codeDigits) + (iA * 10);
		}
		string = Integer.toString(iA);
		while (string.length() < i) {
			string = "0" + string;
		}
		
		return string;
	}
	
	public static byte[] v(byte[] keyBytes, byte[] text) throws Exception {
		Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA1", "BC");
		} catch (NoSuchAlgorithmException unused) {
			mac = Mac.getInstance("HMAC-SHA-1", "BC");
		}
		mac.init(new SecretKeySpec(keyBytes, "RAW"));
		return mac.doFinal(text);
	}
	
	private static final int[] f9885d = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};
	
	public static int addChecksum(long num, int digits) {
		boolean z = true;
		int i = 0;
		while (true) {
			int i2 = digits - 1;
			if (digits <= 0) {
				break;
			}
			int i3 = (int) (num % 10);
			num /= 10;
			if (z) {
				i3 = f9885d[i3];
			}
			i += i3;
			z = !z;
			digits = i2;
		}
		int i4 = i % 10;
		return i4 > 0 ? 10 - i4 : i4;
	}
	
}