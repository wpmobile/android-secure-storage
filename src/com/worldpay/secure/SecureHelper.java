package com.worldpay.secure;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Base64;

/**
 * Provides the necessary methods to help in data encryption and decryption.
 * <p>
 * Copyright : Copyrights with WorldPay
 */
public final class SecureHelper {

	private static final String FILE_NAME_RANDOM_NO = "SP_SECURE";
	private static final String FILE_NAME_IV = "SP_IV";
	private static final String KEY_IV = "IV_";
	private static final String ALIAS_RANDOM_NO = "RANDOM_NO";
	private static final String SP_DIRECTORY = "/shared_prefs/";
	private static final String SP_FILE_EXTENSION = ".xml";
	private static final int TOTAL_NO_OF_IV = 10;

	private FileInputStream fileInputStream = null;
	private KeyStore keyStore = null;
	private KeyGenerator keyGenerator = null;
	private SecretKey secretKey = null;
	private Cipher cipher = null;
	private byte[] ivSpec = null;
	private Context context = null;

	/**
	 * Create a new instance of {@link SecureHelper}.
	 * 
	 * @param ctx
	 *            :Context of calling activity.
	 * @param cipher
	 *            : cipher object of calling activity.
	 * @return None.
	 */
	public SecureHelper(Context ctx, Cipher cipher) {
		try {
			this.context = ctx;
			this.cipher = cipher;
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Prevent from class deserialization.
	 */
	private void readObject(ObjectInputStream in) throws java.io.IOException {
		throw new java.io.IOException("Class cannot be deserialized");
	}

	/**
	 * Prevent from object serialization.
	 */
	private void writeObject(ObjectOutputStream out) throws java.io.IOException {
		throw new java.io.IOException("Object cannot be serialized");
	}

	/**
	 * Prevent from class clonable.
	 */
	@SuppressWarnings("checkstyle:redundantmodifier")
	@Override
	public final Object clone() throws java.lang.CloneNotSupportedException {
		throw new java.lang.CloneNotSupportedException();
	}

	/**
	 * Generation of AES key.
	 * 
	 * @param algo
	 *            : Name of the Algorithm.
	 * @return None.
	 */
	@SuppressLint("TrulyRandom")
	private void generateKey(String algo) {
		try {
			// Get the KeyGenerator
			keyGenerator = KeyGenerator.getInstance(algo);

			// initiate the 128 bit AES key
			keyGenerator.init(128);

			// Generate the secret key
			secretKey = keyGenerator.generateKey();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Generation of keystore associated with Algorithm, Alias Name, Keystore
	 * Name, Keystore Password and context of calling activity.
	 * 
	 * @param algorithm
	 *            :Name of Algorithm.
	 * @param aliasName
	 *            : Alias name will refer key.
	 * @param name
	 *            : Name of keystore file.
	 * @param password
	 *            : Password of keystore file.
	 * @return None.
	 */
	protected void generateKeyStore(String algorithm, String aliasName, String name, char[] password) {
		FileOutputStream fileOutputStream = null;

		try {
			generateKey(algorithm);
			keyStore.load(null, password);
			storeKey(aliasName, password);

			if (fileOutputStream == null) {
				fileOutputStream = context.openFileOutput(name, 0);
			}

			keyStore.store(fileOutputStream, password);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (fileOutputStream != null) {
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Retrieve the key from keystore.
	 * 
	 * @param alias
	 *            : The alias for the key.
	 * @param password
	 *            : The password of the keystore.
	 * @param name
	 *            : Name of the keystore file.
	 * @return key.
	 */
	protected Key getKey(String alias, char[] password, String name) {
		Key key = null;
		fileInputStream = null;

		try {
			fileInputStream = context.openFileInput(name);
			keyStore.load(fileInputStream, password);
			key = keyStore.getKey(alias, password);

		} catch (Exception e) {
			e.printStackTrace();

		} finally {
			if (fileInputStream != null) {
				try {
					fileInputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return key;
	}

	/**
	 * Associates the given alias with the password.
	 * 
	 * @param alias
	 *            : The alias for the key.
	 * @param password
	 *            : The password of the keystore.
	 * @return None.
	 */
	private void storeKey(String alias, char[] password) {
		try {
			keyStore.setKeyEntry(alias, secretKey, password, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * It will check whether keystore is exist or not. true if exist and false
	 * if not.
	 * 
	 * @param filename
	 *            : Name of keystore file.
	 * @return Boolean status.
	 */
	protected boolean isKeyStoreExist(String filename) {
		fileInputStream = null;
		try {
			fileInputStream = context.openFileInput(filename);
			return fileInputStream != null;
		} catch (Exception e) {
			return false;
		} finally {
			try {
				if (fileInputStream != null) {
					fileInputStream.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Convert into hex string.
	 * 
	 * @param data
	 *            : Byte array which is use to convert into hex string.
	 * @return hex String.
	 */
	protected String byteArrayToHexString(byte[] data) {
		StringBuffer strbuf = null;

		try {
			if (data != null && data.length > 0) {
				strbuf = new StringBuffer(data.length * 2);
			}

			int i;
			for (i = 0; i < data.length; i++) {
				if ((data[i] & 0xff) < 0x10) {
					strbuf.append("0");
				}
				strbuf.append(Long.toString(data[i] & 0xff, 16));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return strbuf.toString();
	}

	/**
	 * Convert hex string to byte array.
	 * 
	 * @param hexString
	 *            : The hex string which is use to convert into byte array.
	 * @return Byte array .
	 */
	protected byte[] hexStringToByteArray(String hexString) {
		int len = 0;
		byte[] data = null;

		if (!TextUtils.isEmpty(hexString)) {
			len = hexString.length();
			try {
				if (len >= 0) {
					data = new byte[len / 2];
					for (int i = 0; i < len; i += 2) {
						data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
					}
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return data;
	}

	/**
	 * Returns the random generated password.
	 * 
	 * @param None
	 * 
	 * @return Alpha numeric string.
	 */
	private String generateRandomNumber() {
		return Long.toHexString(new SecureRandom().nextLong());
	}

	/**
	 * Takes base64 encrypted string as a parameter and returns sha512 encrypted
	 * string.
	 * 
	 * @param encrypedValue
	 *            : base64 encrypted string .
	 * @return sha512 encrypted string
	 */
	private String generateSHA512(String encrypedValue) {
		byte[] hash = null;
		MessageDigest sha = null;
		try {
			sha = MessageDigest.getInstance("SHA-512");
			hash = sha.digest(encrypedValue.getBytes());
		} catch (NoSuchAlgorithmException ne) {
			ne.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			sha = null;
		}
		return byteArrayToHexString(hash);
	}

	/**
	 * Generates a random number and stores it in shared preferences if it is
	 * not already present.
	 * 
	 * @return random number character array
	 */
	protected char[] getStoredRandomNumber() {
		char[] storeRandomNumber = null;
		SharedPreferences sharedPreferences = null;
		SharedPreferences.Editor editor = null;
		String sharedPrefRandomNoStr = null;
		String randomNumber = null;

		try {
			sharedPreferences = context.getSharedPreferences(FILE_NAME_RANDOM_NO, Context.MODE_PRIVATE);
			sharedPrefRandomNoStr = sharedPreferences.getString(ALIAS_RANDOM_NO, null);

			// Set stored random number
			if (!TextUtils.isEmpty(sharedPrefRandomNoStr)) {
				storeRandomNumber = sharedPrefRandomNoStr.toCharArray();
			}

			// Generate new random number
			else {
				editor = sharedPreferences.edit();
				randomNumber = generateRandomNumber();
				storeRandomNumber = randomNumber.toCharArray();
				editor.putString(ALIAS_RANDOM_NO, randomNumber);

				if (isSDKVersionLessThanGingerBread()) {
					editor.commit();
				} else {
					editor.apply();
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			sharedPreferences = null;
			editor = null;
			sharedPrefRandomNoStr = null;
			randomNumber = null;
		}

		return storeRandomNumber;
	}

	/**
	 * This method calculates and return the first 8 odd digits in string
	 * format.
	 * 
	 * @param completeString
	 *            : A string
	 * 
	 * @return A string
	 */
	private String first8OddDigit(String completeString) {
		StringBuilder sbFirst8OddDigit = null;
		StringBuilder sbCompleteString = null;
		try {
			sbFirst8OddDigit = new StringBuilder();
			sbCompleteString = new StringBuilder(completeString.toString().trim());
			if (completeString != null && completeString.length() <= 15) {
				int noToBeAppend = (16 - completeString.length() % 16);
				for (int k = 0; k < noToBeAppend; k++) {
					sbCompleteString.append(0);
				}
			}
			for (int i = 0; i < 16; i++) {
				if (i % 2 != 1) {
					sbFirst8OddDigit.append(sbCompleteString.charAt(i));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return sbFirst8OddDigit.toString().trim();
	}

	/**
	 * This method calculates and return the keystore password from the random
	 * number.
	 * 
	 * @param randomNumber
	 *            : A string
	 * 
	 * @return the password string
	 */
	protected String generatePassword(String randomNumber) {
		String first8Odd = null;
		String encryptedValue = null;
		String sha512str = null;

		try {
			encryptedValue = Base64.encodeToString(randomNumber.getBytes(), Base64.DEFAULT);
			sha512str = generateSHA512(encryptedValue);
			first8Odd = first8OddDigit(sha512str);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return first8Odd;
	}

	/**
	 * This method Generates Initialization Vectors.
	 * 
	 * @return None
	 */
	protected void generateIV() {
		String[] strIV = new String[TOTAL_NO_OF_IV];
		try {
			for (int i = 0; i < TOTAL_NO_OF_IV; i++) {
				ivSpec = new SecureRandom().generateSeed(cipher.getBlockSize());
				strIV[i] = byteArrayToHexString(ivSpec);
			}
			storeIV(strIV);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			strIV = null;
		}

	}

	/**
	 * This method stores Initialization Vectors in shared preferences.
	 * 
	 * @param ivArray
	 *            : String array contains IV values.
	 * @return None
	 */
	private void storeIV(String[] ivArray) {
		SharedPreferences sharedPreferences = null;
		SharedPreferences.Editor editor = null;

		try {
			sharedPreferences = context.getSharedPreferences(FILE_NAME_IV, Context.MODE_PRIVATE);
			editor = sharedPreferences.edit();
			for (int i = 0; i < ivArray.length; i++) {
				editor.putString(KEY_IV + i, ivArray[i]);
			}

			if (isSDKVersionLessThanGingerBread()) {
				editor.commit();
			} else {
				editor.apply();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			sharedPreferences = null;
			editor = null;
		}
	}

	/**
	 * This method returns Initialization Vector which is stored in shared
	 * preference.
	 * 
	 * @param ivNo
	 *            : Initialization Vector number which you want to get.
	 * @return Initialization Vector.
	 */
	protected String getIV(int ivNo) {
		SharedPreferences sharedPreferences = null;
		String sharedPrefText = null;

		try {
			int ivInt = (ivNo % 10);
			sharedPreferences = context.getSharedPreferences(FILE_NAME_IV, Context.MODE_PRIVATE);
			for (int i = 0; i < TOTAL_NO_OF_IV; i++) {
				if (ivInt == i) {
					sharedPrefText = sharedPreferences.getString(KEY_IV + i, null);
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			sharedPreferences = null;
		}

		return sharedPrefText;
	}

	/**
	 * Check for existence of IV based on shared preference.
	 * 
	 * @return true if exist otherwise false.
	 */
	protected boolean isIVExist() {
		String destPath = context.getFilesDir().getPath();
		destPath = destPath.substring(0, destPath.lastIndexOf("/")) + SP_DIRECTORY + FILE_NAME_IV + SP_FILE_EXTENSION;
		File f = new File(destPath);
		return f.exists();
	}

	/**
	 * Method gives the status of device sdk version.
	 * 
	 * @return boolean status.
	 */
	private boolean isSDKVersionLessThanGingerBread() {
		return android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.GINGERBREAD;
	}
}
