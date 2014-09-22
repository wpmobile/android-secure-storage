package com.worldpay.secure;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.content.Context;
import android.text.TextUtils;

/**
 * This class is used to provide sensitive data security in android applications
 * by providing convenient methods to encrypt and decrypt the sensitive data.
 * <p>
 * Copyright : Copyrights with WorldPay
 */

public final class SecureStorage implements SecureInterface {

	private static final String KEYSTORE_FILENAME = "Secure.keystore";
	private static final String KEY_ALIAS_NAME = "";
	private static final String ALGORITHM = "AES";
	private static final String STORAGE_CIPHER = "AES/CBC/PKCS5Padding";

	private char[] keyStorePassword = null;
	private Cipher cipher = null;
	private SecretKeySpec secretKeySpec = null;
	private SecureHelper secureHelper = null;

	public SecureStorage(Context context) {
		byte[] raw = null;
		char[] storedRandomNumber = null;

		try {
			cipher = Cipher.getInstance(STORAGE_CIPHER);
			secureHelper = new SecureHelper(context, cipher);

			storedRandomNumber = secureHelper.getStoredRandomNumber();

			if (storedRandomNumber != null) {
				keyStorePassword = secureHelper.generatePassword(new String(storedRandomNumber)).toCharArray();

				if (!secureHelper.isKeyStoreExist(KEYSTORE_FILENAME)) {
					secureHelper.generateKeyStore(ALGORITHM, KEY_ALIAS_NAME, KEYSTORE_FILENAME, keyStorePassword);
				}

				// Checking for existence of IV based on shared preference.
				if (!secureHelper.isIVExist()) {
					secureHelper.generateIV();
				}

				// Generate the secret key spec
				raw = secureHelper.getKey(KEY_ALIAS_NAME, keyStorePassword, KEYSTORE_FILENAME).getEncoded();
				secretKeySpec = new SecretKeySpec(raw, ALGORITHM);
			}

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			raw = null;
			storedRandomNumber = null;
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
	 * Encrypt the specified text.
	 * 
	 * @param text
	 *            : The data that has to be encrypted.
	 * @param ivInt
	 *            : The Initialization Vector Number that is used for encrypt
	 *            the text.
	 * 
	 * 
	 * @return Encrypted data.
	 * @throws Exception
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	@Override
	public String encrypt(String text, int ivInt) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		byte[] encryptedEncodedBytes = null;
		byte[] fromHextoByteArray = null;
		IvParameterSpec ivParam = null;

		try {
			String initVectorFromPrefs = secureHelper.getIV(ivInt);
			fromHextoByteArray = secureHelper.hexStringToByteArray(initVectorFromPrefs);

			if (fromHextoByteArray != null) {
				ivParam = new IvParameterSpec(fromHextoByteArray);
				cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParam);

				if (!TextUtils.isEmpty(text)) {
					encryptedEncodedBytes = cipher.doFinal(text.getBytes());
					return secureHelper.byteArrayToHexString(encryptedEncodedBytes);
				} else {
					throw new IllegalArgumentException("Original text cannot be blank");
				}

			} else {
				throw new IllegalArgumentException("Random number for initialization vector is not found");
			}
		} finally {
			encryptedEncodedBytes = null;
			fromHextoByteArray = null;
			ivParam = null;
		}
	}

	/**
	 * Decrypt the encrypted text.
	 * 
	 * @param text
	 *            : The encrypted text to be decrypted.
	 * @param ivInt
	 *            : The Initialization Vector Number which is used for decrypt
	 *            the text.
	 * 
	 * @return Original data.
	 * @throws Exception
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	@Override
	public String decrypt(String text, int ivInt) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		byte[] decodedBytes = null;
		byte[] fromHextoByteArray = null;
		IvParameterSpec ivParam = null;
		String ivFromSP = null;

		try {
			ivFromSP = secureHelper.getIV(ivInt);

			fromHextoByteArray = secureHelper.hexStringToByteArray(ivFromSP);
			if (fromHextoByteArray != null) {
				ivParam = new IvParameterSpec(fromHextoByteArray);
				cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParam);

				if (text != null && text.toString().trim().length() > 0) {
					decodedBytes = cipher.doFinal(secureHelper.hexStringToByteArray(text));
					return new String(decodedBytes);
				}

				throw new IllegalArgumentException("Encrypted text cannot be blank");

			} else {
				throw new IllegalArgumentException("Random number for initialization vector is not found");
			}

		} finally {
			decodedBytes = null;
			ivParam = null;
			ivFromSP = null;
			fromHextoByteArray = null;
		}
	}
}
