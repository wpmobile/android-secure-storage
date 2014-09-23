package com.worldpay.secure;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

interface SecureInterface {

	/**
	 * Encrypt the specified text.
	 * 
	 * @param text
	 *            : The data that has to be encrypted.
	 * @param ivInt
	 *            : The Initialization Vector Number that is used for encrypt
	 *            the text.
	 * @return The encrypted text
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	String encrypt(String text, int ivInt) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException;

	/**
	 * Encrypt the specified text using the initial generated IV.
	 * 
	 * @param text
	 *            : The data that has to be encrypted.
	 * @param ivInt
	 *            : The Initialization Vector Number that is used for encrypt
	 *            the text.
	 * @return The encrypted text
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	String encrypt(String text) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException;

	/**
	 * Decrypt the encrypted text.
	 * 
	 * @param text
	 *            : The encrypted text to be decrypted.
	 * @param ivInt
	 *            : The Initialization Vector Number which is used for decrypt
	 *            the text.
	 * @return The original text.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	String decrypt(String text, int ivInt) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException;

	/**
	 * Decrypt the encrypted text using the initial generated IV.
	 * 
	 * @param text
	 *            : The encrypted text to be decrypted.
	 * @return The original text.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	String decrypt(String text) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException;

	/**
	 * Clear all persisted data to do with the secure library.
	 */
	void clearAll();
}
