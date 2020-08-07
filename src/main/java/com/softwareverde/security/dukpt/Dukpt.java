package com.softwareverde.security.dukpt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * <p>The Dukpt class acts a name-space for the Derived
 * Unique Key-Per-Transaction (Dukpt) standard using the
 * Data Encryption Standard, DES, (often referred to in practice as
 * "DEA", for Data Encryption Algorithm).
 *
 * <p>The functions provided attempt to aid a user in performing
 * encryption, decryption, and possibly more complex operations
 * using these.
 *
 * <p>There is also a set of conversion methods to hopefully make
 * the class even easier to interface with.  Many of these involve
 * the BitSet wrapper of java.util.BitSet which was designed to have
 * a proper "length()" function as Java's BitSet does not have a method
 * that returns the constructed length of the BitSet, only its actual
 * size in memory and its "logical" size (1 + the index of the left-most 1).
 *
 * <p>To further augment to the security of Dukpt, two "oblivate()" methods are
 * included, one for the extended BitSet and one for byte arrays.  These
 * overwrite their respective arguments with random data as supplied by
 * java.secruty.SecureRandom to ensure that their randomness is
 * cryptographically strong.  The default number of overwrites is specified by
 * the static constant NUM_OVERWRITES but the user can supply a different number
 * should they desire the option.
 *
 * @author Software Verde: Andrew Groot
 * @author Software Verde: Josh Green
 */
public final class Dukpt {
	public static final int NUM_OVERWRITES = 3;

	public static final String KEY_REGISTER_BITMASK = "C0C0C0C000000000C0C0C0C000000000";
	private static final BitSet DEFAULT_KEY_REGISTER_BITMASK = toBitSet(toByteArray(KEY_REGISTER_BITMASK));

	public static final String DATA_VARIANT_BITMASK = "0000000000FF00000000000000FF0000";
	public static final String MAC_VARIANT_BITMASK  = "000000000000FF00000000000000FF00";
	public static final String PIN_VARIANT_BITMASK  = "00000000000000FF00000000000000FF";
	private static final BitSet DEFAULT_VARIANT_BITMASK = toBitSet(toByteArray(PIN_VARIANT_BITMASK));

	/**
	 * <p>Computes a DUKPT (Derived Unique Key-Per-Transaction).
	 *
	 * <p>This is derived from the Base Derivation Key, which should
	 * have been injected into the device and should remain secret,
	 * and the Key Serial Number which is a concatenation of the
	 * device's serial number and its encryption (or transaction)
	 * counter.
	 *
	 * @see #getIpek
	 * @param baseDerivationKey The Base Derivation Key
	 * @param keySerialNumber The Key Serial Number
	 * @return A unique key for this set of data.
	 * @throws Exception
	 */
	public static byte[] computeKey(byte[] baseDerivationKey, byte[] keySerialNumber) throws Exception {
		return computeKey(baseDerivationKey, keySerialNumber, DEFAULT_KEY_REGISTER_BITMASK, DEFAULT_VARIANT_BITMASK);
	}

	/**
	 * <p>Computes a DUKPT (Derived Unique Key-Per-Transaction) using the provided key register bitmask and data variant
	 * bitmask.</p>
	 *
	 * @see #computeKey(byte[], byte[])
	 * @param baseDerivationKey
	 * @param keySerialNumber
	 * @param keyRegisterBitmask
	 * @param dataVariantBitmask
	 * @return
	 * @throws Exception
	 */
	protected static byte[] computeKey(byte[] baseDerivationKey, byte[] keySerialNumber, BitSet keyRegisterBitmask, BitSet dataVariantBitmask) throws Exception {
		BitSet bdk = toBitSet(baseDerivationKey);
		BitSet ksn = toBitSet(keySerialNumber);
		BitSet ipek = getIpek(bdk, ksn, keyRegisterBitmask);

		// convert key for returning
		BitSet key = _getCurrentKey(ipek, ksn, keyRegisterBitmask, dataVariantBitmask);
		byte[] rkey = toByteArray(key);

		// secure memory
		obliviate(ksn);
		obliviate(bdk);
		obliviate(ipek);
		obliviate(key);

		return rkey;
	}

	/**
	 * <p>Computes the Initial PIN Encryption Key (Sometimes referred to as
	 * the Initial PIN Entry Device Key).
	 *
	 * <p>Within the function, the transaction counter is removed.
	 * This is because the IPEK should be seen as the Dukpt
	 * (Derived Unique Key-Per-Transaction) corresponding to a brand
	 * new transaction counter (assuming it starts at 0).
	 *
	 * <p>Due to the process under which one key is derived from a subset of
	 * those before it, the IPEK can be used to quickly calculate the
	 * DUKPT for any Key Serial Number, or more specifically, any
	 * encryption count.
	 *
	 * <p>This algorithm was found in Annex A, section 6 on page 69
	 * of the ANSI X9.24-1:2009 document.
	 *
	 * @param key The Base Derivation Key.
	 * @param ksn The Key Serial Number.
	 * @return The Initial PIN Encryption Key
	 * @throws Exception
	 */
	public static BitSet getIpek(BitSet key, BitSet ksn) throws Exception {
		return getIpek(key, ksn, DEFAULT_KEY_REGISTER_BITMASK);
	}

	/**
	 * <p>Computes the Initial PIN Encryption Key using the provided key register bitmask.
	 *
	 * @see #getIpek(BitSet, BitSet)
	 * @param key
	 * @param ksn
	 * @param keyRegisterBitmask
	 * @return
	 * @throws Exception
	 */
	protected static BitSet getIpek(BitSet key, BitSet ksn, BitSet keyRegisterBitmask) throws Exception {
		byte[][] ipek = new byte[2][];
		BitSet keyRegister = key.get(0, key.bitSize());
		BitSet data = ksn.get(0, ksn.bitSize());
		data.clear(59, 80);

		ipek[0] = encryptTripleDes(toByteArray(keyRegister), toByteArray(data.get(0, 64)));

		keyRegister.xor(keyRegisterBitmask);
		ipek[1] = encryptTripleDes(toByteArray(keyRegister), toByteArray(data.get(0, 64)));

		byte[] bipek = concat(ipek[0], ipek[1]);
		BitSet bsipek = toBitSet(bipek);

		// secure memory
		obliviate(ipek[0]);
		obliviate(ipek[1]);
		obliviate(bipek);
		obliviate(keyRegister);
		obliviate(data);

		return bsipek;
	}

	/**
	 * <p>Computes a Dukpt (Derived Unique Key-Per-Transaction) given an IPEK
	 * and Key Serial Number.
	 *
	 * <p>Here, a non-reversible operation is used to find one key from
	 * another.  This is where the transaction counter comes in.  In order
	 * to have the desired number of possible unique keys (over 1 million)
	 * for a given device, a transaction counter size of 20 bits would
	 * suffice.  However, by adding an extra bit and a constraint (that
	 * keys must have AT MOST 9* bits set) the same number of values can be
	 * achieved while allowing a user to calculate the key in at most 9
	 * steps.
	 *
	 * <p>We have reason to believe that is actually 10 bits (as the
	 * sum of the 21 choose i for i from 0 to 9 is only around 700,000 while
	 * taking i from 0 to 10 yields exactly 2^20 (just over 1,000,000) values)
	 * but regardless of the truth, our algorithm is not dependent upon this
	 * figure and will work no matter how it is implemented in the encrypting
	 * device or application.
	 *
	 * <p>This algorithm was found in Annex A, section 3 on pages 50-54
	 * of the ANSI X9.24-1:2009 document.
	 *
	 * @param ipek The Initial PIN Encryption Key.
	 * @param ksn The Key Serial Number.
	 * @return The Dukpt that corresponds to this combination of values.
	 * @throws Exception
	 */
	private static BitSet _getCurrentKey(BitSet ipek, BitSet ksn, BitSet keyRegisterBitmask, BitSet dataVariantBitmask) throws Exception {
		BitSet key = ipek.get(0, ipek.bitSize());
		BitSet counter = ksn.get(0, ksn.bitSize());
		counter.clear(59, ksn.bitSize());

		for (int i = 59; i < ksn.bitSize(); i++) {
			if (ksn.get(i)) {
				counter.set(i);
				BitSet tmp = _nonReversibleKeyGenerationProcess(key, counter.get(16, 80), keyRegisterBitmask);
				// secure memory
				obliviate(key);
				key = tmp;
			}
		}
		key.xor(dataVariantBitmask); // data encryption variant (e.g. To PIN)

		// secure memory
		obliviate(counter);

		return key;
	}

	/**
	 * <p>Creates a new key from a previous key and the right 64 bits of the
	 * Key Serial Number for the desired transaction.
	 *
	 * <p>This algorithm was found in Annex A, section 2 on page 50
	 * of the ANSI X9.24-1:2009 document.
	 *
	 * @param p_key The previous key to be used for derivation.
	 * @param data The data to encrypt it with, usually the right 64 bits of the transaction counter.
	 * @return A key that cannot be traced back to p_key.
	 * @throws Exception
	 */
	private static BitSet _nonReversibleKeyGenerationProcess(BitSet p_key, BitSet data, BitSet keyRegisterBitmask) throws Exception {
		BitSet keyreg = p_key.get(0, p_key.bitSize());
		BitSet reg1 = data.get(0, data.bitSize());
		// step 1: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2.
		BitSet reg2 = reg1.get(0, 64); // reg2 is being used like a temp here
		reg2.xor(keyreg.get(64, 128));   // and here, too, kind of
		// step 2: Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
		reg2 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg2)));
		// step 3: Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
		reg2.xor(keyreg.get(64, 128));
		// done messing with reg2

		// step 4: XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
		keyreg.xor(keyRegisterBitmask);
		// step 5: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
		reg1.xor(keyreg.get(64, 128));
		// step 6: Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
		reg1 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg1)));
		// step 7: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
		reg1.xor(keyreg.get(64, 128));
		// done

		byte[] reg1b = toByteArray(reg1), reg2b = toByteArray(reg2);
		byte[] key = concat(reg1b, reg2b);
		BitSet rkey = toBitSet(key);

		// secure memory
		obliviate(reg1);
		obliviate(reg2);
		obliviate(reg1b);
		obliviate(reg2b);
		obliviate(key);
		obliviate(keyreg);

		return rkey;
	}

	/**
	 * <p>Performs Single DES Encryption.
	 *
	 * @param key The key for encryption.
	 * @param data The data to encrypt.
	 * @param padding When true, PKCS5 Padding will be used.  This is most likely not desirable.
	 * @return The encrypted.
	 * @throws Exception
	 */
	public static byte[] encryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		SecretKey encryptKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key));
		Cipher encryptor;
		if (padding) {
			encryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
		} else {
			encryptor = Cipher.getInstance("DES/CBC/NoPadding");
		}
		encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
		return encryptor.doFinal(data);
	}

	/**
	 * <p>Creates a data key, as described <a href="https://idtechproducts.com/support/technical-blog/id/how-to-decrypt-credit-card-data-part-ii/">here</a>.</p>
	 *
	 * <p>NOTE: for standard usage, the derived key provided to this method must be generated using the {@link #DATA_VARIANT_BITMASK}.
	 *
	 * <p>### The following content is copied from the above-linked page ###</p>
	 *
	 * <h3>Creating Data, PIN, and MAC Key Variants</h3>
	 *
	 * <p>ANSI X9.24 allows a DUKPT key to take on one of three final forms, called variants. The forms are MAC, PIN,
	 * and Data. Let’s defer any discussion of what these various key types are used for in order to concentrate on how
	 * they’re created.
	 *
	 * <p>The starting point for any of the variants is a DUKPT basis key (the derived key that we called curKey in Step
	 * 5 further above). To get the MAC variant, you simply need to XOR the basis key (the “derived key”) with a special
	 * constant:
	 *
	 * <pre>MACkey = derivedKey ^ 0x000000000000FF00000000000000FF00;</pre>
	 *
	 * The PIN variant, likewise, is created in similar fashion, but using a different constant:
	 *
	 * <pre>PINkey = derivedKey ^ 0x00000000000000FF00000000000000FF;</pre>
	 *
	 * The Data variant requires yet another constant:
	 *
	 * <pre>Datakey = derivedKey ^ 0x0000000000FF00000000000000FF0000;</pre>
	 *
	 * For MAC and PIN variants, the XOR operation constitutes the final step in creating the relevant session key. For the Data variant, it’s customary to perform one additional step, involving a one-way hash (to preclude any possibility of someone back-transforming a Data key into a MAC key). In pseudocode:
	 *
	 * <pre>
	 *     // left half:
	 *     var left = des(  EDE3KeyExpand( derivedKey ),
	 * 			    top8bytes( derivedKey ),
	 * 			    true,
	 * 			    CBC,
	 * 			    iv );
	 *
	 *     // right half:
	 *     var right = des( EDE3KeyExpand( derivedKey ),
	 * 			    bottom8bytes( derivedKey ),
	 * 			    true,
	 * 			    CBC,
	 * 			    iv );
	 *
	 * finalDataKey = (left << 64) | right;  // combine halves
	 * </pre>
	 *
	 * <p>In English: First, obtain a 24-byte version of your derived key, by using the EDE3 expansion method.
	 * (This simply means copying the first 8 bytes of a 16-byte key onto the tail end of the key, creating a 24-byte
	 * key in which the first and last 8 bytes are the same.) Use that key to TDES-encrypt the first 8 bytes of your
	 * 16-byte derived key, thereby creating an 8-byte cipher. That’s the left half of the eventual data key. To create
	 * the right half, use the same 24-byte key to encrypt the bottom 8 bytes of the derivedKey. Combine the two 8-byte
	 * ciphers (left and right pieces), and you’re done.
	 *
	 * @param derivedKey
	 * @return
	 */
	public static byte[] toDataKey(final byte[] derivedKey) throws Exception {
		if (derivedKey == null || derivedKey.length != 16) {
			throw new IllegalArgumentException("Invalid key provided: " + (derivedKey == null ? "null" : "length " + derivedKey.length));
		}

		byte[] left = Arrays.copyOfRange(derivedKey, 0, 8);
		byte[] right = Arrays.copyOfRange(derivedKey, 8, 16);

		byte[] leftEncrypted = Dukpt.encryptTripleDes(derivedKey, left);
		byte[] rightEncrypted = Dukpt.encryptTripleDes(derivedKey, right);
		byte[] dataKey = Dukpt.concat(leftEncrypted, rightEncrypted);

		Dukpt.obliviate(left);
		Dukpt.obliviate(right);
		Dukpt.obliviate(leftEncrypted);
		Dukpt.obliviate(rightEncrypted);

		return dataKey;
	}

	/**
	 * <p>Performs Single DES Decryption.
	 *
	 * @param key The key for decryption.
	 * @param data The data to decrypt.
	 * @param padding When true, PKCS5 Padding will be assumed.  This is most likely not desirable.
	 * @return The decrypted data.
	 * @throws Exception
	 */
	public static byte[] decryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		SecretKey decryptKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key));
		Cipher decryptor;
		if (padding) {
			decryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
		} else {
			decryptor = Cipher.getInstance("DES/CBC/NoPadding");
		}
		decryptor.init(Cipher.DECRYPT_MODE, decryptKey, iv);
		return decryptor.doFinal(data);
	}

	/**
	 * <p>Performs Single DEA Encryption without padding.
	 *
	 * @param key The key for encryption.
	 * @param data The data to encrypt.
	 * @return The encrypted data.
	 * @throws Exception
	 */
	public static byte[] encryptDes(byte[] key, byte[] data) throws Exception {
		return encryptDes(key, data, false);
	}

	/**
	 * <p>Performs Single DES Decryption assuming no padding was used.
	 *
	 * @param key The key for decryption.
	 * @param data The data to decrypt.
	 * @return The decrypted data.
	 * @throws Exception
	 */
	public static byte[] decryptDes(byte[] key, byte[] data) throws Exception {
		return decryptDes(key, data, false);
	}

	/**
	 * <p>Performs Triple DES Encryption.
	 *
	 * @param key The key for encryption.
	 * @param data The data to encrypt.
	 * @param padding When true, PKCS5 Padding will be used.  This is most likely not desirable.
	 * @return The encrypted data.
	 * @throws Exception
	 */
	public static byte[] encryptTripleDes(byte[] key, byte[] data, boolean padding) throws Exception {
		BitSet bskey = toBitSet(key);
		BitSet k1, k2, k3;
		if (bskey.bitSize() == 64) {
			// single length
			k1 = bskey.get(0, 64);
			k2 = k1;
			k3 = k1;
		} else if (bskey.bitSize() == 128) {
			// double length
			k1 = bskey.get(0, 64);
			k2 = bskey.get(64, 128);
			k3 = k1;
		} else {
			// triple length
			if (bskey.bitSize() != 192) {
				throw new InvalidParameterException("Key is not 8/16/24 bytes long.");
			}
			k1 = bskey.get(0, 64);
			k2 = bskey.get(64, 128);
			k3 = bskey.get(128, 192);
		}
		byte[] kb1 = toByteArray(k1), kb2 = toByteArray(k2), kb3 = toByteArray(k3);
		byte[] key16 = concat(kb1, kb2);
		byte[] key24 = concat(key16, kb3);

		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		SecretKey encryptKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(key24));
		Cipher encryptor;
		if (padding) {
			encryptor = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		} else {
			encryptor = Cipher.getInstance("DESede/CBC/NoPadding");
		}
		encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
		byte[] bytes = encryptor.doFinal(data);

		// secure memory
		obliviate(k1);
		obliviate(k2);
		obliviate(k3);
		obliviate(kb1);
		obliviate(kb2);
		obliviate(kb3);
		obliviate(key16);
		obliviate(key24);
		obliviate(bskey);

		return bytes;
	}

	/**
	 * <p>Performs Triple DES Decryption.
	 *
	 * @param key The key for decryption.
	 * @param data The data to decrypt.
	 * @param padding When true, PKCS5 Padding will be assumed.  This is most likely not desirable.
	 * @return The decrypted data.
	 * @throws Exception
	 */
	public static byte[] decryptTripleDes(byte[] key, byte[] data, boolean padding) throws Exception {
		BitSet bskey = toBitSet(key);
		BitSet k1, k2, k3;
		if (bskey.bitSize() == 64) {
			// single length
			k1 = bskey.get(0, 64);
			k2 = k1;
			k3 = k1;
		} else if (bskey.bitSize() == 128) {
			// double length
			k1 = bskey.get(0, 64);
			k2 = bskey.get(64, 128);
			k3 = k1;
		} else {
			// triple length
			if (bskey.bitSize() != 192) {
				throw new InvalidParameterException("Key is not 8/16/24 bytes long.");
			}
			k1 = bskey.get(0, 64);
			k2 = bskey.get(64, 128);
			k3 = bskey.get(128, 192);
		}
		byte[] kb1 = toByteArray(k1), kb2 = toByteArray(k2), kb3 = toByteArray(k3);
		byte[] key16 = concat(kb1, kb2);
		byte[] key24 = concat(key16, kb3);

		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		SecretKey encryptKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(key24));
		Cipher decryptor;
		if (padding)
			decryptor = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		else
			decryptor = Cipher.getInstance("DESede/CBC/NoPadding");
		decryptor.init(Cipher.DECRYPT_MODE, encryptKey, iv);
		byte[] bytes = decryptor.doFinal(data);

		// secure memory
		obliviate(k1);
		obliviate(k2);
		obliviate(k3);
		obliviate(kb1);
		obliviate(kb2);
		obliviate(kb3);
		obliviate(key16);
		obliviate(key24);
		obliviate(bskey);

		return bytes;
	}

	/**
	 * <p>Performs Single DEA Encryption without padding.
	 *
	 * @param key The key for encryption.
	 * @param data The data to encrypt.
	 * @return The encrypted data.
	 * @throws Exception
	 */
	public static byte[] encryptTripleDes(byte[] key, byte[] data) throws Exception {
		return encryptTripleDes(key, data, false);
	}

	/**
	 * Performs Triple DEA Decryption without padding.
	 *
	 * @param key The key for decryption.
	 * @param data The data to decrypt.
	 * @return The decrypted data.
	 * @throws Exception
	 */
	public static byte[] decryptTripleDes(byte[] key, byte[] data) throws Exception {
		return decryptTripleDes(key, data, false);
	}

	/**
	 * <p>Performs Single AES Encryption.
	 *
	 * <p>This is supplied for use generic encryption and decryption purposes, but is not a part of the Dukpt algorithm.
	 *
	 * @param key The key for encryption.
	 * @param data The data to encrypt.
	 * @param padding When true, PKCS5 Padding will be used.  This is most likely not desirable.
	 * @return The encrypted.
	 * @throws Exception
	 */
	public static byte[] encryptAes(byte[] key, byte[] data, boolean padding) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(new byte[16]);
		SecretKeySpec encryptKey = new SecretKeySpec(key, "AES");

		Cipher encryptor;
		if (padding) {
			encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} else {
			encryptor = Cipher.getInstance("AES/CBC/NoPadding");
		}
		encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
		return encryptor.doFinal(data);
	}

	/**
	 * <p>Performs Single AES Decryption.
	 *
	 * <p>This is supplied for use generic encryption and decryption purposes, but is not a part of the Dukpt algorithm.
	 *
	 * @param key The key for decryption.
	 * @param data The data to decrypt.
	 * @param padding When true, PKCS5 Padding will be assumed.  This is most likely not desirable.
	 * @return The decrypted data.
	 * @throws Exception
	 */
	public static byte[] decryptAes(byte[] key, byte[] data, boolean padding) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(new byte[16]);
		SecretKeySpec decryptKey = new SecretKeySpec(key, "AES");

		Cipher decryptor;
		if (padding) {
			decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} else {
			decryptor = Cipher.getInstance("AES/CBC/NoPadding");
		}
		decryptor.init(Cipher.DECRYPT_MODE, decryptKey, iv);
		return decryptor.doFinal(data);
	}

	/**
	 * <p>Performs Single AES Encryption without padding.
	 *
	 * <p>This is supplied for use generic encryption and decryption purposes, but is not a part of the Dukpt algorithm.
	 *
	 * @param key The key for encryption.
	 * @param data The data to encrypt.
	 * @return The encrypted data.
	 * @throws Exception
	 */
	public static byte[] encryptAes(byte[] key, byte[] data) throws Exception {
		return encryptAes(key, data, false);
	}

	/**
	 * <p>Performs Triple AES Decryption without padding.
	 *
	 * <p>This is supplied for use generic encryption and decryption purposes, but is not a part of the Dukpt algorithm.
	 *
	 * @param key The key for decryption.
	 * @param data The data to decrypt.
	 * @return The decrypted data.
	 * @throws Exception
	 */
	public static byte[] decryptAes(byte[] key, byte[] data) throws Exception {
		return decryptAes(key, data, false);
	}

	/**
	 * <p>Converts a byte into an extended BitSet.
	 */
	public static BitSet toBitSet(byte b) {
		BitSet bs = new BitSet(8);
		for (int i = 0; i < 8; i++) {
			if ((b & (1L << i)) > 0) {
				bs.set(7 - i);
			}
		}
		return bs;
	}

	/**
	 * <p>Converts a byte array to an extended BitSet.
	 */
	public static BitSet toBitSet(byte[] b) {
		BitSet bs = new BitSet(8 * b.length);
		for (int i = 0; i < b.length; i++) {
			for (int j = 0; j < 8; j++) {
				if ((b[i] & (1L << j)) > 0) {
					bs.set(8 * i + (7 - j));
				}
			}
		}
		return bs;
	}

	/**
	 * <p>Converts an extended BitSet into a byte.
	 *
	 * <p>Requires that the BitSet be exactly 8 bits long.
	 */
	public static byte toByte(BitSet b) {
		byte value = 0;
		for (int i = 0; i < b.bitSize(); i++) {
			if (b.get(i))
				value = (byte) (value | (1L << 7 - i));
		}
		return value;
	}

	/**
	 * <p>Converts a BitSet into a byte array.
	 *
	 * <p>Pads to the left with zeroes.
	 *
	 * <p>Note: this is different from {@link BitSet#toByteArray()}.</p>
	 */
	public static byte[] toByteArray(BitSet b) {
		int size = (int) Math.ceil(b.bitSize() / 8.0d);
		byte[] value = new byte[size];
		for (int i = 0; i < size; i++) {
			value[i] = toByte(b.get(i * 8, Math.min(b.bitSize(), (i + 1) * 8)));
		}
		return value;
	}

	/**
	 * <p>Converts a hexadecimal String into a byte array (Big-Endian).
	 *
	 * @param s A representation of a hexadecimal number without any leading qualifiers such as "0x" or "x".
	 */
	public static byte[] toByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * <p>Converts a byte array into a hexadecimal string (Big-Endian).
	 *
	 * @return A representation of a hexadecimal number without any leading qualifiers such as "0x" or "x".
	 */
	public static String toHex(byte[] bytes) {
		BigInteger bi = new BigInteger(1, bytes);
		return String.format("%0" + (bytes.length << 1) + "X", bi);
	}

	/**
	 * <p>Concatenates two byte arrays.
	 *
	 * @return The array a concatenated with b.  So if r is the returned array, r[0] = a[0] and r[a.length] = b[0].
	 */
	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		for (int i = 0; i < a.length; i++) {
			c[i] = a[i];
		}
		for (int i = 0; i < b.length; i++) {
			c[a.length + i] = b[i];
		}
		return c;
	}
	/**
	 * <p>Overwrites the extended BitSet NUM_OVERWRITES times with random data for security purposes.
	 */
	public static void obliviate(BitSet b) {
		obliviate(b, NUM_OVERWRITES);
	}

	/**
	 * <p>Overwrites the byte array NUM_OVERWRITES times with random data for security purposes.
	 */
	public static void obliviate(byte[] b) {
		obliviate(b, NUM_OVERWRITES);
	}

	/**
	 * <p>Overwrites the extended BitSet with random data for security purposes.
	 */
	public static void obliviate(BitSet b, int n) {
		java.security.SecureRandom r = new java.security.SecureRandom();
		for (int i=0; i<NUM_OVERWRITES; i++) {
			for (int j = 0; j<b.bitSize(); j++) {
				b.set(j, r.nextBoolean());
			}
		}
	}

	/**
	 * <p>Overwrites the byte array with random data for security purposes.
	 */
	public static void obliviate(byte[] b, int n) {
		for (int i=0; i<n; i++) {
			b[i] = 0x00;
			b[i] = 0x01;
		}

		java.security.SecureRandom r = new java.security.SecureRandom();
		for (int i=0; i<n; i++) {
			r.nextBytes(b);
		}
	}

}
