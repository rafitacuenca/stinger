/*
 * CryptoUtil.java
 *
 * Created on January 5, 2007, 1:56 PM
 *
 * Copyright (C) 2007 Eric Sheridan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

package org.owasp.stinger.util;

import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * 
 * @author esheridan
 */
public class CryptoUtil {

	private final static String HASH_ALGORITHM = "SHA-512";

	private final static int SALT_SIZE = 64;

	private final static String PRNG = "SHA1PRNG";

	private final static int ITERATIONS = 100;

	public static byte[] getSalt() throws CryptoException {
		return getSalt(SALT_SIZE);
	}

	public static byte[] getSalt(int n) throws CryptoException {
		byte[] result = new byte[n];

		try {
			SecureRandom sr = SecureRandom.getInstance(PRNG);

			sr.nextBytes(result);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static byte[] doHash(byte[] content) throws CryptoException {
		byte[] result = null;

		try {
			byte[] salt = getSalt();
			byte[] password = getSalt();

			result = doHash(ITERATIONS, salt, password, content);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static byte[] doHash(byte[] salt, byte[] content)
			throws CryptoException {
		byte[] result = null;

		try {
			byte[] password = getSalt();

			result = doHash(ITERATIONS, salt, password, content);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static byte[] doHash(int i, byte[] salt, byte[] content)
			throws CryptoException {
		byte[] result = null;

		try {
			byte[] password = getSalt();

			result = doHash(i, salt, password, content);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static byte[] doHash(int n, byte[] salt, byte[] password,
			byte[] content) throws CryptoException {
		byte[] result = null;

		try {
			MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);

			md.update(salt);
			md.update(password);
			result = md.digest();

			for (int i = 1; i < n; i++) {
				result = md.digest(result);
			}

		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static byte[] doWeakHash(byte[] content) throws CryptoException {
		byte[] result = null;

		try {
			MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);

			result = md.digest(content);

			for (int i = 1; i < ITERATIONS; i++) {
				result = md.digest(result);
			}

			result = md.digest(content);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}
}
