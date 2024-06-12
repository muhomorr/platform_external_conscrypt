/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.org.conscrypt;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public final class CertBlocklistImpl implements CertBlocklist {
    private static final Logger logger = Logger.getLogger(CertBlocklistImpl.class.getName());

    private final Set<BigInteger> serialBlocklist;
    private final Set<ByteString> sha1PubkeyBlocklist;
    private final Set<ByteString> sha256PubkeyBlocklist;
    private Map<ByteString, Boolean> cache;

    /**
     * Number of entries in the cache. The cache contains public keys which are
     * at most 4096 bits (512 bytes) for RSA. For a cache size of 64, that is
     * at most 512 * 64 = 32,768 bytes.
     */
    private static final int CACHE_SIZE = 64;

    /**
     * public for testing only.
     */
    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteString> sha1PubkeyBlocklist) {
        this(serialBlocklist, sha1PubkeyBlocklist, Collections.emptySet());
    }

    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteString> sha1PubkeyBlocklist,
            Set<ByteString> sha256PubkeyBlocklist) {
        this.cache = Collections.synchronizedMap(new LinkedHashMap<ByteString, Boolean>() {
            @Override
            protected boolean removeEldestEntry(Map.Entry<ByteString, Boolean> eldest) {
                return size() > CACHE_SIZE;
            }
        });
        this.serialBlocklist = serialBlocklist;
        this.sha1PubkeyBlocklist = sha1PubkeyBlocklist;
        this.sha256PubkeyBlocklist = sha256PubkeyBlocklist;
    }

    public static CertBlocklist getDefault() {
        String androidData = System.getenv("ANDROID_DATA");
        String blocklistRoot = androidData + "/misc/keychain/";
        String defaultPubkeyBlocklistPath = blocklistRoot + "pubkey_blacklist.txt";
        String defaultSerialBlocklistPath = blocklistRoot + "serial_blacklist.txt";
        String defaultPubkeySha256BlocklistPath = blocklistRoot + "pubkey_sha256_blocklist.txt";

        Set<ByteString> sha1PubkeyBlocklist =
                readPublicKeyBlockList(defaultPubkeyBlocklistPath, "SHA-1");
        Set<ByteString> sha256PubkeyBlocklist =
                readPublicKeyBlockList(defaultPubkeySha256BlocklistPath, "SHA-256");
        Set<BigInteger> serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
        return new CertBlocklistImpl(serialBlocklist, sha1PubkeyBlocklist, sha256PubkeyBlocklist);
    }

    private static boolean isHex(String value) {
        try {
            new BigInteger(value, 16);
            return true;
        } catch (NumberFormatException e) {
            logger.log(Level.WARNING, "Could not parse hex value " + value, e);
            return false;
        }
    }

    private static boolean isPubkeyHash(String value, int expectedHashLength) {
        if (value.length() != expectedHashLength) {
            logger.log(Level.WARNING, "Invalid pubkey hash length: " + value.length());
            return false;
        }
        return isHex(value);
    }

    private static String readBlocklist(String path) {
        try {
            return readFileAsString(path);
        } catch (FileNotFoundException ignored) {
            // Ignored
        } catch (IOException e) {
            logger.log(Level.WARNING, "Could not read blocklist", e);
        }
        return "";
    }

    // From IoUtils.readFileAsString
    private static String readFileAsString(String path) throws IOException {
        return readFileAsBytes(path).toString("UTF-8");
    }

    // Based on IoUtils.readFileAsBytes
    private static ByteArrayOutputStream readFileAsBytes(String path) throws IOException {
        RandomAccessFile f = null;
        try {
            f = new RandomAccessFile(path, "r");
            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) f.length());
            byte[] buffer = new byte[8192];
            while (true) {
                int byteCount = f.read(buffer);
                if (byteCount == -1) {
                    return bytes;
                }
                bytes.write(buffer, 0, byteCount);
            }
        } finally {
            closeQuietly(f);
        }
    }

    // Base on IoUtils.closeQuietly
    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (RuntimeException rethrown) {
                throw rethrown;
            } catch (Exception ignored) {
                // Ignored
            }
        }
    }

    private static Set<BigInteger> readSerialBlockList(String path) {
        /*
         * Deprecated. Serials may inadvertently match a certificate that was
         * issued not in compliance with the Baseline Requirements. Prefer
         * using the certificate public key.
         */
        Set<BigInteger> bl = new HashSet<BigInteger>();
        String serialBlocklist = readBlocklist(path);
        if (!serialBlocklist.equals("")) {
            for (String value : serialBlocklist.split(",", -1)) {
                try {
                    bl.add(new BigInteger(value, 16));
                } catch (NumberFormatException e) {
                    logger.log(Level.WARNING, "Tried to blacklist invalid serial number " + value, e);
                }
            }
        }

        // whether that succeeds or fails, send it on its merry way
        return Collections.unmodifiableSet(bl);
    }

    static final byte[][] SHA1_BUILTINS = {
            // Blocklist test cert for CTS. The cert and key can be found in
            // src/test/resources/blocklist_test_ca.pem and
            // src/test/resources/blocklist_test_ca_key.pem.
            "bae78e6bed65a2bf60ddedde7fd91e825865e93d".getBytes(UTF_8),
    };

    static final byte[][] SHA256_BUILTINS = {
            // Blocklist test cert for CTS. The cert and key can be found in
            // src/test/resources/blocklist_test_ca2.pem and
            // src/test/resources/blocklist_test_ca2_key.pem.
            "809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd".getBytes(UTF_8),
    };

    private static Set<ByteString> readPublicKeyBlockList(String path, String hashType) {
        Set<ByteString> bl;

        switch (hashType) {
            case "SHA-1":
                bl = new HashSet<ByteString>(toByteStrings(SHA1_BUILTINS));
                break;
            case "SHA-256":
                bl = new HashSet<ByteString>(toByteStrings(SHA256_BUILTINS));
                // Blocklist statically included in Conscrypt. See constants/.
                for (byte[] staticPubKey : StaticBlocklist.PUBLIC_KEYS) {
                    bl.add(new ByteString(staticPubKey));
                }
                break;
            default:
                throw new RuntimeException(
                        "Unknown hashType: " + hashType + ". Expected SHA-1 or SHA-256");
        }

        MessageDigest md;
        try {
            md = MessageDigest.getInstance(hashType);
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
            return bl;
        }
        // The hashes are encoded with hexadecimal values. There should be
        // twice as many characters as the digest length in bytes.
        int hashLength = md.getDigestLength() * 2;

        // attempt to augment it with values taken from gservices
        String pubkeyBlocklist = readBlocklist(path);
        if (!pubkeyBlocklist.equals("")) {
            for (String value : pubkeyBlocklist.split(",", -1)) {
                value = value.trim();
                if (isPubkeyHash(value, hashLength)) {
                    bl.add(new ByteString(value.getBytes(UTF_8)));
                } else {
                    logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
                }
            }
        }

        return bl;
    }

    private static boolean isPublicKeyBlockListed(
            ByteString encodedPublicKey, Set<ByteString> blocklist, String hashType) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(hashType);
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
            return false;
        }
        ByteString out = new ByteString(toHex(md.digest(encodedPublicKey.bytes)));
        if (blocklist.contains(out)) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isPublicKeyBlockListed(PublicKey publicKey) {
        ByteString encodedPublicKey = new ByteString(publicKey.getEncoded());
        Boolean cachedResult = cache.get(encodedPublicKey);
        if (cachedResult != null) {
            return cachedResult.booleanValue();
        }
        if (!sha1PubkeyBlocklist.isEmpty()) {
            if (isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, "SHA-1")) {
                cache.put(encodedPublicKey, true);
                return true;
            }
        }
        if (!sha256PubkeyBlocklist.isEmpty()) {
            if (isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, "SHA-256")) {
                cache.put(encodedPublicKey, true);
                return true;
            }
        }
        cache.put(encodedPublicKey, false);
        return false;
    }

    private static final byte[] HEX_TABLE = { (byte) '0', (byte) '1', (byte) '2', (byte) '3',
        (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'a',
        (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'};

    private static byte[] toHex(byte[] in) {
        byte[] out = new byte[in.length * 2];
        int outIndex = 0;
        for (int i = 0; i < in.length; i++) {
            int value = in[i] & 0xff;
            out[outIndex++] = HEX_TABLE[value >> 4];
            out[outIndex++] = HEX_TABLE[value & 0xf];
        }
        return out;
    }

    @Override
    public boolean isSerialNumberBlockListed(BigInteger serial) {
        return serialBlocklist.contains(serial);
    }

    private static List<ByteString> toByteStrings(byte[]... allBytes) {
        List<ByteString> byteStrings = new ArrayList<>(allBytes.length + 1);
        for (byte[] bytes : allBytes) {
            byteStrings.add(new ByteString(bytes));
        }
        return byteStrings;
    }

    private static class ByteString {
        final byte[] bytes;

        public ByteString(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (!(o instanceof ByteString)) {
                return false;
            }

            ByteString other = (ByteString) o;
            return Arrays.equals(bytes, other.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }
    }
}
