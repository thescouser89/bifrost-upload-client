/**
 * JBoss, Home of Professional Open Source.
 * Copyright 2024-2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.pnc.bifrost.upload;

import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ChecksumComputingStream extends FilterInputStream {

    private final MessageDigest md5;

    public static final int BUFFER_SIZE = 65536; // 64KiB buffer

    private ChecksumComputingStream(InputStream stream, MessageDigest md5) {
        super(stream);
        this.md5 = md5;
    }

    public static ChecksumComputingStream of(InputStream is) {
        MessageDigest md5;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        DigestInputStream md5dis = new DigestInputStream(is, md5);
        return new ChecksumComputingStream(md5dis, md5);
    }

    public static ChecksumComputingStream computeChecksums(InputStream is) throws IOException {
        ChecksumComputingStream cheksumStream = of(is);
        cheksumStream.readFully();
        return cheksumStream;
    }

    public String getMD5Sum() {
        return format(md5.digest());
    }

    public void readFully() throws IOException {
        final byte[] buffer = new byte[BUFFER_SIZE];

        while (true) {
            if (read(buffer) == -1) break;
        }
    }

    private static String format(byte[] digest) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}