/*
 * Copyright [2019] [Laurent HUET]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.elasticsearch.plugin.ingest.fingerprint;

import org.elasticsearch.ingest.AbstractProcessor;
import org.elasticsearch.ingest.IngestDocument;
import org.elasticsearch.ingest.Processor;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.elasticsearch.ingest.ConfigurationUtils.readBooleanProperty;
import static org.elasticsearch.ingest.ConfigurationUtils.readList;
import static org.elasticsearch.ingest.ConfigurationUtils.readOptionalStringProperty;


public class FingerprintProcessor extends AbstractProcessor {

    public static final String TYPE = "fingerprint";

    private final String target;
    private final List<String> source;
    private final String method;
    private final boolean base64encode;

    public FingerprintProcessor(String tag, String target, List<String> source, String method, boolean base64encode) {
        super(tag);
        this.target = target;
        this.source = source;
        this.method = method;
        this.base64encode = base64encode;
    }

    @Override
    public IngestDocument execute(IngestDocument ingestDocument) throws Exception {

        // A first try with a MessageDigest object pool was not very concluant.
        // Thus keeping the code simple seems to be a good approach for now
        MessageDigest md = MessageDigest.getInstance(this.method);

        for (String field: source) {
            md.update(ingestDocument.getFieldValue(field, String.class).getBytes("UTF-8"));
        }
        byte[] hash = md.digest();

        String encodedHash;
        if (base64encode) {
            encodedHash = Base64.getEncoder().encodeToString(hash);
        }
        else {
            encodedHash = toHexString(hash);
        }

        if (target.equals("_id")) {
            ingestDocument.getSourceAndMetadata().put(IngestDocument.MetaData.ID.getFieldName(), encodedHash);
        }
        else {
            ingestDocument.setFieldValue(target, encodedHash);
        }

        return ingestDocument;
    }

    @Override
    public String getType() {
        return TYPE;
    }

    public String getTarget() {
        return target;
    }

    public List<String> getSource() {
        return source;
    }

    public String getMethod() {
        return method;
    }

    public boolean isBase64encode() {
        return base64encode;
    }

    public static final class Factory implements Processor.Factory {


        @Override
        public FingerprintProcessor create(Map<String, Processor.Factory> processorFactories, String tag, Map<String, Object> config)
                throws Exception {
            // Target is optional. If not set, we put the hash value as the document Id
            String target = readOptionalStringProperty(TYPE, tag, config, "target_field");
            if (target == null) target = "_id";
            // Fields source for the hash
            List<String> source = readList(TYPE, tag, config, "field");
            if (source == null) source = Arrays.asList("_all");
            // Method is optional. Use SHA-1 by default
            String method = readOptionalStringProperty(TYPE, tag, config, "method");
            if (method == null) {
                method = Method.SHA1.getAlgorithm();
            }
            else {
                method = Method.fromString(method).getAlgorithm();
            }
            // hash is Hex encoding by default except if base64 is set to true
            Boolean base64encode = readBooleanProperty(TYPE, tag, config, "base64", false);

            return new FingerprintProcessor(tag, target, source, method, base64encode);
        }
    }

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    /**
     * Format a byte array as a hex string.
     *
     * @param bytes the input to be represented as hex.
     * @return a hex representation of the input as a String.
     */
    public static String toHexString(byte[] bytes) {
        Objects.requireNonNull(bytes);
        StringBuilder sb = new StringBuilder(2 * bytes.length);

        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            sb.append(HEX_DIGITS[b >> 4 & 0xf]).append(HEX_DIGITS[b & 0xf]);
        }

        return sb.toString();
    }


    enum Method {
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA224("SHA-224"),
        SHA256("SHA-256"),
        SHA384("SHA-384"),
        SHA512("SHA-512");

        private String algorithm;

        Method(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return this.algorithm;
        }

        public static Method fromString(String method) {
            try {
                return Method.valueOf(method);
            }
            catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Method '" + method + "' not supported", e);
            }

        }
    }

}
