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

import static org.elasticsearch.ingest.ConfigurationUtils.readList;
import static org.elasticsearch.ingest.ConfigurationUtils.readOptionalStringProperty;

public class FingerprintProcessor extends AbstractProcessor {

    public static final String TYPE = "fingerprint";

    private final String target;
    private final List<String> source;
    private final String method;

    public FingerprintProcessor(String tag, String target, List<String> source, String method) {
        super(tag);
        this.target = target;
        this.source = source;
        this.method = method;
    }

    @Override
    public IngestDocument execute(IngestDocument ingestDocument) throws Exception {

        // TODO: [Performance] Use a MessageDisgest pool object to prevent creating a new one for each document
        MessageDigest md = MessageDigest.getInstance(this.method);


        for (String field: source) {
            md.update(ingestDocument.getFieldValue(field, String.class).getBytes("UTF-8"));
        }
        byte[] hash = md.digest();

        if (target.equals("_id")) {
            ingestDocument.getSourceAndMetadata().put(IngestDocument.MetaData.ID.getFieldName(),Base64.getEncoder().encodeToString(hash));
        }
        else {
            ingestDocument.setFieldValue(target, Base64.getEncoder().encodeToString(hash));
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

    public static final class Factory implements Processor.Factory {

        @Override
        public FingerprintProcessor create(Map<String, Processor.Factory> processorFactories, String tag, Map<String, Object> config)
                throws Exception {
            // Target is optional. If not set, we put the hash value as the document Id
            String target = readOptionalStringProperty(TYPE, tag, config, "target_field");
            if (target == null) target = "_id";
            // Field is optional. If not set, we used all the field values sorted by lexical order
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

            return new FingerprintProcessor(tag, target, source, method);
        }
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
