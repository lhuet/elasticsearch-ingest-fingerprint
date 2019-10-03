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

import org.elasticsearch.ingest.IngestDocument;
import org.elasticsearch.ingest.RandomDocumentPicks;
import org.elasticsearch.test.ESTestCase;
import org.junit.BeforeClass;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FingerprintProcessorTests extends ESTestCase {

    private static Map<String, Object> defaultTestDoc;

    @BeforeClass
    public static void defaultDoc() {
        defaultTestDoc = new HashMap<>();
        defaultTestDoc.put("message", "my test string value");
        defaultTestDoc.put("asecondmessage", "my second test string value");
        defaultTestDoc.put("eventmessage",
                "124.126.126.0 - - [2017-07-03T08:09:00.435Z] \"GET /favicon-96x96.png HTTP/1.1\" 200" +
                        " 7589 \"-\" \"https://www.google.co.uk/\" \"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) " +
                        "Gecko/20100101 Firefox/33.0\"");
        defaultTestDoc.put("longproperty", Long.valueOf(1234));

    }

    public void testBase64SHA1SourceFieldOnTargetField() throws Exception {

        List<String> sourceField = Arrays.asList("message");

        IngestDocument resultedDoc = helperFingerprintProcessorExecute("hash", sourceField, "SHA1", true);
        logger.info("Document after processor: "  + resultedDoc.toString());

        byte[] sha1msg = MessageDigest.getInstance("SHA-1")
                .digest(resultedDoc.getFieldValue("message", String.class).getBytes("UTF-8"));

        String processorSha1 = resultedDoc.getFieldValue("hash", String.class);
        String computedSha1 = Base64.getEncoder().encodeToString(sha1msg);

        assertTrue(processorSha1.equals(computedSha1));
    }

    public void testHexSHA1SourceFieldOnIdField() throws Exception {

        List<String> sourceField = Arrays.asList("message");

        IngestDocument resultedDoc = helperFingerprintProcessorExecute("_id", sourceField, "SHA-1", false);
        logger.info("Document after processor: "  + resultedDoc.toString());

        byte[] sha1msg = MessageDigest.getInstance("SHA-1")
                .digest(resultedDoc.getFieldValue("message", String.class).getBytes("UTF-8"));

        String processorSha1 = (String) resultedDoc.getSourceAndMetadata().get(IngestDocument.MetaData.ID.getFieldName());
        String computedSha1 = FingerprintProcessor.toHexString(sha1msg);

        assertTrue(processorSha1.equals(computedSha1));
    }

    public void testBase64MD5SourceFieldOnIdField() throws Exception {

        helperTestAlgorithmBase64SourceFieldOnIdField("MD5");

    }

    public void testBase64SHA1SourceFieldOnIdField() throws Exception {

        helperTestAlgorithmBase64SourceFieldOnIdField("SHA-1");

    }

    public void testBase64SHA224SourceFieldOnIdField() throws Exception {

        helperTestAlgorithmBase64SourceFieldOnIdField("SHA-224");

    }

    public void testBase64SHA256SourceFieldOnIdField() throws Exception {

        helperTestAlgorithmBase64SourceFieldOnIdField("SHA-256");

    }

    public void testBase64SHA384SourceFieldOnIdField() throws Exception {

        helperTestAlgorithmBase64SourceFieldOnIdField("SHA-384");

    }

    public void testBase64SHA512SourceFieldOnIdField() throws Exception {

        helperTestAlgorithmBase64SourceFieldOnIdField("SHA-512");

    }


    public void testBase64DefaultSettingsManyTimes() throws Exception {

        List<String> sourceField = Arrays.asList("eventmessage");

        IngestDocument resultedDoc = null;

        for (int i = 0; i < 1000000; i++) {
            resultedDoc = helperFingerprintProcessorExecute("_id", sourceField, "SHA-1", true);
        }
        logger.info("Document after processor: "  + resultedDoc.toString());

        byte[] sha1msg = MessageDigest.getInstance("SHA-1")
                .digest(resultedDoc.getFieldValue("eventmessage", String.class).getBytes("UTF-8"));

        String processorSha1 = (String) resultedDoc.getSourceAndMetadata().get(IngestDocument.MetaData.ID.getFieldName());
        String computedSha1 = Base64.getEncoder().encodeToString(sha1msg);

        assertTrue(processorSha1.equals(computedSha1));

    }


    private void helperTestAlgorithmBase64SourceFieldOnIdField(String algorithm) throws Exception {

        List<String> sourceField = Arrays.asList("message");

        IngestDocument resultedDoc = helperFingerprintProcessorExecute("_id", sourceField, algorithm, true);
        logger.info("Document after processor: "  + resultedDoc.toString());

        byte[] sha1msg = MessageDigest.getInstance(algorithm)
                .digest(resultedDoc.getFieldValue("message", String.class).getBytes("UTF-8"));

        String processorSha1 = (String) resultedDoc.getSourceAndMetadata().get(IngestDocument.MetaData.ID.getFieldName());
        String computedSha1 = Base64.getEncoder().encodeToString(sha1msg);

        assertTrue(processorSha1.equals(computedSha1));
    }

    private IngestDocument helperFingerprintProcessorExecute(String targetField, List<String> sourceField,
                                                             String algorithm, boolean base64encode) throws Exception {

        IngestDocument ingestDoc = RandomDocumentPicks.randomIngestDocument(random(), defaultTestDoc);

        FingerprintProcessor fingerprintProcessor =
                new FingerprintProcessor(randomAlphaOfLength(10), targetField, sourceField, algorithm, base64encode);

        return fingerprintProcessor.execute(ingestDoc);
    }
}