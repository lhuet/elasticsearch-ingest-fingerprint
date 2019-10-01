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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class FingerprintProcessorTests extends ESTestCase {

    private static Map<String, Object> defaultTestDoc;

    @BeforeClass
    public static void defaultDoc() {
        defaultTestDoc = new HashMap<>();
        defaultTestDoc.put("message", "my test string value");
        defaultTestDoc.put("asecondmessage", "my second test string value");

    }

    public void testSHA1SourceFieldOnTargetField() throws Exception {

        List<String> sourceField = new ArrayList<>();
        sourceField.add("message");

        IngestDocument resultedDoc = helperFingerprintProcessorExecute("hash", sourceField, "SHA1");

        logger.info("Document after processor: "  + resultedDoc.toString());

        byte[] sha1msg = MessageDigest.getInstance("SHA-1")
                .digest(resultedDoc.getFieldValue("message", String.class).getBytes("UTF-8"));

        String processorSha1 = resultedDoc.getFieldValue("hash", String.class);
        String computedSha1 = Base64.getEncoder().encodeToString(sha1msg);

        assertTrue(processorSha1.equals(computedSha1));
    }

    public void testSHA1SourceFieldOnIdField() throws Exception {

        List<String> sourceField = new ArrayList<>();
        sourceField.add("message");

        IngestDocument resultedDoc = helperFingerprintProcessorExecute("_id", sourceField, "SHA-1");

        logger.info("Document after processor: "  + resultedDoc.toString());

        byte[] sha1msg = MessageDigest.getInstance("SHA-1")
                .digest(resultedDoc.getFieldValue("message", String.class).getBytes("UTF-8"));

        String processorSha1 = (String) resultedDoc.getSourceAndMetadata().get(IngestDocument.MetaData.ID.getFieldName());
        String computedSha1 = Base64.getEncoder().encodeToString(sha1msg);

        assertTrue(processorSha1.equals(computedSha1));

    }

    public void testSHA256SourceFieldOnIdField() throws Exception {

        List<String> sourceField = new ArrayList<>();
        sourceField.add("asecondmessage");
        sourceField.add("message");
        IngestDocument resultedDoc = helperFingerprintProcessorExecute("_id", sourceField, "SHA-256");

        logger.info("Document after processor: "  + resultedDoc.toString());

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(resultedDoc.getFieldValue("asecondmessage", String.class).getBytes("UTF-8"));
        md.update(resultedDoc.getFieldValue("message", String.class).getBytes("UTF-8"));
        byte[] sha1msg = md.digest();

        String processorSha256 = (String) resultedDoc.getSourceAndMetadata().get(IngestDocument.MetaData.ID.getFieldName());
        String computedSha1 = Base64.getEncoder().encodeToString(sha1msg);

        assertTrue(processorSha256.equals(computedSha1));

    }

    private IngestDocument helperFingerprintProcessorExecute(String targetField, List<String> sourceField,
                                                             String algorithm) throws Exception {

        IngestDocument ingestDoc = RandomDocumentPicks.randomIngestDocument(random(), defaultTestDoc);

        FingerprintProcessor fingerprintProcessor =
                new FingerprintProcessor(randomAlphaOfLength(10), targetField, sourceField, algorithm);

        return fingerprintProcessor.execute(ingestDoc);
    }
}