# Elasticsearch Fingerprint Ingest Processor

This processor generate a simple hash with one or several source fields.
The `target_field` is added in the document with the hash computed (except its value is `_id`).
Several hash algorithms are supported:

- MD5
- SHA1 (Default if not specified)
- SHA224
- SHA256
- SHA386
- SHA512

Pipeline parameters:

- `field` (required): Array containing the String document properties used for the hash.
- `target_field` (optional, default value `_id`): Field added to the document with the hash value (in Base64)
- `method` (optional, default value `SHA1`): Hash algorithm 
- `base64` (optional, default value `false`): Hash encoded in Base64 (Hex encoded if false, default behaviour)

# Build / Install

Requirement: Java 12 + compiler

In order to install this plugin, you need to create a zip distribution first by running

```bash
./gradlew clean check
```

This will produce a zip file in `build/distributions`.

After building the zip file, you can install it like this

```bash
bin/plugin install file:///path/to/ingest-fingerprint/build/distribution/ingest-fingerprint-7.3.2.0.zip
```

## Usage

```json
# Default hash method: SHA1
# Hash default target: _id
PUT _ingest/pipeline/fingerprint-pipeline1
{
  "description": "A pipeline with all default parameters",
  "processors": [
    {
      "fingerprint" : {
        "field" : ["message"]
      }
    }
  ]
}

# Index a sample document
POST /my-index/_doc?pipeline=fingerprint-pipeline1
{
  "message" : "my message value"
}

# Get the indexed document
GET my-index/_doc/DotknAH9dliUimillL63BsgOqXw=

# Sample document indexed
{
  "_index" : "my-index",
  "_type" : "_doc",
  "_id" : "DotknAH9dliUimillL63BsgOqXw=",
  "_version" : 3,
  "_seq_no" : 5,
  "_primary_term" : 1,
  "found" : true,
  "_source" : {
    "message" : "my message value"
  }
}


# Default hash method: SHA1
PUT _ingest/pipeline/fingerprint-pipeline2
{
  "description": "A pipeline with a target field",
  "processors": [
    {
      "fingerprint" : {
        "field" : ["message"],
        "target_field": "hash"
      }
    }
  ]
}

# Index a sample document
PUT /my-index/_doc/1?pipeline=fingerprint-pipeline2
{
  "message" : "my message value"
}

# Get the indexed document
GET my-index/_doc/1

# Sample indexed document
{
  "_index" : "my-index",
  "_type" : "_doc",
  "_id" : "1",
  "_version" : 1,
  "_seq_no" : 0,
  "_primary_term" : 1,
  "found" : true,
  "_source" : {
    "message" : "my message value",
    "hash" : "DotknAH9dliUimillL63BsgOqXw="
  }
}

# Pipeline with all config parameters
PUT _ingest/pipeline/fingerprint-pipeline3
{
  "description": "A pipeline with all parameter specified",
  "processors": [
    {
      "fingerprint" : {
        "field" : ["message"],
        "target_field": "hash",
        "method": "MD5"
      }
    }
  ]
}

# Index a sample document
PUT /my-index/_doc/2?pipeline=fingerprint-pipeline3
{
  "message" : "my message value"
}

# Get the indexed document
GET my-index/_doc/2

# Sample indexed document
{
  "_index" : "my-index",
  "_type" : "_doc",
  "_id" : "2",
  "_version" : 1,
  "_seq_no" : 1,
  "_primary_term" : 1,
  "found" : true,
  "_source" : {
    "message" : "my message value",
    "hash" : "HyA+gmAocOjpxrBGBGgz+w=="
  }
}
```
