# Cloud Storage Connector Examples

These examples demonstrate AxonFlow's S3, Azure Blob, and GCS connector support
in the **Community edition**. They use MinIO as an S3-compatible backend for local
testing without cloud credentials.

## Prerequisites

1. AxonFlow running via Docker Compose with MinIO:
   ```bash
   docker compose up -d
   ```
   This starts MinIO on port 9000 with default credentials (`minioadmin:minioadmin`)
   and creates the `axonflow-test-bucket` bucket automatically.

2. An S3 connector configured in AxonFlow pointing to the MinIO instance:
   ```
   Endpoint: http://minio:9000
   Access Key: minioadmin
   Secret Key: minioadmin
   Region: us-east-1
   Force Path Style: true
   ```

## Running Examples

### HTTP (cURL)
```bash
cd http
./cloud-storage.sh
```

### Go
```bash
cd go
go run main.go
```

### Python
```bash
cd python
pip install -r requirements.txt
python main.py
```

### TypeScript
```bash
cd typescript
npm install
npx ts-node src/index.ts
```

### Java
```bash
cd java
mvn compile exec:java
```

## What These Examples Test

Each example runs the same assertion set against the S3 connector via MinIO:

1. **Connector registration** - S3 connector appears in the connector list
2. **Put object** - Upload content with specific data
3. **Get object** - Retrieve and verify exact content matches what was uploaded
4. **List objects** - Verify uploaded object appears in listing with correct key
5. **Head object** - Verify object metadata (content type, size)
6. **Delete object** - Remove object
7. **Verify deletion** - Confirm deleted object no longer appears in listing
8. **Policy enforcement** - Verify governance policies apply to cloud storage operations

## Connector Types

| Connector | Config Type | Community | Enterprise |
|-----------|------------|-----------|------------|
| S3 / MinIO / R2 | `s3` | Yes | Yes |
| Azure Blob | `azure_blob` | Yes | Yes |
| GCS | `gcs` | Yes | Yes |
