# Ollama Provider Setup Guide

## Overview

This guide covers setting up and configuring the Ollama provider for AxonFlow Enterprise Edition. Ollama enables self-hosted LLM deployment for air-gapped environments, on-premise infrastructure, and cost-optimized local development.

### When to Use Ollama

- **Air-Gapped Environments**: Government, defense, or highly regulated industries without internet access
- **Data Sovereignty**: Keep all data and models within your infrastructure
- **Cost Optimization**: Eliminate per-token costs for high-volume workloads
- **Local Development**: Fast iteration without API rate limits or costs
- **Custom Models**: Deploy fine-tuned models specific to your domain

### Key Benefits

- ✅ Zero external API dependencies
- ✅ Complete data privacy and control
- ✅ No per-token costs after infrastructure investment
- ✅ GPU acceleration support
- ✅ Rapid model switching
- ✅ Open-source model ecosystem

---

## Prerequisites

### Hardware Requirements

#### Minimum (Development)
- CPU: 8 cores
- RAM: 16 GB
- Storage: 50 GB SSD
- GPU: Optional (CPU inference supported)

#### Recommended (Production - 7B models)
- CPU: 16+ cores
- RAM: 32 GB
- Storage: 200 GB NVMe SSD
- GPU: NVIDIA GPU with 8+ GB VRAM (e.g., RTX 4060, A4000)

#### High-Performance (Production - 70B models)
- CPU: 32+ cores
- RAM: 128 GB
- Storage: 500 GB NVMe SSD
- GPU: NVIDIA GPU with 80+ GB VRAM (e.g., A100, H100)

### Software Requirements

- **Docker**: 24.0+ (for containerized deployment)
- **NVIDIA Container Toolkit**: For GPU support
- **Operating System**: Linux (Ubuntu 22.04+, RHEL 8+), macOS 12+

---

## Installation Methods

### Method 1: Docker Deployment (Recommended)

#### 1.1 Install Ollama Container

```bash
# Pull official Ollama image
docker pull ollama/ollama:latest

# Run Ollama server (CPU)
docker run -d \
  --name ollama \
  -p 11434:11434 \
  -v ollama-data:/root/.ollama \
  --restart unless-stopped \
  ollama/ollama

# Run Ollama server (GPU with NVIDIA)
docker run -d \
  --name ollama \
  --gpus all \
  -p 11434:11434 \
  -v ollama-data:/root/.ollama \
  --restart unless-stopped \
  ollama/ollama
```

#### 1.2 Verify Installation

```bash
# Check Ollama is running
curl http://localhost:11434/api/version

# Expected output:
# {"version":"0.1.47"}
```

#### 1.3 Pull Models

```bash
# Pull Llama 3.1 8B (recommended starter model)
docker exec ollama ollama pull llama3.1

# Pull Mistral 7B
docker exec ollama ollama pull mistral

# Pull Code Llama 7B
docker exec ollama ollama pull codellama

# Pull Llama 3.1 70B (requires significant resources)
docker exec ollama ollama pull llama3.1:70b

# List installed models
docker exec ollama ollama list
```

### Method 2: Bare Metal Installation

#### 2.1 Linux Installation

```bash
# Install Ollama (automated script)
curl -fsSL https://ollama.com/install.sh | sh

# Verify installation
ollama --version

# Start Ollama service
sudo systemctl start ollama
sudo systemctl enable ollama

# Check service status
sudo systemctl status ollama
```

#### 2.2 macOS Installation

```bash
# Download and install Ollama
# Visit: https://ollama.com/download/mac

# Or use Homebrew
brew install ollama

# Start Ollama service
brew services start ollama

# Verify
ollama --version
```

#### 2.3 Pull Models (Bare Metal)

```bash
# Pull models directly
ollama pull llama3.1
ollama pull mistral
ollama pull codellama

# List models
ollama list

# Test model
ollama run llama3.1 "Hello, how are you?"
```

### Method 3: Kubernetes Deployment

#### 3.1 Kubernetes Manifest

```yaml
# ollama-deployment.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ollama
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ollama-data
  namespace: ollama
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 200Gi
  storageClassName: fast-ssd
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ollama
  namespace: ollama
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ollama
  template:
    metadata:
      labels:
        app: ollama
    spec:
      containers:
      - name: ollama
        image: ollama/ollama:latest
        ports:
        - containerPort: 11434
          name: http
        resources:
          requests:
            memory: "32Gi"
            cpu: "8"
            nvidia.com/gpu: "1"
          limits:
            memory: "64Gi"
            cpu: "16"
            nvidia.com/gpu: "1"
        volumeMounts:
        - name: data
          mountPath: /root/.ollama
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: ollama-data
      nodeSelector:
        gpu-type: nvidia-a100  # Adjust based on your cluster
---
apiVersion: v1
kind: Service
metadata:
  name: ollama
  namespace: ollama
spec:
  type: ClusterIP
  ports:
  - port: 11434
    targetPort: 11434
    name: http
  selector:
    app: ollama
```

#### 3.2 Deploy to Kubernetes

```bash
# Apply manifests
kubectl apply -f ollama-deployment.yaml

# Verify deployment
kubectl get pods -n ollama
kubectl logs -n ollama -l app=ollama

# Port forward for testing
kubectl port-forward -n ollama svc/ollama 11434:11434

# Test connection
curl http://localhost:11434/api/version
```

#### 3.3 Pull Models in Kubernetes

```bash
# Exec into pod
kubectl exec -it -n ollama deployment/ollama -- bash

# Pull models
ollama pull llama3.1
ollama pull mistral

# Exit pod
exit
```

---

## AxonFlow Configuration

### Environment Variables

Add these to your AxonFlow environment configuration:

```yaml
# config/environments/production.yaml (air-gapped)
LLM_PROVIDER: ollama
LLM_OLLAMA_ENABLED: true
LLM_OLLAMA_BASE_URL: http://ollama:11434
LLM_OLLAMA_MODEL: llama3.1
LLM_OLLAMA_TIMEOUT: 120s  # Increase for large models
```

### CloudFormation Parameters

For AWS deployments (hybrid scenarios):

```yaml
# infrastructure/cloudformation/axonflow.yaml
Parameters:
  OllamaEnabled:
    Type: String
    Default: "false"
    AllowedValues: ["true", "false"]
    Description: Enable Ollama provider

  OllamaBaseURL:
    Type: String
    Default: "http://ollama.axonflow.internal:11434"
    Description: Ollama API base URL

  OllamaModel:
    Type: String
    Default: "llama3.1"
    Description: Default Ollama model
```

### Docker Compose (Development)

```yaml
# docker-compose.ollama.yaml
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    container_name: axonflow-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama-data:/root/.ollama
    restart: unless-stopped
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]

  axonflow:
    image: axonflow/orchestrator:latest
    depends_on:
      - ollama
    environment:
      - LLM_PROVIDER=ollama
      - LLM_OLLAMA_ENABLED=true
      - LLM_OLLAMA_BASE_URL=http://ollama:11434
      - LLM_OLLAMA_MODEL=llama3.1
    ports:
      - "8080:8080"

volumes:
  ollama-data:
```

### Application Code

```go
package main

import (
    "context"
    "fmt"
    "time"
    "axonflow/platform/orchestrator/llm"
)

func main() {
    // Create Ollama provider
    provider, err := llm.NewOllamaProvider(llm.OllamaConfig{
        BaseURL: "http://localhost:11434",
        Model:   "llama3.1",
        Timeout: 60 * time.Second,
    })
    if err != nil {
        panic(err)
    }

    // Generate completion
    resp, err := provider.Complete(context.Background(), llm.CompletionRequest{
        Prompt:      "Explain quantum computing in simple terms.",
        MaxTokens:   500,
        Temperature: 0.7,
    })
    if err != nil {
        panic(err)
    }

    fmt.Printf("Model: %s\n", resp.Model)
    fmt.Printf("Response: %s\n", resp.Content)
    fmt.Printf("Tokens: %d (prompt) + %d (completion) = %d total\n",
        resp.Tokens.PromptTokens,
        resp.Tokens.CompletionTokens,
        resp.Tokens.TotalTokens)
    fmt.Printf("Latency: %v\n", resp.Latency)
}
```

---

## Supported Models

### Recommended Models

| Model | Size | Use Case | Memory | Speed |
|-------|------|----------|--------|-------|
| **llama3.1** | 8B | General purpose | 8 GB | Fast |
| **mistral** | 7B | Cost-effective | 6 GB | Fast |
| **codellama** | 7B | Code generation | 8 GB | Fast |
| **llama3.1:70b** | 70B | High accuracy | 80 GB | Slow |
| **neural-chat** | 7B | Conversational | 8 GB | Fast |
| **openchat** | 7B | Instruction following | 8 GB | Fast |

### Model Management

```bash
# Pull model
ollama pull <model-name>

# List installed models
ollama list

# Remove model
ollama rm <model-name>

# Show model details
ollama show <model-name>

# Copy model with custom name
ollama cp llama3.1 my-custom-model
```

### Quantization Levels

Ollama supports different quantization levels to trade accuracy for memory:

```bash
# Full precision (largest, most accurate)
ollama pull llama3.1

# 8-bit quantization
ollama pull llama3.1:8bit

# 4-bit quantization (recommended)
ollama pull llama3.1:4bit

# 2-bit quantization (smallest, fastest, least accurate)
ollama pull llama3.1:2bit
```

---

## Performance Tuning

### GPU Optimization

#### Check GPU Availability

```bash
# NVIDIA GPU check
nvidia-smi

# Docker GPU check
docker run --rm --gpus all nvidia/cuda:12.0-base nvidia-smi
```

#### GPU Configuration

```bash
# Set GPU memory limit (in MB)
export OLLAMA_GPU_MEMORY=8000

# Restart Ollama
docker restart ollama
```

### CPU Optimization

```bash
# Set number of CPU threads
export OLLAMA_NUM_THREADS=16

# Set batch size
export OLLAMA_BATCH_SIZE=512

# Restart Ollama
docker restart ollama
```

### Memory Management

```bash
# Set context window size (default: 2048)
export OLLAMA_CONTEXT_SIZE=4096

# Keep model loaded in memory (seconds)
export OLLAMA_KEEP_ALIVE=3600

# Restart Ollama
docker restart ollama
```

### Load Balancing Multiple Instances

```yaml
# nginx.conf
upstream ollama_backend {
    least_conn;
    server ollama-1:11434 max_fails=3 fail_timeout=30s;
    server ollama-2:11434 max_fails=3 fail_timeout=30s;
    server ollama-3:11434 max_fails=3 fail_timeout=30s;
}

server {
    listen 11434;

    location / {
        proxy_pass http://ollama_backend;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

---

## Security Best Practices

### 1. Network Isolation

```bash
# Create isolated Docker network
docker network create ollama-private

# Run Ollama on private network
docker run -d \
  --name ollama \
  --network ollama-private \
  -v ollama-data:/root/.ollama \
  ollama/ollama
```

### 2. Firewall Rules

```bash
# Allow only AxonFlow to access Ollama
sudo ufw allow from 10.0.1.0/24 to any port 11434
sudo ufw deny 11434
```

### 3. TLS Termination

Use a reverse proxy (NGINX, Traefik) for TLS:

```yaml
# traefik.yaml
http:
  routers:
    ollama:
      rule: "Host(`ollama.internal.axonflow.com`)"
      service: ollama
      tls:
        certResolver: letsencrypt

  services:
    ollama:
      loadBalancer:
        servers:
          - url: "http://ollama:11434"
```

### 4. Authentication (Optional)

Ollama doesn't have built-in auth. Use a reverse proxy:

```nginx
# nginx.conf with basic auth
location / {
    auth_basic "Ollama API";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://ollama:11434;
}
```

### 5. Model Verification

```bash
# Verify model checksums before pulling
ollama pull llama3.1 --verify

# Check model integrity
ollama show llama3.1 --modelfile
```

---

## Troubleshooting

### Issue 1: Connection Refused

**Symptom**: `dial tcp 127.0.0.1:11434: connect: connection refused`

**Solutions**:
```bash
# Check if Ollama is running
docker ps | grep ollama
# or
systemctl status ollama

# Restart Ollama
docker restart ollama
# or
sudo systemctl restart ollama

# Check logs
docker logs ollama
# or
journalctl -u ollama -f
```

### Issue 2: Out of Memory

**Symptom**: `error loading model: out of memory`

**Solutions**:
```bash
# Use smaller quantized model
ollama pull llama3.1:4bit

# Reduce context size
export OLLAMA_CONTEXT_SIZE=2048

# Add swap space (Linux)
sudo fallocate -l 16G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue 3: Slow Response Times

**Symptom**: Completions taking >30 seconds

**Solutions**:
```bash
# Enable GPU if available
docker run --gpus all ollama/ollama

# Use smaller model
ollama pull mistral  # 7B instead of 70B

# Increase batch size
export OLLAMA_BATCH_SIZE=1024

# Keep model in memory
export OLLAMA_KEEP_ALIVE=-1  # Keep forever
```

### Issue 4: Model Not Found

**Symptom**: `error: model 'llama3.1' not found`

**Solutions**:
```bash
# Pull the model
docker exec ollama ollama pull llama3.1

# List available models
docker exec ollama ollama list

# Check model name spelling
# Correct: llama3.1
# Incorrect: llama3, llama-3.1
```

### Issue 5: GPU Not Detected

**Symptom**: `WARN[0000] GPU not available, using CPU`

**Solutions**:
```bash
# Install NVIDIA Container Toolkit
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | \
  sudo tee /etc/apt/sources.list.d/nvidia-docker.list
sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker

# Verify GPU access
docker run --rm --gpus all nvidia/cuda:12.0-base nvidia-smi
```

---

## Use Cases

### Government Air-Gapped Environment

**Scenario**: Defense agency needs AI capabilities without internet connectivity.

**Setup**:
1. Download Ollama installer on connected machine
2. Transfer to air-gapped environment via secure media
3. Download models on connected machine: `ollama pull llama3.1`
4. Export model: `ollama cp llama3.1 /mnt/transfer/`
5. Import on air-gapped machine: `ollama import /mnt/secure/llama3.1`
6. Configure AxonFlow to use local Ollama instance

**Benefits**:
- Zero external dependencies
- Complete data sovereignty
- Meets compliance requirements (e.g., FedRAMP, IL5)

### Healthcare On-Premise

**Scenario**: Hospital needs HIPAA-compliant AI for clinical decision support.

**Setup**:
```yaml
# Production configuration
LLM_PROVIDER: ollama
LLM_OLLAMA_BASE_URL: https://ollama.hospital.internal
LLM_OLLAMA_MODEL: llama3.1:70b
LLM_OLLAMA_TIMEOUT: 180s

# Deploy on hospital network
# - No PHI leaves premises
# - GPU acceleration for real-time responses
# - HA setup with 3 Ollama instances
```

**Benefits**:
- PHI never leaves hospital network
- Low latency for clinical workflows
- Predictable costs (no per-token charges)

### Cost-Optimized Development

**Scenario**: Startup developing AI features on limited budget.

**Setup**:
```bash
# Local development
docker-compose -f docker-compose.ollama.yaml up -d

# Use smaller models for fast iteration
ollama pull mistral  # 7B model, fast on laptop

# Switch to larger models for quality testing
ollama pull llama3.1:70b  # Use remote GPU server
```

**Benefits**:
- Zero API costs during development
- Fast iteration without rate limits
- Easy model switching for experimentation

---

## Monitoring

### Prometheus Metrics

Ollama exposes metrics at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ollama'
    static_configs:
      - targets: ['ollama:11434']
```

### Key Metrics

- `ollama_requests_total` - Total API requests
- `ollama_request_duration_seconds` - Request latency
- `ollama_models_loaded` - Models currently in memory
- `ollama_gpu_memory_used_bytes` - GPU memory usage

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Ollama Performance",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [{"expr": "rate(ollama_requests_total[5m])"}]
      },
      {
        "title": "Latency P95",
        "targets": [{"expr": "histogram_quantile(0.95, ollama_request_duration_seconds)"}]
      }
    ]
  }
}
```

---

## Migration Guide

### From OpenAI to Ollama

```go
// Before (OpenAI)
provider, err := llm.NewOpenAIProvider(llm.OpenAIConfig{
    APIKey: "sk-...",
    Model:  "gpt-4",
})

// After (Ollama)
provider, err := llm.NewOllamaProvider(llm.OllamaConfig{
    BaseURL: "http://localhost:11434",
    Model:   "llama3.1",  // Similar capabilities to GPT-4
})

// Same API calls - no code changes needed
resp, err := provider.Complete(ctx, llm.CompletionRequest{
    Prompt:      prompt,
    MaxTokens:   1000,
    Temperature: 0.7,
})
```

### From AWS Bedrock to Ollama

```yaml
# Before (Bedrock - cloud)
LLM_PROVIDER: bedrock
LLM_BEDROCK_REGION: us-east-1
LLM_BEDROCK_MODEL: anthropic.claude-3-5-sonnet-20240620-v1:0

# After (Ollama - on-premise)
LLM_PROVIDER: ollama
LLM_OLLAMA_BASE_URL: http://ollama:11434
LLM_OLLAMA_MODEL: llama3.1
```

**No code changes required** - only configuration update.

---

## Cost Analysis

### Infrastructure Costs

#### AWS g5.2xlarge (GPU inference)
- **Specs**: 8 vCPU, 32 GB RAM, NVIDIA A10G (24 GB)
- **Cost**: $1.21/hour = ~$870/month (on-demand)
- **Throughput**: ~50 requests/min (7B models)
- **Cost per 1M tokens**: ~$0.50 (vs $3 for OpenAI GPT-4)

#### On-Premise Server
- **Initial**: $15,000 (server + GPU)
- **Monthly**: $200 (power, cooling, maintenance)
- **Break-even**: 6-12 months vs cloud APIs
- **5-year TCO**: ~$27,000

### Cost Comparison (1M tokens/day)

| Provider | Monthly Cost | Annual Cost | Notes |
|----------|--------------|-------------|-------|
| **OpenAI GPT-4** | $90,000 | $1,080,000 | $3/M tokens |
| **AWS Bedrock** | $45,000 | $540,000 | $1.50/M tokens |
| **Ollama (Cloud GPU)** | $870 | $10,440 | Infrastructure only |
| **Ollama (On-Prem)** | $200 | $2,400 | After initial investment |

**Ollama savings**: 95-99% vs cloud APIs at scale.

---

## Support

### Documentation
- **Ollama Docs**: https://ollama.com/docs
- **Model Library**: https://ollama.com/library
- **AxonFlow Docs**: https://docs.getaxonflow.com

### Community
- **Ollama GitHub**: https://github.com/ollama/ollama
- **Ollama Discord**: https://discord.gg/ollama
- **AxonFlow Support**: support@getaxonflow.com

### Enterprise Support
For production deployments, AxonFlow offers:
- Architecture design consultation
- Performance optimization
- Model selection guidance
- 24/7 technical support

**Contact**: enterprise@getaxonflow.com

---

## Appendix: Model Comparison

### Llama 3.1 vs GPT-4

| Metric | Llama 3.1 (8B) | GPT-4 | Notes |
|--------|----------------|-------|-------|
| **Parameters** | 8B | ~1.7T | GPT-4 is much larger |
| **Quality** | Good | Excellent | GPT-4 more accurate |
| **Speed** | 50-100 tokens/s | 10-20 tokens/s | Llama faster |
| **Cost** | Infrastructure only | $30/M tokens | Llama cheaper at scale |
| **Privacy** | Complete | Shared with OpenAI | Llama better for sensitive data |

### When to Use Which Model

- **Llama 3.1 8B**: General purpose, fast, cost-effective
- **Llama 3.1 70B**: High accuracy, competitive with GPT-4
- **Mistral 7B**: Efficient, multilingual
- **Code Llama**: Code generation, technical docs
- **Neural Chat**: Customer support, conversational AI

---

**Last Updated**: November 2025
**AxonFlow Version**: Enterprise Edition 2.0+
**Ollama Version**: 0.1.47+
