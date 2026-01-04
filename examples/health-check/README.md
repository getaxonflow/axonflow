# Health Check Examples

Demonstrates how to check the health of AxonFlow Agent and Orchestrator services. This is essential for monitoring and ensuring your governance infrastructure is running.

## SDK Methods

| Method | Description |
|--------|-------------|
| `HealthCheck()` | Check Agent service health |
| `OrchestratorHealthCheck()` | Check Orchestrator service health |

## Quick Start

### Prerequisites

1. Start AxonFlow services:
   ```bash
   docker-compose up -d
   ```

2. Verify services are running:
   ```bash
   curl http://localhost:8080/health   # Agent
   curl http://localhost:8081/health   # Orchestrator
   ```

### Run Examples

**Go:**
```bash
cd go
go run main.go
```

**Python:**
```bash
cd python
pip install axonflow
python main.py
```

**TypeScript:**
```bash
cd typescript
npm install @axonflow/sdk
npx ts-node index.ts
```

**Java:**
```bash
cd java
mvn exec:java -Dexec.mainClass="com.example.HealthCheckExample"
```

**HTTP/cURL:**
```bash
cd http
chmod +x health-check.sh
./health-check.sh
```

## Expected Output

```
=== AxonFlow Health Check Example ===

1. Checking Agent health...
   Agent Status: healthy
   Version: 2.6.0
   Uptime: 2h30m15s

2. Checking Orchestrator health...
   Orchestrator Status: healthy
   Version: 2.6.0
   Database: connected

=== Health Check Summary ===
   Agent: HEALTHY
   Orchestrator: HEALTHY
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AXONFLOW_ENDPOINT` | Agent URL | `http://localhost:8080` |
| `AXONFLOW_LICENSE_KEY` | License key (optional for community) | - |

## Use Cases

1. **Kubernetes Liveness Probes** - Check if services are responsive
2. **Monitoring Dashboards** - Display service health status
3. **CI/CD Pipelines** - Verify deployment succeeded
4. **Alerting Systems** - Trigger alerts on health failures

## Related Examples

- [Hello World](../hello-world/) - Basic query execution
- [Execution Replay](../execution-replay/) - Debug and trace executions
