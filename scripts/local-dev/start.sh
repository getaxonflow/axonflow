#!/bin/bash
# Start AxonFlow local development environment
# This script builds and starts all services with Docker Compose

set -e

cd "$(dirname "$0")/../.."

echo "🚀 Starting AxonFlow local development environment..."
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi

# Build and start services
echo "📦 Building Docker images (this may take a few minutes on first run)..."
docker compose build

echo ""
echo "🔄 Starting services..."
docker compose up -d

echo ""
echo "⏳ Waiting for services to become healthy..."
sleep 5

# Wait for PostgreSQL
echo -n "  Waiting for PostgreSQL... "
timeout 30 bash -c 'until docker compose exec -T postgres pg_isready -U axonflow -d axonflow > /dev/null 2>&1; do sleep 1; done' && echo "✅" || echo "⚠️  Timeout"

# Wait for Agent (runs migrations)
echo -n "  Waiting for Agent (running migrations)... "
timeout 60 bash -c 'until docker compose exec -T axonflow-agent wget --spider -q http://localhost:8080/health > /dev/null 2>&1; do sleep 2; done' && echo "✅" || echo "⚠️  Timeout"

# Wait for Orchestrator
echo -n "  Waiting for Orchestrator... "
timeout 60 bash -c 'until docker compose exec -T axonflow-orchestrator wget --spider -q http://localhost:8081/health > /dev/null 2>&1; do sleep 2; done' && echo "✅" || echo "⚠️  Timeout"

# Wait for Customer Portal
echo -n "  Waiting for Customer Portal... "
timeout 60 bash -c 'until docker compose exec -T axonflow-customer-portal wget --spider -q http://localhost:8080/health > /dev/null 2>&1; do sleep 2; done' && echo "✅" || echo "⚠️  Timeout"

# Wait for Grafana
echo -n "  Waiting for Grafana... "
timeout 60 bash -c 'until docker compose exec -T grafana wget --spider -q http://localhost:3000/api/health > /dev/null 2>&1; do sleep 2; done' && echo "✅" || echo "⚠️  Timeout"

echo ""
echo "✅ AxonFlow is running!"
echo ""
echo "📍 Service endpoints:"
echo "   Agent:           http://localhost:8080"
echo "   Orchestrator:    http://localhost:8081"
echo "   Customer Portal: http://localhost:8082"
echo "   Prometheus:      http://localhost:9090"
echo "   Grafana:         http://localhost:3000 (admin / grafana_localdev456)"
echo "   PostgreSQL:      localhost:5432 (axonflow / localdev123)"
echo ""
echo "📋 Useful commands:"
echo "   docker compose logs -f agent           # Follow agent logs"
echo "   docker compose ps                      # Check service status"
echo "   docker compose down -v                 # Stop and remove volumes"
echo "   docker compose logs -f axonflow-agent   # Watch migrations apply"
echo ""
