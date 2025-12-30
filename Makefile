.PHONY: help start stop status logs clean rebuild test test-coverage build build-community build-enterprise lint docs

# Default target
.DEFAULT_GOAL := help

# Colors for output
YELLOW := \033[1;33m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m

# Build edition (community or enterprise)
EDITION ?= enterprise

help: ## Show this help message
	@echo "$(GREEN)AxonFlow Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(GREEN)Examples:$(NC)"
	@echo "  make start              # Start all services"
	@echo "  make logs service=agent # View agent logs"
	@echo "  make rebuild service=agent # Rebuild agent"

start: ## Start all local services
	@echo "$(GREEN)Starting AxonFlow local development environment...$(NC)"
	@./scripts/local-dev/start.sh

stop: ## Stop all services
	@echo "$(YELLOW)Stopping services...$(NC)"
	@docker-compose down
	@echo "$(GREEN)✅ Services stopped$(NC)"

status: ## Show service status
	@echo "$(GREEN)Service Status:$(NC)"
	@docker-compose ps

logs: ## View logs (use: make logs service=agent)
	@if [ -n "$(service)" ]; then \
		docker-compose logs -f axonflow-$(service); \
	else \
		docker-compose logs -f; \
	fi

clean: ## Stop services and remove volumes (WARNING: deletes all data)
	@echo "$(RED)⚠️  This will delete all local data. Continue? [y/N]$(NC)" && read ans && [ $${ans:-N} = y ]
	@echo "$(YELLOW)Cleaning up...$(NC)"
	@docker-compose down -v
	@echo "$(GREEN)✅ Cleaned$(NC)"

rebuild: ## Rebuild and restart a service (use: make rebuild service=agent)
	@if [ -z "$(service)" ]; then \
		echo "$(RED)Error: Please specify service. Example: make rebuild service=agent$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Rebuilding axonflow-$(service)...$(NC)"
	@docker-compose up -d --build axonflow-$(service)
	@echo "$(GREEN)✅ Rebuilt axonflow-$(service)$(NC)"

test: ## Run all tests
	@echo "$(YELLOW)Running tests...$(NC)"
	@go test ./platform/... -v
	@echo "$(GREEN)✅ Tests passed$(NC)"

test-coverage: ## Run tests with coverage report
	@echo "$(YELLOW)Running tests with coverage...$(NC)"
	@go test ./platform/... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✅ Coverage report generated: coverage.html$(NC)"

test-migrations: ## Test database migrations
	@echo "$(YELLOW)Testing migrations...$(NC)"
	@./scripts/local-dev/test-migrations.sh

build: ## Build all Docker images (enterprise by default)
	@echo "$(YELLOW)Building images (edition: $(EDITION))...$(NC)"
	@docker-compose build --build-arg EDITION=$(EDITION)
	@echo "$(GREEN)✅ Images built$(NC)"

build-community: ## Build Community Docker images (no enterprise features)
	@echo "$(YELLOW)Building Community images...$(NC)"
	@docker-compose build --build-arg EDITION=community
	@echo "$(GREEN)✅ Community images built$(NC)"

build-enterprise: ## Build Enterprise Docker images (all features)
	@echo "$(YELLOW)Building Enterprise images...$(NC)"
	@docker-compose build --build-arg EDITION=enterprise
	@echo "$(GREEN)✅ Enterprise images built$(NC)"

lint: ## Run linters
	@echo "$(YELLOW)Running linters...$(NC)"
	@golangci-lint run ./... || true
	@echo "$(GREEN)✅ Linting complete$(NC)"

fmt: ## Format Go code
	@echo "$(YELLOW)Formatting code...$(NC)"
	@gofmt -s -w platform/
	@echo "$(GREEN)✅ Code formatted$(NC)"

health: ## Check health of all services
	@echo "$(GREEN)Checking service health:$(NC)"
	@echo "Agent:           $$(curl -s http://localhost:8080/health | jq -r '.status // "unhealthy"' 2>/dev/null || echo 'not running')"
	@echo "Orchestrator:    $$(curl -s http://localhost:8081/health | jq -r '.status // "unhealthy"' 2>/dev/null || echo 'not running')"
	@echo "Customer Portal: $$(curl -s http://localhost:8082/health 2>/dev/null || echo 'not running')"
	@echo "Prometheus:      $$(curl -s http://localhost:9090/-/healthy 2>/dev/null && echo 'healthy' || echo 'not running')"
	@echo "Grafana:         $$(curl -s http://localhost:3000/api/health 2>/dev/null | jq -r '.database // "unhealthy"' || echo 'not running')"

restart: ## Restart a service (use: make restart service=agent)
	@if [ -z "$(service)" ]; then \
		echo "$(RED)Error: Please specify service. Example: make restart service=agent$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Restarting axonflow-$(service)...$(NC)"
	@docker-compose restart axonflow-$(service)
	@echo "$(GREEN)✅ Restarted axonflow-$(service)$(NC)"

shell-agent: ## Open shell in agent container
	@docker-compose exec axonflow-agent sh

shell-db: ## Open psql shell in database
	@docker-compose exec postgres psql -U axonflow -d axonflow

endpoints: ## Show all service endpoints
	@echo "$(GREEN)Service Endpoints:$(NC)"
	@echo "  Agent:           http://localhost:8080"
	@echo "  Orchestrator:    http://localhost:8081"
	@echo "  Customer Portal: http://localhost:8082"
	@echo "  Prometheus:      http://localhost:9090"
	@echo "  Grafana:         http://localhost:3000 (admin / grafana_localdev456)"
	@echo "  PostgreSQL:      localhost:5432 (axonflow / localdev123)"

docs: ## Generate documentation
	@echo "$(YELLOW)Opening documentation...$(NC)"
	@open docs/LOCAL_DEVELOPMENT.md || xdg-open docs/LOCAL_DEVELOPMENT.md || echo "See docs/LOCAL_DEVELOPMENT.md"
