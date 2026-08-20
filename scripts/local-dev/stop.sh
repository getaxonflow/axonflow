#!/bin/bash
# Stop AxonFlow local development environment
# Options:
#   --keep-data: Stop services but keep volumes (faster restart)
#   --clean: Stop services and remove volumes (fresh start)

set -e

cd "$(dirname "$0")/../.."

CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --keep-data)
            CLEAN=false
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--keep-data|--clean]"
            exit 1
            ;;
    esac
done

echo "🛑 Stopping AxonFlow local development environment..."

if [ "$CLEAN" = true ]; then
    echo "   Mode: Clean (removing volumes)"
    docker compose down -v
    echo "✅ Stopped and removed all volumes (fresh state)"
else
    echo "   Mode: Keep data (preserving volumes)"
    docker compose down
    echo "✅ Stopped (data preserved for faster restart)"
fi

echo ""
echo "To start again:"
echo "   scripts/local-dev/start.sh"
echo ""
