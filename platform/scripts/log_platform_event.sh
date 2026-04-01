#!/bin/bash

# Script to log platform events for display in the dashboard
# Usage: ./log_platform_event.sh "event_type" "description" [details]

EVENTS_FILE="/home/ubuntu/platform_events.json"
MAX_EVENTS=100

# Parse arguments
EVENT_TYPE="${1:-system}"
DESCRIPTION="${2:-Platform event}"
DETAILS="${3:-}"

# Create timestamp
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Create event JSON
EVENT=$(cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "type": "$EVENT_TYPE",
  "description": "$DESCRIPTION",
  "details": "$DETAILS"
}
EOF
)

# Ensure events file exists
if [ ! -f "$EVENTS_FILE" ]; then
    echo '{"events": []}' > $EVENTS_FILE
fi

# Add event to file
if command -v jq &> /dev/null; then
    # Use jq if available for proper JSON handling
    jq ".events = ([$EVENT] + .events) | .events = .events[0:$MAX_EVENTS]" $EVENTS_FILE > ${EVENTS_FILE}.tmp && mv ${EVENTS_FILE}.tmp $EVENTS_FILE
else
    # Simple append without jq (less robust)
    echo "$EVENT" >> ${EVENTS_FILE}.log
fi

echo "Event logged: $EVENT_TYPE - $DESCRIPTION"