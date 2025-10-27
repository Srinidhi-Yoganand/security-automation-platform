#!/bin/bash
# Run custom CodeQL queries on a database

if [ -z "$1" ]; then
    echo "Usage: ./run-codeql-queries.sh <database-path>"
    exit 1
fi

DB_PATH=$1
OUTPUT_DIR="codeql-results"

echo "Running CodeQL queries on: $DB_PATH"
mkdir -p $OUTPUT_DIR

./tools/codeql/codeql database analyze $DB_PATH \
    codeql-queries/idor-detection.ql \
    --format=sarif-latest \
    --output=$OUTPUT_DIR/idor-results.sarif

./tools/codeql/codeql database analyze $DB_PATH \
    codeql-queries/idor-detection.ql \
    --format=csv \
    --output=$OUTPUT_DIR/idor-results.csv

echo "✅ Results saved to: $OUTPUT_DIR/"
