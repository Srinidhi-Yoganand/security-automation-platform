#!/bin/bash
# Create CodeQL database for a Java project

if [ -z "$1" ]; then
    echo "Usage: ./create-codeql-db.sh <java-project-path>"
    exit 1
fi

PROJECT_PATH=$1
DB_NAME=$(basename $PROJECT_PATH)-codeql-db

echo "Creating CodeQL database for: $PROJECT_PATH"
echo "Database name: $DB_NAME"

mkdir -p codeql-databases

./tools/codeql/codeql database create \
    codeql-databases/$DB_NAME \
    --language=java \
    --source-root=$PROJECT_PATH \
    --command="mvn clean compile -DskipTests" \
    --overwrite

echo "✅ Database created: codeql-databases/$DB_NAME"
