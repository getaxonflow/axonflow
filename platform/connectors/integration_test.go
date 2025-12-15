// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

// Package connectors provides integration tests for all database connectors.
//
// Run these tests with Docker containers:
//
//	# Start test containers
//	docker run -d --name mysql-test -p 3306:3306 \
//	  -e MYSQL_ROOT_PASSWORD=testpassword \
//	  -e MYSQL_DATABASE=testdb \
//	  mysql:8
//
//	docker run -d --name mongo-test -p 27017:27017 mongo:6
//
//	# Run integration tests
//	go test -tags=integration ./connectors/...
//
//	# Clean up
//	docker rm -f mysql-test mongo-test
package connectors

import (
	"context"
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/mongodb"
	"axonflow/platform/connectors/mysql"
)

// TestMain sets up and tears down test infrastructure
func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()
	os.Exit(code)
}

// MySQL Integration Tests

func TestMySQL_FullCRUD(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		dsn = "root:testpassword@tcp(localhost:3306)/testdb?parseTime=true"
	}

	c := mysql.NewMySQLConnector()
	ctx := context.Background()

	// Connect
	err := c.Connect(ctx, &base.ConnectorConfig{
		Name:          "mysql-integration-test",
		ConnectionURL: dsn,
		Timeout:       30 * time.Second,
	})
	if err != nil {
		t.Skipf("MySQL not available: %v", err)
	}
	defer c.Disconnect(ctx)

	// Create table
	_, err = c.Execute(ctx, &base.Command{
		Action:    "CREATE",
		Statement: "CREATE TABLE IF NOT EXISTS integration_test (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
	})
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Clean up at end
	defer c.Execute(ctx, &base.Command{
		Action:    "DROP",
		Statement: "DROP TABLE IF EXISTS integration_test",
	})

	// INSERT
	result, err := c.Execute(ctx, &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO integration_test (name) VALUES (?)",
		Parameters: map[string]interface{}{
			"0": "Test User",
		},
	})
	if err != nil {
		t.Fatalf("INSERT failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", result.RowsAffected)
	}

	// SELECT
	queryResult, err := c.Query(ctx, &base.Query{
		Statement: "SELECT id, name, created_at FROM integration_test WHERE name = ?",
		Parameters: map[string]interface{}{
			"0": "Test User",
		},
	})
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	if queryResult.RowCount != 1 {
		t.Errorf("Expected 1 row, got %d", queryResult.RowCount)
	}
	if queryResult.Rows[0]["name"] != "Test User" {
		t.Errorf("Unexpected name: %v", queryResult.Rows[0]["name"])
	}

	// UPDATE
	result, err = c.Execute(ctx, &base.Command{
		Action:    "UPDATE",
		Statement: "UPDATE integration_test SET name = ? WHERE name = ?",
		Parameters: map[string]interface{}{
			"0": "Updated User",
			"1": "Test User",
		},
	})
	if err != nil {
		t.Fatalf("UPDATE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", result.RowsAffected)
	}

	// DELETE
	result, err = c.Execute(ctx, &base.Command{
		Action:    "DELETE",
		Statement: "DELETE FROM integration_test WHERE name = ?",
		Parameters: map[string]interface{}{
			"0": "Updated User",
		},
	})
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", result.RowsAffected)
	}

	// Verify deletion
	queryResult, err = c.Query(ctx, &base.Query{
		Statement: "SELECT COUNT(*) as cnt FROM integration_test",
	})
	if err != nil {
		t.Fatalf("COUNT failed: %v", err)
	}
}

func TestMySQL_Transaction(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		dsn = "root:testpassword@tcp(localhost:3306)/testdb?parseTime=true"
	}

	c := mysql.NewMySQLConnector()
	ctx := context.Background()

	err := c.Connect(ctx, &base.ConnectorConfig{
		Name:          "mysql-tx-test",
		ConnectionURL: dsn,
		Timeout:       30 * time.Second,
	})
	if err != nil {
		t.Skipf("MySQL not available: %v", err)
	}
	defer c.Disconnect(ctx)

	// Create table
	c.Execute(ctx, &base.Command{
		Action:    "CREATE",
		Statement: "CREATE TABLE IF NOT EXISTS tx_test (id INT PRIMARY KEY, value INT)",
	})
	defer c.Execute(ctx, &base.Command{
		Action:    "DROP",
		Statement: "DROP TABLE IF EXISTS tx_test",
	})

	// Test transaction commit
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO tx_test (id, value) VALUES (1, 100)")
	if err != nil {
		tx.Rollback()
		t.Fatalf("INSERT in transaction failed: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify commit
	result, _ := c.Query(ctx, &base.Query{
		Statement: "SELECT value FROM tx_test WHERE id = 1",
	})
	if result.RowCount != 1 {
		t.Error("Transaction commit didn't persist data")
	}

	// Test transaction rollback
	tx2, _ := c.BeginTx(ctx, nil)
	tx2.ExecContext(ctx, "UPDATE tx_test SET value = 200 WHERE id = 1")
	tx2.Rollback()

	// Verify rollback
	result, _ = c.Query(ctx, &base.Query{
		Statement: "SELECT value FROM tx_test WHERE id = 1",
	})
	if result.Rows[0]["value"].(int64) != 100 {
		t.Error("Transaction rollback didn't revert changes")
	}
}

// MongoDB Integration Tests

func TestMongoDB_FullCRUD(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}

	c := mongodb.NewMongoDBConnector()
	ctx := context.Background()

	err := c.Connect(ctx, &base.ConnectorConfig{
		Name:          "mongo-integration-test",
		ConnectionURL: uri,
		Timeout:       30 * time.Second,
		Options: map[string]interface{}{
			"database": "axonflow_integration_test",
		},
	})
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	defer c.Disconnect(ctx)

	collectionName := "integration_test"

	// Clean up collection
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	// INSERT
	result, err := c.Execute(ctx, &base.Command{
		Action:    "insert",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"document": map[string]interface{}{
				"name":  "Test User",
				"email": "test@example.com",
				"age":   25,
			},
		},
	})
	if err != nil {
		t.Fatalf("INSERT failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", result.RowsAffected)
	}

	// FIND
	queryResult, err := c.Query(ctx, &base.Query{
		Statement: "find:" + collectionName,
		Parameters: map[string]interface{}{
			"name": "Test User",
		},
	})
	if err != nil {
		t.Fatalf("FIND failed: %v", err)
	}
	if queryResult.RowCount != 1 {
		t.Errorf("Expected 1 row, got %d", queryResult.RowCount)
	}
	if queryResult.Rows[0]["email"] != "test@example.com" {
		t.Errorf("Unexpected email: %v", queryResult.Rows[0]["email"])
	}

	// UPDATE
	result, err = c.Execute(ctx, &base.Command{
		Action:    "updateOne",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"name": "Test User"},
			"update": map[string]interface{}{
				"$set": map[string]interface{}{"age": 26},
			},
		},
	})
	if err != nil {
		t.Fatalf("UPDATE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", result.RowsAffected)
	}

	// DELETE
	result, err = c.Execute(ctx, &base.Command{
		Action:    "deleteOne",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"name": "Test User"},
		},
	})
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", result.RowsAffected)
	}

	// Verify deletion
	queryResult, _ = c.Query(ctx, &base.Query{
		Statement: "count:" + collectionName,
		Parameters: map[string]interface{}{
			"name": "Test User",
		},
	})
	if count, _ := queryResult.Rows[0]["count"].(int64); count != 0 {
		t.Error("Document not deleted")
	}
}

func TestMongoDB_Aggregation(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}

	c := mongodb.NewMongoDBConnector()
	ctx := context.Background()

	err := c.Connect(ctx, &base.ConnectorConfig{
		Name:          "mongo-agg-test",
		ConnectionURL: uri,
		Timeout:       30 * time.Second,
		Options: map[string]interface{}{
			"database": "axonflow_integration_test",
		},
	})
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	defer c.Disconnect(ctx)

	collectionName := "agg_test"

	// Clean up and insert test data
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	c.Execute(ctx, &base.Command{
		Action:    "insertMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"documents": []interface{}{
				map[string]interface{}{"category": "electronics", "price": 100},
				map[string]interface{}{"category": "electronics", "price": 200},
				map[string]interface{}{"category": "clothing", "price": 50},
				map[string]interface{}{"category": "clothing", "price": 75},
			},
		},
	})

	// Run aggregation
	result, err := c.Query(ctx, &base.Query{
		Statement: "aggregate:" + collectionName,
		Parameters: map[string]interface{}{
			"pipeline": []interface{}{
				map[string]interface{}{
					"$group": map[string]interface{}{
						"_id":        "$category",
						"totalPrice": map[string]interface{}{"$sum": "$price"},
						"avgPrice":   map[string]interface{}{"$avg": "$price"},
						"count":      map[string]interface{}{"$sum": 1},
					},
				},
				map[string]interface{}{
					"$sort": map[string]interface{}{"_id": 1},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Aggregation failed: %v", err)
	}

	if result.RowCount != 2 {
		t.Errorf("Expected 2 groups, got %d", result.RowCount)
	}

	// Clean up
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})
}

func TestMongoDB_BulkOperations(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}

	c := mongodb.NewMongoDBConnector()
	ctx := context.Background()

	err := c.Connect(ctx, &base.ConnectorConfig{
		Name:          "mongo-bulk-test",
		ConnectionURL: uri,
		Timeout:       30 * time.Second,
		Options: map[string]interface{}{
			"database": "axonflow_integration_test",
		},
	})
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	defer c.Disconnect(ctx)

	collectionName := "bulk_test"

	// Clean up
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	// Insert many
	result, err := c.Execute(ctx, &base.Command{
		Action:    "insertMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"documents": []interface{}{
				map[string]interface{}{"name": "Doc1", "status": "pending"},
				map[string]interface{}{"name": "Doc2", "status": "pending"},
				map[string]interface{}{"name": "Doc3", "status": "pending"},
				map[string]interface{}{"name": "Doc4", "status": "pending"},
				map[string]interface{}{"name": "Doc5", "status": "pending"},
			},
		},
	})
	if err != nil {
		t.Fatalf("InsertMany failed: %v", err)
	}
	if result.RowsAffected != 5 {
		t.Errorf("Expected 5 rows affected, got %d", result.RowsAffected)
	}

	// Update many
	result, err = c.Execute(ctx, &base.Command{
		Action:    "updateMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"status": "pending"},
			"update": map[string]interface{}{
				"$set": map[string]interface{}{"status": "processed"},
			},
		},
	})
	if err != nil {
		t.Fatalf("UpdateMany failed: %v", err)
	}
	if result.RowsAffected != 5 {
		t.Errorf("Expected 5 rows affected, got %d", result.RowsAffected)
	}

	// Delete many
	result, err = c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"status": "processed"},
		},
	})
	if err != nil {
		t.Fatalf("DeleteMany failed: %v", err)
	}
	if result.RowsAffected != 5 {
		t.Errorf("Expected 5 rows affected, got %d", result.RowsAffected)
	}
}
