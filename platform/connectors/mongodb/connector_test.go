// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodb

import (
	"context"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"axonflow/platform/connectors/base"
)

// getTestURI returns the MongoDB URI for testing
// Set MONGODB_TEST_URI environment variable for integration tests
func getTestURI() string {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		// Default URI for local testing with Docker
		uri = "mongodb://localhost:27017"
	}
	return uri
}

func skipIfNoMongoDB(t *testing.T) *MongoDBConnector {
	uri := getTestURI()

	// Try to connect
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
		return nil
	}
	defer client.Disconnect(ctx)

	if err := client.Ping(ctx, nil); err != nil {
		t.Skipf("MongoDB not available: %v", err)
		return nil
	}

	c := NewMongoDBConnector()
	err = c.Connect(context.Background(), &base.ConnectorConfig{
		Name:          "test-mongodb",
		ConnectionURL: uri,
		Timeout:       30 * time.Second,
		Options: map[string]interface{}{
			"database": "axonflow_test",
		},
	})
	if err != nil {
		t.Skipf("Failed to connect: %v", err)
		return nil
	}

	return c
}

func TestNewMongoDBConnector(t *testing.T) {
	c := NewMongoDBConnector()
	if c == nil {
		t.Fatal("NewMongoDBConnector returned nil")
	}
	if c.logger == nil {
		t.Error("expected logger to be initialized")
	}
}

func TestMongoDBConnector_Metadata(t *testing.T) {
	c := NewMongoDBConnector()

	if c.Type() != "mongodb" {
		t.Errorf("Type() = %s, want mongodb", c.Type())
	}
	if c.Version() != "1.0.0" {
		t.Errorf("Version() = %s, want 1.0.0", c.Version())
	}
	if c.Name() != "mongodb" {
		t.Errorf("Name() = %s, want mongodb", c.Name())
	}

	caps := c.Capabilities()
	expectedCaps := []string{
		"query",
		"execute",
		"aggregation",
		"connection_pooling",
		"transactions",
		"change_streams",
	}
	if len(caps) != len(expectedCaps) {
		t.Errorf("Capabilities() length = %d, want %d", len(caps), len(expectedCaps))
	}
}

func TestMongoDBConnector_BuildURI(t *testing.T) {
	c := NewMongoDBConnector()

	tests := []struct {
		name    string
		config  *base.ConnectorConfig
		wantErr bool
	}{
		{
			name: "full connection URL",
			config: &base.ConnectorConfig{
				Name:          "test",
				ConnectionURL: "mongodb://localhost:27017/testdb",
			},
			wantErr: false,
		},
		{
			name: "build from options",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"port":     float64(27017),
					"database": "testdb",
				},
			},
			wantErr: false,
		},
		{
			name: "with credentials",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"port":     float64(27017),
					"database": "testdb",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "with replica set",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"hosts":       "host1:27017,host2:27017",
					"database":    "testdb",
					"replica_set": "rs0",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := c.buildURI(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildURI() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && uri == "" {
				t.Error("buildURI() returned empty URI")
			}
		})
	}
}

func TestMongoDBConnector_ParseStatement(t *testing.T) {
	c := NewMongoDBConnector()

	tests := []struct {
		statement      string
		wantOperation  string
		wantCollection string
	}{
		{"find:users", "find", "users"},
		{"aggregate:orders", "aggregate", "orders"},
		{"users", "find", "users"},
	}

	for _, tt := range tests {
		t.Run(tt.statement, func(t *testing.T) {
			operation, collection := c.parseStatement(tt.statement)
			if operation != tt.wantOperation {
				t.Errorf("parseStatement() operation = %s, want %s", operation, tt.wantOperation)
			}
			if collection != tt.wantCollection {
				t.Errorf("parseStatement() collection = %s, want %s", collection, tt.wantCollection)
			}
		})
	}
}

func TestMongoDBConnector_ConvertToBSONValue(t *testing.T) {
	c := NewMongoDBConnector()

	tests := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "simple map",
			input: map[string]interface{}{"key": "value"},
		},
		{
			name:  "nested map",
			input: map[string]interface{}{"outer": map[string]interface{}{"inner": "value"}},
		},
		{
			name:  "array",
			input: []interface{}{1, 2, 3},
		},
		{
			name: "ObjectID",
			input: map[string]interface{}{
				"$oid": "507f1f77bcf86cd799439011",
			},
		},
		{
			name: "Date",
			input: map[string]interface{}{
				"$date": "2024-01-15T10:30:00Z",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.convertToBSONValue(tt.input)
			if result == nil {
				t.Error("convertToBSONValue() returned nil")
			}
		})
	}
}

func TestMongoDBConnector_ConvertFromBSON(t *testing.T) {
	c := NewMongoDBConnector()

	objectID := primitive.NewObjectID()
	dateTime := primitive.DateTime(time.Now().UnixMilli())

	tests := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "ObjectID",
			input: objectID,
		},
		{
			name:  "DateTime",
			input: dateTime,
		},
		{
			name:  "bson.M",
			input: bson.M{"key": "value"},
		},
		{
			name:  "bson.A",
			input: bson.A{1, 2, 3},
		},
		{
			name:  "string",
			input: "hello",
		},
		{
			name:  "int",
			input: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.convertFromBSON(tt.input)
			if result == nil && tt.input != nil {
				t.Error("convertFromBSON() returned nil for non-nil input")
			}
		})
	}
}

func TestMongoDBConnector_ParamsToBSON(t *testing.T) {
	c := NewMongoDBConnector()

	tests := []struct {
		name    string
		params  map[string]interface{}
		wantErr bool
	}{
		{
			name:    "nil params",
			params:  nil,
			wantErr: false,
		},
		{
			name: "explicit filter",
			params: map[string]interface{}{
				"filter": map[string]interface{}{"status": "active"},
			},
			wantErr: false,
		},
		{
			name: "direct params",
			params: map[string]interface{}{
				"status": "active",
				"age":    25,
			},
			wantErr: false,
		},
		{
			name: "with special keys",
			params: map[string]interface{}{
				"status":     "active",
				"_internal":  "ignored",
				"sort":       map[string]interface{}{"name": 1},
				"projection": map[string]interface{}{"name": 1},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := c.paramsToBSON(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("paramsToBSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && result == nil {
				t.Error("paramsToBSON() returned nil")
			}
		})
	}
}

func TestMongoDBConnector_Connect_MissingDatabase(t *testing.T) {
	c := NewMongoDBConnector()

	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name:          "test-mongodb",
		ConnectionURL: "mongodb://localhost:27017",
		Options:       map[string]interface{}{},
	})

	if err == nil {
		c.Disconnect(context.Background())
		t.Error("expected error for missing database")
	}
}

func TestMongoDBConnector_DisconnectWithoutConnect(t *testing.T) {
	c := NewMongoDBConnector()

	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("Disconnect() error = %v, want nil", err)
	}
}

func TestMongoDBConnector_QueryWithoutConnect(t *testing.T) {
	c := NewMongoDBConnector()

	_, err := c.Query(context.Background(), &base.Query{
		Statement: "find:users",
	})

	if err == nil {
		t.Error("expected error when querying without connection")
	}
}

func TestMongoDBConnector_ExecuteWithoutConnect(t *testing.T) {
	c := NewMongoDBConnector()

	_, err := c.Execute(context.Background(), &base.Command{
		Action:    "insert",
		Statement: "users",
		Parameters: map[string]interface{}{
			"document": map[string]interface{}{"name": "test"},
		},
	})

	if err == nil {
		t.Error("expected error when executing without connection")
	}
}

func TestMongoDBConnector_HealthCheckWithoutConnect(t *testing.T) {
	c := NewMongoDBConnector()

	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status when not connected")
	}
}

// Integration tests - run with actual MongoDB
func TestMongoDBConnector_Integration_Connect(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	if c.client == nil {
		t.Error("expected client to be initialized")
	}
	if c.database == nil {
		t.Error("expected database to be initialized")
	}
}

func TestMongoDBConnector_Integration_HealthCheck(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if !status.Healthy {
		t.Errorf("expected healthy status, got error: %s", status.Error)
	}
}

func TestMongoDBConnector_Integration_CRUD(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	ctx := context.Background()
	collectionName := "connector_test"

	// Clean up before test
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	// Test INSERT
	result, err := c.Execute(ctx, &base.Command{
		Action:    "insert",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"document": map[string]interface{}{
				"name":  "Alice",
				"email": "alice@example.com",
				"age":   30,
			},
		},
	})
	if err != nil {
		t.Fatalf("INSERT failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}

	// Test FIND
	queryResult, err := c.Query(ctx, &base.Query{
		Statement: "find:" + collectionName,
		Parameters: map[string]interface{}{
			"name": "Alice",
		},
	})
	if err != nil {
		t.Fatalf("FIND failed: %v", err)
	}
	if queryResult.RowCount != 1 {
		t.Errorf("expected 1 row, got %d", queryResult.RowCount)
	}
	if queryResult.Rows[0]["email"] != "alice@example.com" {
		t.Errorf("unexpected email: %v", queryResult.Rows[0]["email"])
	}

	// Test UPDATE
	result, err = c.Execute(ctx, &base.Command{
		Action:    "updateOne",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"name": "Alice"},
			"update": map[string]interface{}{
				"$set": map[string]interface{}{"age": 31},
			},
		},
	})
	if err != nil {
		t.Fatalf("UPDATE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}

	// Verify update
	queryResult, err = c.Query(ctx, &base.Query{
		Statement: "findOne:" + collectionName,
		Parameters: map[string]interface{}{
			"name": "Alice",
		},
	})
	if err != nil {
		t.Fatalf("FIND after UPDATE failed: %v", err)
	}
	// Age comes back as float64 from JSON
	age, ok := queryResult.Rows[0]["age"].(int32)
	if !ok {
		// Try float64 conversion
		if ageFloat, ok := queryResult.Rows[0]["age"].(float64); ok {
			age = int32(ageFloat)
		}
	}
	if age != 31 {
		t.Errorf("expected age 31, got %v", queryResult.Rows[0]["age"])
	}

	// Test DELETE
	result, err = c.Execute(ctx, &base.Command{
		Action:    "deleteOne",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"name": "Alice"},
		},
	})
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}

	// Verify deletion
	queryResult, err = c.Query(ctx, &base.Query{
		Statement: "count:" + collectionName,
		Parameters: map[string]interface{}{
			"name": "Alice",
		},
	})
	if err != nil {
		t.Fatalf("COUNT after DELETE failed: %v", err)
	}
	count, _ := queryResult.Rows[0]["count"].(int64)
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}

func TestMongoDBConnector_Integration_InsertMany(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	ctx := context.Background()
	collectionName := "insertmany_test"

	// Clean up
	defer func() {
		c.Execute(ctx, &base.Command{
			Action:    "deleteMany",
			Statement: collectionName,
			Parameters: map[string]interface{}{
				"filter": map[string]interface{}{},
			},
		})
	}()

	// Insert multiple documents
	result, err := c.Execute(ctx, &base.Command{
		Action:    "insertMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"documents": []interface{}{
				map[string]interface{}{"name": "Doc1"},
				map[string]interface{}{"name": "Doc2"},
				map[string]interface{}{"name": "Doc3"},
			},
		},
	})
	if err != nil {
		t.Fatalf("InsertMany failed: %v", err)
	}
	if result.RowsAffected != 3 {
		t.Errorf("expected 3 rows affected, got %d", result.RowsAffected)
	}
}

func TestMongoDBConnector_Integration_Aggregation(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	ctx := context.Background()
	collectionName := "agg_test"

	// Clean up and insert test data
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	defer func() {
		c.Execute(ctx, &base.Command{
			Action:    "deleteMany",
			Statement: collectionName,
			Parameters: map[string]interface{}{
				"filter": map[string]interface{}{},
			},
		})
	}()

	// Insert test data
	c.Execute(ctx, &base.Command{
		Action:    "insertMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"documents": []interface{}{
				map[string]interface{}{"category": "A", "value": 10},
				map[string]interface{}{"category": "A", "value": 20},
				map[string]interface{}{"category": "B", "value": 30},
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
						"_id":   "$category",
						"total": map[string]interface{}{"$sum": "$value"},
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
		t.Errorf("expected 2 groups, got %d", result.RowCount)
	}
}

func TestMongoDBConnector_Integration_Distinct(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	ctx := context.Background()
	collectionName := "distinct_test"

	// Clean up
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	defer func() {
		c.Execute(ctx, &base.Command{
			Action:    "deleteMany",
			Statement: collectionName,
			Parameters: map[string]interface{}{
				"filter": map[string]interface{}{},
			},
		})
	}()

	// Insert test data
	c.Execute(ctx, &base.Command{
		Action:    "insertMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"documents": []interface{}{
				map[string]interface{}{"status": "active"},
				map[string]interface{}{"status": "active"},
				map[string]interface{}{"status": "inactive"},
			},
		},
	})

	// Get distinct values
	result, err := c.Query(ctx, &base.Query{
		Statement: "distinct:" + collectionName,
		Parameters: map[string]interface{}{
			"field": "status",
		},
	})
	if err != nil {
		t.Fatalf("Distinct failed: %v", err)
	}

	if result.RowCount != 2 {
		t.Errorf("expected 2 distinct values, got %d", result.RowCount)
	}
}

func TestMongoDBConnector_Integration_UpdateMany(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	ctx := context.Background()
	collectionName := "updatemany_test"

	// Clean up and insert test data
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	defer func() {
		c.Execute(ctx, &base.Command{
			Action:    "deleteMany",
			Statement: collectionName,
			Parameters: map[string]interface{}{
				"filter": map[string]interface{}{},
			},
		})
	}()

	// Insert test data
	c.Execute(ctx, &base.Command{
		Action:    "insertMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"documents": []interface{}{
				map[string]interface{}{"type": "A", "processed": false},
				map[string]interface{}{"type": "A", "processed": false},
				map[string]interface{}{"type": "B", "processed": false},
			},
		},
	})

	// Update many
	result, err := c.Execute(ctx, &base.Command{
		Action:    "updateMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"type": "A"},
			"update": map[string]interface{}{
				"$set": map[string]interface{}{"processed": true},
			},
		},
	})
	if err != nil {
		t.Fatalf("UpdateMany failed: %v", err)
	}

	if result.RowsAffected != 2 {
		t.Errorf("expected 2 rows affected, got %d", result.RowsAffected)
	}
}

func TestMongoDBConnector_Integration_ReplaceOne(t *testing.T) {
	c := skipIfNoMongoDB(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	ctx := context.Background()
	collectionName := "replace_test"

	// Clean up and insert test data
	c.Execute(ctx, &base.Command{
		Action:    "deleteMany",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{},
		},
	})

	defer func() {
		c.Execute(ctx, &base.Command{
			Action:    "deleteMany",
			Statement: collectionName,
			Parameters: map[string]interface{}{
				"filter": map[string]interface{}{},
			},
		})
	}()

	// Insert test data
	c.Execute(ctx, &base.Command{
		Action:    "insert",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"document": map[string]interface{}{
				"name": "original",
				"data": "old",
			},
		},
	})

	// Replace document
	result, err := c.Execute(ctx, &base.Command{
		Action:    "replaceOne",
		Statement: collectionName,
		Parameters: map[string]interface{}{
			"filter": map[string]interface{}{"name": "original"},
			"replacement": map[string]interface{}{
				"name":        "replaced",
				"data":        "new",
				"extra_field": "added",
			},
		},
	})
	if err != nil {
		t.Fatalf("ReplaceOne failed: %v", err)
	}

	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}

	// Verify replacement
	queryResult, err := c.Query(ctx, &base.Query{
		Statement: "findOne:" + collectionName,
		Parameters: map[string]interface{}{
			"name": "replaced",
		},
	})
	if err != nil {
		t.Fatalf("Find after replace failed: %v", err)
	}

	if queryResult.RowCount != 1 {
		t.Errorf("expected 1 result, got %d", queryResult.RowCount)
	}
	if queryResult.Rows[0]["extra_field"] != "added" {
		t.Error("replacement didn't include new fields")
	}
}
