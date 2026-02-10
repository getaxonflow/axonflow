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

package mongodb

import (
	"context"
	"os"
	"strings"
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

func TestMongoDBConnector_NameWithConfig(t *testing.T) {
	c := NewMongoDBConnector()

	// Without config, returns default
	if c.Name() != "mongodb" {
		t.Errorf("Name() = %s, want mongodb", c.Name())
	}

	// With config
	c.config = &base.ConnectorConfig{Name: "my-mongo"}
	if c.Name() != "my-mongo" {
		t.Errorf("Name() = %s, want my-mongo", c.Name())
	}

	// With empty config name, returns empty
	c.config = &base.ConnectorConfig{}
	if c.Name() != "" {
		t.Errorf("Name() = %s, want empty string", c.Name())
	}
}

func TestMongoDBConnector_ToBSON_EdgeCases(t *testing.T) {
	c := NewMongoDBConnector()

	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
	}{
		{"nil input", nil, true},              // nil can't be converted to bson.M
		{"empty string", "", true},            // empty string is invalid JSON
		{"integer", 42, true},                 // int can't be converted to bson.M
		{"float", 3.14, true},                 // float can't be converted to bson.M
		{"bool", true, true},                  // bool can't be converted to bson.M
		{"slice", []interface{}{"a"}, true},   // slice can't be converted to bson.M
		{"bson.M input", bson.M{"key": "value"}, false},
		{"map[string]interface{}", map[string]interface{}{"key": "value"}, false},
		{"valid JSON string", `{"key": "value"}`, false},
		{"invalid JSON string", `{invalid}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := c.toBSON(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("toBSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && result == nil {
				t.Error("toBSON() returned nil for valid input")
			}
		})
	}
}

func TestMongoDBConnector_ConvertFromBSON_MoreTypes(t *testing.T) {
	c := NewMongoDBConnector()

	binary := primitive.Binary{Subtype: 0, Data: []byte("hello")}

	tests := []struct {
		name  string
		input interface{}
	}{
		{"nil input", nil},
		{"binary", binary},
		{"nested bson.M", bson.M{"outer": bson.M{"inner": "value"}}},
		{"bson.A with mixed types", bson.A{1, "two", 3.0}},
		{"empty bson.M", bson.M{}},
		{"empty bson.A", bson.A{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.convertFromBSON(tt.input)
			// Should not panic
			_ = result
		})
	}
}

func TestMongoDBConnector_BuildURI_EdgeCases(t *testing.T) {
	c := NewMongoDBConnector()

	tests := []struct {
		name    string
		config  *base.ConnectorConfig
		wantErr bool
	}{
		{
			name: "with authSource option",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":       "localhost",
					"port":       float64(27017),
					"database":   "testdb",
					"authSource": "admin",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "port as string",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"port":     "27017", // string instead of float64
					"database": "testdb",
				},
			},
			wantErr: false,
		},
		{
			name: "default port when not specified",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"database": "testdb",
				},
			},
			wantErr: false,
		},
		{
			name: "SRV connection",
			config: &base.ConnectorConfig{
				Name:          "test",
				ConnectionURL: "mongodb+srv://cluster0.example.mongodb.net/testdb",
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

func TestMongoDBConnector_QueryWithConfig(t *testing.T) {
	c := NewMongoDBConnector()
	c.config = &base.ConnectorConfig{Name: "test-mongo"}

	// Query should fail due to no connection but config should be used for error message
	_, err := c.Query(context.Background(), &base.Query{
		Statement: "find:users",
	})

	if err == nil {
		t.Error("expected error when querying without connection")
	}
	// Error should contain the config name
	if !strings.Contains(err.Error(), "test-mongo") {
		t.Errorf("error should contain config name, got: %v", err)
	}
}

func TestMongoDBConnector_ExecuteWithConfig(t *testing.T) {
	c := NewMongoDBConnector()
	c.config = &base.ConnectorConfig{Name: "test-mongo"}

	// Execute should fail due to no connection but config should be used for error message
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

// =============================================================================
// Additional unit tests for coverage improvement
// All tests below exercise parsing, conversion, routing, and validation logic
// without requiring a real MongoDB connection.
// =============================================================================

func TestParseStatement_CaseVariations(t *testing.T) {
	c := NewMongoDBConnector()

	tests := []struct {
		name           string
		statement      string
		wantOperation  string
		wantCollection string
	}{
		{"uppercase operation", "FIND:users", "FIND", "users"},
		{"mixed case operation", "FindOne:products", "FindOne", "products"},
		{"aggregate mixed case", "Aggregate:orders", "Aggregate", "orders"},
		{"count operation", "count:metrics", "count", "metrics"},
		{"distinct operation", "distinct:categories", "distinct", "categories"},
		{"colon in collection name", "find:my:collection", "find", "my:collection"},
		{"empty operation with colon", ":users", "", "users"},
		{"just a colon", ":", "", ""},
		{"operation only no collection", "find:", "find", ""},
		{"whitespace in operation", " find :users", " find ", "users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operation, collection := c.parseStatement(tt.statement)
			if operation != tt.wantOperation {
				t.Errorf("parseStatement(%q) operation = %q, want %q", tt.statement, operation, tt.wantOperation)
			}
			if collection != tt.wantCollection {
				t.Errorf("parseStatement(%q) collection = %q, want %q", tt.statement, collection, tt.wantCollection)
			}
		})
	}
}

func TestParseStatement_DefaultCollection(t *testing.T) {
	c := NewMongoDBConnector()
	c.collection = "default_coll"

	// When no colon is present and default collection is set,
	// statement becomes the operation, collection becomes the default
	operation, collection := c.parseStatement("find")
	if operation != "find" {
		t.Errorf("operation = %q, want %q", operation, "find")
	}
	if collection != "default_coll" {
		t.Errorf("collection = %q, want %q", collection, "default_coll")
	}

	// With a colon, default collection is not used
	operation, collection = c.parseStatement("aggregate:orders")
	if operation != "aggregate" {
		t.Errorf("operation = %q, want %q", operation, "aggregate")
	}
	if collection != "orders" {
		t.Errorf("collection = %q, want %q", collection, "orders")
	}
}

func TestParseStatement_NoColonNoDefaultCollection(t *testing.T) {
	c := NewMongoDBConnector()
	// No default collection set, no colon in statement
	// Should default to operation="find", collection=statement
	operation, collection := c.parseStatement("myCollection")
	if operation != "find" {
		t.Errorf("operation = %q, want %q", operation, "find")
	}
	if collection != "myCollection" {
		t.Errorf("collection = %q, want %q", collection, "myCollection")
	}
}

func TestBuildURI_WithTLS(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-tls",
		Options: map[string]interface{}{
			"host":     "mongo.example.com",
			"port":     float64(27017),
			"database": "testdb",
			"tls":      true,
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if !strings.Contains(uri, "tls=true") {
		t.Errorf("URI should contain tls=true, got: %s", uri)
	}
}

func TestBuildURI_WithTLSInsecure(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-tls-insecure",
		Options: map[string]interface{}{
			"host":         "mongo.example.com",
			"port":         float64(27017),
			"database":     "testdb",
			"tls":          true,
			"tls_insecure": true,
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if !strings.Contains(uri, "tls=true") {
		t.Errorf("URI should contain tls=true, got: %s", uri)
	}
	if !strings.Contains(uri, "tlsInsecure=true") {
		t.Errorf("URI should contain tlsInsecure=true, got: %s", uri)
	}
}

func TestBuildURI_WithDirectConnection(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-direct",
		Options: map[string]interface{}{
			"host":              "mongo.example.com",
			"port":              float64(27017),
			"database":          "testdb",
			"direct_connection": true,
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if !strings.Contains(uri, "directConnection=true") {
		t.Errorf("URI should contain directConnection=true, got: %s", uri)
	}
}

func TestBuildURI_WithAuthDatabase(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-authdb",
		Options: map[string]interface{}{
			"host":          "mongo.example.com",
			"port":          float64(27017),
			"database":      "testdb",
			"auth_database": "admin",
		},
		Credentials: map[string]string{
			"username": "admin_user",
			"password": "admin_pass",
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if !strings.Contains(uri, "authSource=admin") {
		t.Errorf("URI should contain authSource=admin, got: %s", uri)
	}
	if !strings.Contains(uri, "admin_user:admin_pass@") {
		t.Errorf("URI should contain credentials, got: %s", uri)
	}
}

func TestBuildURI_WithReplicaSetAndMultipleHosts(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-replicaset",
		Options: map[string]interface{}{
			"hosts":       "host1:27017,host2:27018,host3:27019",
			"database":    "testdb",
			"replica_set": "myReplicaSet",
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if !strings.Contains(uri, "host1:27017,host2:27018,host3:27019") {
		t.Errorf("URI should contain all hosts, got: %s", uri)
	}
	if !strings.Contains(uri, "replicaSet=myReplicaSet") {
		t.Errorf("URI should contain replicaSet, got: %s", uri)
	}
}

func TestBuildURI_CredentialsWithSpecialCharacters(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-special-creds",
		Options: map[string]interface{}{
			"host":     "mongo.example.com",
			"port":     float64(27017),
			"database": "testdb",
		},
		Credentials: map[string]string{
			"username": "user@domain",
			"password": "p@ss:w0rd/test",
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	// The URI should contain the credentials (note: buildURI does not URL-encode)
	if !strings.Contains(uri, "user@domain") {
		t.Errorf("URI should contain username, got: %s", uri)
	}
}

func TestBuildURI_NoHostNoPort(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name:    "test-defaults",
		Options: map[string]interface{}{},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if !strings.Contains(uri, "localhost:27017") {
		t.Errorf("URI should default to localhost:27017, got: %s", uri)
	}
}

func TestBuildURI_NilOptions(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-nil-opts",
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if !strings.Contains(uri, "localhost:27017") {
		t.Errorf("URI should default to localhost:27017, got: %s", uri)
	}
}

func TestBuildURI_AllParamsCombined(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-all-params",
		Options: map[string]interface{}{
			"host":              "mongo.example.com",
			"port":              float64(27018),
			"database":          "mydb",
			"auth_database":     "admin",
			"replica_set":       "rs0",
			"tls":               true,
			"tls_insecure":      true,
			"direct_connection": true,
		},
		Credentials: map[string]string{
			"username": "myuser",
			"password": "mypass",
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}

	expectations := []string{
		"mongodb://myuser:mypass@mongo.example.com:27018",
		"authSource=admin",
		"replicaSet=rs0",
		"tls=true",
		"tlsInsecure=true",
		"directConnection=true",
	}
	for _, exp := range expectations {
		if !strings.Contains(uri, exp) {
			t.Errorf("URI should contain %q, got: %s", exp, uri)
		}
	}
}

func TestBuildURI_TLSFalse(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-tls-false",
		Options: map[string]interface{}{
			"host":     "mongo.example.com",
			"port":     float64(27017),
			"database": "testdb",
			"tls":      false,
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if strings.Contains(uri, "tls=") {
		t.Errorf("URI should NOT contain tls parameter when tls=false, got: %s", uri)
	}
}

func TestBuildURI_DirectConnectionFalse(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-direct-false",
		Options: map[string]interface{}{
			"host":              "mongo.example.com",
			"port":              float64(27017),
			"database":          "testdb",
			"direct_connection": false,
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	if strings.Contains(uri, "directConnection=") {
		t.Errorf("URI should NOT contain directConnection parameter when false, got: %s", uri)
	}
}

func TestBuildURI_UsernameNoPassword(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-user-only",
		Options: map[string]interface{}{
			"host":     "mongo.example.com",
			"port":     float64(27017),
			"database": "testdb",
		},
		Credentials: map[string]string{
			"username": "myuser",
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	// Without both username and password, credentials should not be in the URI
	if strings.Contains(uri, "myuser") {
		t.Errorf("URI should not contain username when password is missing, got: %s", uri)
	}
}

func TestBuildURI_PasswordNoUsername(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name: "test-pass-only",
		Options: map[string]interface{}{
			"host":     "mongo.example.com",
			"port":     float64(27017),
			"database": "testdb",
		},
		Credentials: map[string]string{
			"password": "mypass",
		},
	}

	uri, err := c.buildURI(config)
	if err != nil {
		t.Fatalf("buildURI() error = %v", err)
	}
	// Without both username and password, credentials should not be in the URI
	if strings.Contains(uri, "mypass") {
		t.Errorf("URI should not contain password when username is missing, got: %s", uri)
	}
}

func TestConvertToBSONValue_InvalidObjectID(t *testing.T) {
	c := NewMongoDBConnector()

	// Invalid hex string for ObjectID should return the original map (not convert to ObjectID)
	input := map[string]interface{}{
		"$oid": "not-a-valid-hex",
	}
	result := c.convertToBSONValue(input)

	// Since ObjectIDFromHex fails, it falls through to recursive map conversion
	resultMap, ok := result.(bson.M)
	if !ok {
		t.Fatalf("expected bson.M, got %T", result)
	}
	if resultMap["$oid"] != "not-a-valid-hex" {
		t.Errorf("expected original $oid value preserved, got %v", resultMap["$oid"])
	}
}

func TestConvertToBSONValue_InvalidDate(t *testing.T) {
	c := NewMongoDBConnector()

	// Invalid date string should return the original map
	input := map[string]interface{}{
		"$date": "not-a-date",
	}
	result := c.convertToBSONValue(input)

	resultMap, ok := result.(bson.M)
	if !ok {
		t.Fatalf("expected bson.M, got %T", result)
	}
	if resultMap["$date"] != "not-a-date" {
		t.Errorf("expected original $date value preserved, got %v", resultMap["$date"])
	}
}

func TestConvertToBSONValue_ValidObjectID(t *testing.T) {
	c := NewMongoDBConnector()

	input := map[string]interface{}{
		"$oid": "507f1f77bcf86cd799439011",
	}
	result := c.convertToBSONValue(input)

	oid, ok := result.(primitive.ObjectID)
	if !ok {
		t.Fatalf("expected primitive.ObjectID, got %T", result)
	}
	if oid.Hex() != "507f1f77bcf86cd799439011" {
		t.Errorf("ObjectID hex = %s, want 507f1f77bcf86cd799439011", oid.Hex())
	}
}

func TestConvertToBSONValue_ValidDate(t *testing.T) {
	c := NewMongoDBConnector()

	input := map[string]interface{}{
		"$date": "2024-06-15T10:30:00Z",
	}
	result := c.convertToBSONValue(input)

	parsed, ok := result.(time.Time)
	if !ok {
		t.Fatalf("expected time.Time, got %T", result)
	}
	if parsed.Year() != 2024 || parsed.Month() != 6 || parsed.Day() != 15 {
		t.Errorf("unexpected parsed date: %v", parsed)
	}
}

func TestConvertToBSONValue_ScalarTypes(t *testing.T) {
	c := NewMongoDBConnector()

	// Scalars should pass through unchanged
	tests := []struct {
		name  string
		input interface{}
	}{
		{"string", "hello"},
		{"int", 42},
		{"float64", 3.14},
		{"bool true", true},
		{"bool false", false},
		{"nil", nil},
		{"int64", int64(999)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.convertToBSONValue(tt.input)
			if result != tt.input {
				t.Errorf("expected %v, got %v", tt.input, result)
			}
		})
	}
}

func TestConvertToBSONValue_NestedArrayWithMaps(t *testing.T) {
	c := NewMongoDBConnector()

	input := []interface{}{
		map[string]interface{}{"name": "Alice"},
		map[string]interface{}{"name": "Bob"},
		"plain_string",
		42,
	}

	result := c.convertToBSONValue(input)
	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(arr) != 4 {
		t.Errorf("expected 4 elements, got %d", len(arr))
	}

	// First element should be converted to bson.M
	first, ok := arr[0].(bson.M)
	if !ok {
		t.Fatalf("expected bson.M for first element, got %T", arr[0])
	}
	if first["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", first["name"])
	}
}

func TestConvertToBSONValue_DeeplyNestedMap(t *testing.T) {
	c := NewMongoDBConnector()

	input := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": "deep_value",
			},
		},
	}

	result := c.convertToBSONValue(input)
	resultMap, ok := result.(bson.M)
	if !ok {
		t.Fatalf("expected bson.M, got %T", result)
	}

	l1, ok := resultMap["level1"].(bson.M)
	if !ok {
		t.Fatalf("expected bson.M at level1, got %T", resultMap["level1"])
	}

	l2, ok := l1["level2"].(bson.M)
	if !ok {
		t.Fatalf("expected bson.M at level2, got %T", l1["level2"])
	}

	if l2["level3"] != "deep_value" {
		t.Errorf("expected deep_value, got %v", l2["level3"])
	}
}

func TestConvertFromBSON_Timestamp(t *testing.T) {
	c := NewMongoDBConnector()

	ts := primitive.Timestamp{T: 1234567890, I: 1}
	result := c.convertFromBSON(ts)

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["t"] != uint32(1234567890) {
		t.Errorf("expected t=1234567890, got %v", resultMap["t"])
	}
	if resultMap["i"] != uint32(1) {
		t.Errorf("expected i=1, got %v", resultMap["i"])
	}
}

func TestConvertFromBSON_PrimitiveD(t *testing.T) {
	c := NewMongoDBConnector()

	input := primitive.D{
		{Key: "name", Value: "Alice"},
		{Key: "age", Value: int32(30)},
		{Key: "nested", Value: primitive.D{
			{Key: "city", Value: "NYC"},
		}},
	}

	result := c.convertFromBSON(input)
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	if resultMap["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", resultMap["name"])
	}
	if resultMap["age"] != int32(30) {
		t.Errorf("expected age=30, got %v", resultMap["age"])
	}

	nested, ok := resultMap["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested to be map, got %T", resultMap["nested"])
	}
	if nested["city"] != "NYC" {
		t.Errorf("expected city=NYC, got %v", nested["city"])
	}
}

func TestConvertFromBSON_Binary(t *testing.T) {
	c := NewMongoDBConnector()

	binary := primitive.Binary{Subtype: 0x00, Data: []byte{0x01, 0x02, 0x03}}
	result := c.convertFromBSON(binary)

	data, ok := result.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", result)
	}
	if len(data) != 3 || data[0] != 0x01 || data[1] != 0x02 || data[2] != 0x03 {
		t.Errorf("unexpected binary data: %v", data)
	}
}

func TestConvertFromBSON_ObjectIDHex(t *testing.T) {
	c := NewMongoDBConnector()

	oid, _ := primitive.ObjectIDFromHex("507f1f77bcf86cd799439011")
	result := c.convertFromBSON(oid)

	hex, ok := result.(string)
	if !ok {
		t.Fatalf("expected string, got %T", result)
	}
	if hex != "507f1f77bcf86cd799439011" {
		t.Errorf("expected 507f1f77bcf86cd799439011, got %s", hex)
	}
}

func TestConvertFromBSON_DateTime(t *testing.T) {
	c := NewMongoDBConnector()

	now := time.Now()
	dt := primitive.NewDateTimeFromTime(now)
	result := c.convertFromBSON(dt)

	resultTime, ok := result.(time.Time)
	if !ok {
		t.Fatalf("expected time.Time, got %T", result)
	}
	// Compare truncated to milliseconds since DateTime has millisecond precision
	if resultTime.UnixMilli() != now.UnixMilli() {
		t.Errorf("expected time %v, got %v", now.UnixMilli(), resultTime.UnixMilli())
	}
}

func TestConvertFromBSON_NestedBsonAWithObjects(t *testing.T) {
	c := NewMongoDBConnector()

	oid := primitive.NewObjectID()
	input := bson.A{
		bson.M{"_id": oid, "name": "doc1"},
		bson.M{"count": int32(5)},
	}

	result := c.convertFromBSON(input)
	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(arr) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(arr))
	}

	first, ok := arr[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", arr[0])
	}
	// ObjectID should be converted to hex string
	if _, ok := first["_id"].(string); !ok {
		t.Errorf("expected _id to be string (hex), got %T", first["_id"])
	}
}

func TestBsonToMap_EmptyDoc(t *testing.T) {
	c := NewMongoDBConnector()

	result := c.bsonToMap(bson.M{})
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d keys", len(result))
	}
}

func TestBsonToMap_ComplexDoc(t *testing.T) {
	c := NewMongoDBConnector()

	oid := primitive.NewObjectID()
	doc := bson.M{
		"_id":    oid,
		"name":   "test",
		"tags":   bson.A{"tag1", "tag2"},
		"nested": bson.M{"key": "value"},
	}

	result := c.bsonToMap(doc)

	if _, ok := result["_id"].(string); !ok {
		t.Errorf("expected _id as string, got %T", result["_id"])
	}
	if result["name"] != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
	tags, ok := result["tags"].([]interface{})
	if !ok {
		t.Fatalf("expected tags as []interface{}, got %T", result["tags"])
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
	nested, ok := result["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested as map, got %T", result["nested"])
	}
	if nested["key"] != "value" {
		t.Errorf("expected nested key=value, got %v", nested["key"])
	}
}

func TestParamsToBSON_WithDollarQuery(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"$query": map[string]interface{}{
			"status": "active",
			"age":    float64(25),
		},
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if result["status"] != "active" {
		t.Errorf("expected status=active, got %v", result["status"])
	}
}

func TestParamsToBSON_WithQueryKey(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"query": map[string]interface{}{
			"name": "test",
		},
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
}

func TestParamsToBSON_FilterAsJSONString(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"filter": `{"status": "active", "count": 5}`,
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if result["status"] != "active" {
		t.Errorf("expected status=active, got %v", result["status"])
	}
}

func TestParamsToBSON_FilterAsInvalidJSONString(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"filter": `{invalid json}`,
	}

	_, err := c.paramsToBSON(params)
	if err == nil {
		t.Error("expected error for invalid JSON filter")
	}
}

func TestParamsToBSON_AllSpecialKeysSkipped(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"status":     "active",
		"_internal":  "should_be_skipped",
		"sort":       map[string]interface{}{"name": 1},
		"projection": map[string]interface{}{"name": 1},
		"skip":       float64(10),
		"limit":      float64(20),
		"pipeline":   []interface{}{},
		"documents":  []interface{}{},
		"update":     map[string]interface{}{"$set": map[string]interface{}{"x": 1}},
		"field":      "status",
		"_other":     "also_skipped",
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}

	// Only "status" should remain
	if len(result) != 1 {
		t.Errorf("expected 1 key in filter, got %d: %v", len(result), result)
	}
	if result["status"] != "active" {
		t.Errorf("expected status=active, got %v", result["status"])
	}
}

func TestParamsToBSON_FilterPrecedenceOverQuery(t *testing.T) {
	c := NewMongoDBConnector()

	// When both "filter" and "query" are present, "filter" takes precedence
	params := map[string]interface{}{
		"filter": map[string]interface{}{"from_filter": true},
		"query":  map[string]interface{}{"from_query": true},
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if _, ok := result["from_filter"]; !ok {
		t.Error("expected filter key to be used, not query")
	}
}

func TestParamsToBSON_DollarQueryPrecedenceOverQuery(t *testing.T) {
	c := NewMongoDBConnector()

	// When both "$query" and "query" are present, "$query" takes precedence
	params := map[string]interface{}{
		"$query": map[string]interface{}{"from_dollar_query": true},
		"query":  map[string]interface{}{"from_query": true},
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if _, ok := result["from_dollar_query"]; !ok {
		t.Error("expected $query key to be used")
	}
}

func TestParamsToBSON_EmptyParams(t *testing.T) {
	c := NewMongoDBConnector()

	result, err := c.paramsToBSON(map[string]interface{}{})
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty filter, got %v", result)
	}
}

func TestToBSON_MapWithNestedConversion(t *testing.T) {
	c := NewMongoDBConnector()

	input := map[string]interface{}{
		"name": "test",
		"tags": []interface{}{"a", "b"},
		"nested": map[string]interface{}{
			"$oid": "507f1f77bcf86cd799439011",
		},
	}

	result, err := c.toBSON(input)
	if err != nil {
		t.Fatalf("toBSON() error = %v", err)
	}

	// The nested $oid should be converted to a primitive.ObjectID
	oid, ok := result["nested"].(primitive.ObjectID)
	if !ok {
		t.Fatalf("expected nested to be primitive.ObjectID, got %T", result["nested"])
	}
	if oid.Hex() != "507f1f77bcf86cd799439011" {
		t.Errorf("expected ObjectID hex = 507f1f77bcf86cd799439011, got %s", oid.Hex())
	}
}

func TestToBSON_ValidJSONString(t *testing.T) {
	c := NewMongoDBConnector()

	result, err := c.toBSON(`{"name": "test", "age": 25}`)
	if err != nil {
		t.Fatalf("toBSON() error = %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
	// JSON numbers are float64
	if result["age"] != float64(25) {
		t.Errorf("expected age=25, got %v", result["age"])
	}
}

func TestToBSON_BsonMPassthrough(t *testing.T) {
	c := NewMongoDBConnector()

	input := bson.M{"key": "value", "num": 42}
	result, err := c.toBSON(input)
	if err != nil {
		t.Fatalf("toBSON() error = %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result["key"])
	}
	if result["num"] != 42 {
		t.Errorf("expected num=42, got %v", result["num"])
	}
}

func TestQueryRouting_UnsupportedOperation(t *testing.T) {
	c := NewMongoDBConnector()
	c.config = &base.ConnectorConfig{Name: "test-mongo"}
	// Set client to non-nil via a workaround: we need to trigger the routing error,
	// not the "client not connected" error. Since we can't create a real client,
	// we test that the "client not connected" error is returned instead.
	_, err := c.Query(context.Background(), &base.Query{
		Statement: "invalidOperation:users",
	})
	if err == nil {
		t.Error("expected error for query without connection")
	}
	// The error should be about not being connected (client is nil)
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("expected 'not connected' error, got: %v", err)
	}
}

func TestExecuteRouting_UnsupportedAction(t *testing.T) {
	c := NewMongoDBConnector()
	c.config = &base.ConnectorConfig{Name: "test-mongo"}

	_, err := c.Execute(context.Background(), &base.Command{
		Action:    "invalidAction",
		Statement: "users",
	})
	if err == nil {
		t.Error("expected error for execute without connection")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("expected 'not connected' error, got: %v", err)
	}
}

func TestQuery_NilClient_ReturnsClientNotConnected(t *testing.T) {
	c := NewMongoDBConnector()
	c.config = &base.ConnectorConfig{Name: "test-mongo"}

	// With nil client, Query returns "client not connected" before routing.
	// This verifies the nil-client guard fires for all operation names.
	// Routing correctness requires an actual MongoDB connection (integration test).
	operations := []string{
		"find:users", "FIND:users", "Find:users",
		"findOne:users", "FINDONE:users",
		"aggregate:users", "count:users", "distinct:users",
	}

	for _, stmt := range operations {
		t.Run(stmt, func(t *testing.T) {
			_, err := c.Query(context.Background(), &base.Query{
				Statement: stmt,
			})
			if err == nil {
				t.Fatal("expected error without connection")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			if connErr.Message != "client not connected" {
				t.Errorf("expected 'client not connected', got %q", connErr.Message)
			}
		})
	}
}

func TestExecute_NilClient_ReturnsClientNotConnected(t *testing.T) {
	c := NewMongoDBConnector()
	c.config = &base.ConnectorConfig{Name: "test-mongo"}

	// With nil client, Execute returns "client not connected" before routing.
	// Routing correctness requires an actual MongoDB connection (integration test).
	actions := []string{
		"insert", "insertOne", "insertMany",
		"update", "updateOne", "updateMany",
		"delete", "deleteOne", "deleteMany",
		"replace", "replaceOne",
	}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			_, err := c.Execute(context.Background(), &base.Command{
				Action:    action,
				Statement: "users",
				Parameters: map[string]interface{}{
					"document": map[string]interface{}{"name": "test"},
				},
			})
			if err == nil {
				t.Fatal("expected error without connection")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			if connErr.Message != "client not connected" {
				t.Errorf("expected 'client not connected', got %q", connErr.Message)
			}
		})
	}
}

func TestConnect_NilConfig(t *testing.T) {
	c := NewMongoDBConnector()

	err := c.Connect(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !strings.Contains(err.Error(), "config is required") {
		t.Errorf("expected 'config is required' error, got: %v", err)
	}
}

func TestConnect_SetsDefaultType(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name:          "test-mongo",
		ConnectionURL: "mongodb://localhost:27017",
		Options: map[string]interface{}{
			"database": "testdb",
		},
	}

	// Connect will fail because there is no real MongoDB, but the config.Type
	// should be set before the connection attempt
	_ = c.Connect(context.Background(), config)

	if config.Type != "mongodb" {
		t.Errorf("expected config.Type = mongodb, got %s", config.Type)
	}
}

func TestConnect_PreservesExistingType(t *testing.T) {
	c := NewMongoDBConnector()

	config := &base.ConnectorConfig{
		Name:          "test-mongo",
		Type:          "custom-type",
		ConnectionURL: "mongodb://localhost:27017",
		Options: map[string]interface{}{
			"database": "testdb",
		},
	}

	_ = c.Connect(context.Background(), config)

	if config.Type != "custom-type" {
		t.Errorf("expected config.Type = custom-type (preserved), got %s", config.Type)
	}
}

func TestHealthCheck_NoClient(t *testing.T) {
	c := NewMongoDBConnector()

	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("HealthCheck() should not return error, got: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy when client is nil")
	}
	if status.Error != "client not connected" {
		t.Errorf("expected 'client not connected' error, got: %s", status.Error)
	}
}

func TestDisconnect_NilClient(t *testing.T) {
	c := NewMongoDBConnector()

	// Disconnect with nil client should be a no-op
	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("expected nil error for disconnect without client, got: %v", err)
	}
}

func TestName_DefaultWithoutConfig(t *testing.T) {
	c := NewMongoDBConnector()

	if c.Name() != "mongodb" {
		t.Errorf("Name() = %s, want mongodb", c.Name())
	}
}

func TestName_EmptyConfigName(t *testing.T) {
	c := NewMongoDBConnector()
	c.config = &base.ConnectorConfig{Name: ""}

	if c.Name() != "" {
		t.Errorf("Name() = %q, want empty string", c.Name())
	}
}

func TestConvertToBSONValue_MapWithBothOidAndDate(t *testing.T) {
	c := NewMongoDBConnector()

	// If a map has $oid, $oid takes precedence and the entire map converts to ObjectID
	input := map[string]interface{}{
		"$oid":  "507f1f77bcf86cd799439011",
		"$date": "2024-01-15T10:30:00Z",
	}
	result := c.convertToBSONValue(input)

	// $oid is checked first, so it should convert to ObjectID
	_, ok := result.(primitive.ObjectID)
	if !ok {
		t.Errorf("expected primitive.ObjectID when $oid is present, got %T", result)
	}
}

func TestConvertToBSONValue_EmptyMap(t *testing.T) {
	c := NewMongoDBConnector()

	input := map[string]interface{}{}
	result := c.convertToBSONValue(input)

	resultMap, ok := result.(bson.M)
	if !ok {
		t.Fatalf("expected bson.M, got %T", result)
	}
	if len(resultMap) != 0 {
		t.Errorf("expected empty bson.M, got %v", resultMap)
	}
}

func TestConvertToBSONValue_EmptyArray(t *testing.T) {
	c := NewMongoDBConnector()

	input := []interface{}{}
	result := c.convertToBSONValue(input)

	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got %v", arr)
	}
}

func TestConvertToBSONValue_OidWithNonStringValue(t *testing.T) {
	c := NewMongoDBConnector()

	// $oid with a non-string value should fall through to regular map conversion
	input := map[string]interface{}{
		"$oid": 12345,
	}
	result := c.convertToBSONValue(input)

	resultMap, ok := result.(bson.M)
	if !ok {
		t.Fatalf("expected bson.M, got %T", result)
	}
	if resultMap["$oid"] != 12345 {
		t.Errorf("expected $oid=12345, got %v", resultMap["$oid"])
	}
}

func TestConvertToBSONValue_DateWithNonStringValue(t *testing.T) {
	c := NewMongoDBConnector()

	// $date with a non-string value should fall through to regular map conversion
	input := map[string]interface{}{
		"$date": 12345,
	}
	result := c.convertToBSONValue(input)

	resultMap, ok := result.(bson.M)
	if !ok {
		t.Fatalf("expected bson.M, got %T", result)
	}
	if resultMap["$date"] != 12345 {
		t.Errorf("expected $date=12345, got %v", resultMap["$date"])
	}
}

func TestConvertFromBSON_EmptyPrimitiveD(t *testing.T) {
	c := NewMongoDBConnector()

	input := primitive.D{}
	result := c.convertFromBSON(input)

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if len(resultMap) != 0 {
		t.Errorf("expected empty map, got %v", resultMap)
	}
}

func TestParamsToBSON_FilterAsBsonM(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"filter": bson.M{"status": "active"},
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if result["status"] != "active" {
		t.Errorf("expected status=active, got %v", result["status"])
	}
}

func TestParamsToBSON_QueryAsJSONString(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"query": `{"name": "test"}`,
	}

	result, err := c.paramsToBSON(params)
	if err != nil {
		t.Fatalf("paramsToBSON() error = %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
}

func TestParamsToBSON_QueryAsInvalidType(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"query": 42, // Not a map, string, or bson.M
	}

	_, err := c.paramsToBSON(params)
	if err == nil {
		t.Error("expected error for query with invalid type")
	}
}

func TestParamsToBSON_DollarQueryAsInvalidType(t *testing.T) {
	c := NewMongoDBConnector()

	params := map[string]interface{}{
		"$query": true, // Not a map, string, or bson.M
	}

	_, err := c.paramsToBSON(params)
	if err == nil {
		t.Error("expected error for $query with invalid type")
	}
}

func TestConnect_MissingDatabaseOption(t *testing.T) {
	c := NewMongoDBConnector()

	// This should fail at validation because "database" is a required option
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name:          "test-mongo",
		ConnectionURL: "mongodb://localhost:27017",
		Options:       map[string]interface{}{},
	})

	if err == nil {
		c.Disconnect(context.Background())
		t.Error("expected error for missing database option")
	}
}

func TestConnect_NoOptions(t *testing.T) {
	c := NewMongoDBConnector()

	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name:          "test-mongo",
		ConnectionURL: "mongodb://localhost:27017",
	})

	if err == nil {
		c.Disconnect(context.Background())
		t.Error("expected error for nil options (missing database)")
	}
}
