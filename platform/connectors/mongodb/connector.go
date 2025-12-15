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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"axonflow/platform/connectors/base"
)

const (
	// DefaultTimeout is the default operation timeout
	DefaultTimeout = 30 * time.Second
	// DefaultConnectTimeout is the default connection timeout
	DefaultConnectTimeout = 10 * time.Second
	// DefaultMaxPoolSize is the default maximum connection pool size
	DefaultMaxPoolSize = 100
	// DefaultMinPoolSize is the default minimum connection pool size
	DefaultMinPoolSize = 10
)

// MongoDBConnector implements the MCP Connector interface for MongoDB databases.
// It provides CRUD operations, aggregation pipeline support, and production-ready
// connection management for MongoDB 4.0+ databases.
type MongoDBConnector struct {
	config     *base.ConnectorConfig
	client     *mongo.Client
	database   *mongo.Database
	logger     *log.Logger
	dbName     string
	collection string // default collection
}

// NewMongoDBConnector creates a new MongoDB connector instance
func NewMongoDBConnector() *MongoDBConnector {
	return &MongoDBConnector{
		logger: log.New(os.Stdout, "[MCP_MONGODB] ", log.LstdFlags),
	}
}

// Connect establishes a connection to MongoDB with connection pooling
func (c *MongoDBConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Build connection URI
	uri, err := c.buildURI(config)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to build URI", err)
	}

	// Configure client options
	clientOpts := options.Client().ApplyURI(uri)

	// Connection pool settings
	maxPoolSize := uint64(DefaultMaxPoolSize)
	minPoolSize := uint64(DefaultMinPoolSize)
	if val, ok := config.Options["max_pool_size"].(float64); ok {
		maxPoolSize = uint64(val)
	}
	if val, ok := config.Options["min_pool_size"].(float64); ok {
		minPoolSize = uint64(val)
	}
	clientOpts.SetMaxPoolSize(maxPoolSize)
	clientOpts.SetMinPoolSize(minPoolSize)

	// Timeouts
	connectTimeout := DefaultConnectTimeout
	if val, ok := config.Options["connect_timeout"].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			connectTimeout = duration
		}
	}
	clientOpts.SetConnectTimeout(connectTimeout)

	// Socket timeout
	if val, ok := config.Options["socket_timeout"].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			clientOpts.SetSocketTimeout(duration)
		}
	}

	// Server selection timeout
	if val, ok := config.Options["server_selection_timeout"].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			clientOpts.SetServerSelectionTimeout(duration)
		}
	}

	// Read preference
	if rp, ok := config.Options["read_preference"].(string); ok {
		switch strings.ToLower(rp) {
		case "primary":
			clientOpts.SetReadPreference(readpref.Primary())
		case "primarypreferred":
			clientOpts.SetReadPreference(readpref.PrimaryPreferred())
		case "secondary":
			clientOpts.SetReadPreference(readpref.Secondary())
		case "secondarypreferred":
			clientOpts.SetReadPreference(readpref.SecondaryPreferred())
		case "nearest":
			clientOpts.SetReadPreference(readpref.Nearest())
		}
	}

	// App name for monitoring
	appName := "AxonFlow-MongoDB-Connector"
	if name, ok := config.Options["app_name"].(string); ok {
		appName = name
	}
	clientOpts.SetAppName(appName)

	// Retry writes and reads
	clientOpts.SetRetryWrites(true)
	clientOpts.SetRetryReads(true)

	// Create client
	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	client, err := mongo.Connect(connectCtx, clientOpts)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to connect to MongoDB", err)
	}

	// Ping to verify connection
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()

	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		_ = client.Disconnect(ctx)
		return base.NewConnectorError(config.Name, "Connect", "failed to ping MongoDB", err)
	}

	c.client = client

	// Set database
	if dbName, ok := config.Options["database"].(string); ok {
		c.dbName = dbName
		c.database = client.Database(dbName)
	} else {
		return base.NewConnectorError(config.Name, "Connect", "database name is required", nil)
	}

	// Set default collection (optional)
	if collection, ok := config.Options["collection"].(string); ok {
		c.collection = collection
	}

	c.logger.Printf("Connected to MongoDB: %s (database=%s, max_pool=%d)",
		config.Name, c.dbName, maxPoolSize)

	return nil
}

// buildURI constructs MongoDB connection URI from config
func (c *MongoDBConnector) buildURI(config *base.ConnectorConfig) (string, error) {
	// If ConnectionURL is provided, use it directly
	if config.ConnectionURL != "" {
		return config.ConnectionURL, nil
	}

	// Build URI from options
	host := "localhost"
	port := 27017

	if h, ok := config.Options["host"].(string); ok {
		host = h
	}
	if p, ok := config.Options["port"].(float64); ok {
		port = int(p)
	}

	// Handle replica set hosts
	hosts := host
	if h, ok := config.Options["hosts"].(string); ok {
		hosts = h
	}

	// Build URI
	var uri string
	username := config.Credentials["username"]
	password := config.Credentials["password"]

	if username != "" && password != "" {
		uri = fmt.Sprintf("mongodb://%s:%s@%s:%d", username, password, hosts, port)
	} else {
		uri = fmt.Sprintf("mongodb://%s:%d", hosts, port)
	}

	// Add parameters
	params := []string{}

	// Auth database
	if authDB, ok := config.Options["auth_database"].(string); ok {
		params = append(params, fmt.Sprintf("authSource=%s", authDB))
	}

	// Replica set
	if rs, ok := config.Options["replica_set"].(string); ok {
		params = append(params, fmt.Sprintf("replicaSet=%s", rs))
	}

	// TLS/SSL
	if tls, ok := config.Options["tls"].(bool); ok && tls {
		params = append(params, "tls=true")
		if tlsInsecure, ok := config.Options["tls_insecure"].(bool); ok && tlsInsecure {
			params = append(params, "tlsInsecure=true")
		}
	}

	// Direct connection (for single server)
	if direct, ok := config.Options["direct_connection"].(bool); ok && direct {
		params = append(params, "directConnection=true")
	}

	if len(params) > 0 {
		uri += "?" + strings.Join(params, "&")
	}

	return uri, nil
}

// Disconnect closes the MongoDB client connection
func (c *MongoDBConnector) Disconnect(ctx context.Context) error {
	if c.client == nil {
		return nil
	}

	disconnectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := c.client.Disconnect(disconnectCtx); err != nil {
		return base.NewConnectorError(c.Name(), "Disconnect", "failed to disconnect", err)
	}

	c.logger.Printf("Disconnected from MongoDB: %s", c.Name())
	return nil
}

// HealthCheck verifies the MongoDB connection is healthy
func (c *MongoDBConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.client == nil {
		return &base.HealthStatus{
			Healthy:   false,
			Error:     "client not connected",
			Timestamp: time.Now(),
		}, nil
	}

	start := time.Now()
	err := c.client.Ping(ctx, readpref.Primary())
	latency := time.Since(start)

	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Latency:   latency,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}

	// Get server status
	var serverStatus bson.M
	err = c.database.RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&serverStatus)

	details := map[string]string{
		"database": c.dbName,
	}

	if err == nil {
		if version, ok := serverStatus["version"].(string); ok {
			details["mongodb_version"] = version
		}
		if connections, ok := serverStatus["connections"].(bson.M); ok {
			if current, ok := connections["current"].(int32); ok {
				details["current_connections"] = fmt.Sprintf("%d", current)
			}
			if available, ok := connections["available"].(int32); ok {
				details["available_connections"] = fmt.Sprintf("%d", available)
			}
		}
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a read operation (find, aggregate, count, distinct)
func (c *MongoDBConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "client not connected", nil)
	}

	// Apply timeout
	timeout := query.Timeout
	if timeout == 0 && c.config != nil {
		timeout = c.config.Timeout
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Determine operation type from statement
	// Statement format: "operation:collection" or just "operation" (uses default collection)
	operation, collectionName := c.parseStatement(query.Statement)

	collection := c.database.Collection(collectionName)

	start := time.Now()
	var results []map[string]interface{}
	var err error

	switch strings.ToLower(operation) {
	case "find", "":
		results, err = c.find(queryCtx, collection, query)
	case "findone":
		results, err = c.findOne(queryCtx, collection, query)
	case "aggregate":
		results, err = c.aggregate(queryCtx, collection, query)
	case "count":
		results, err = c.count(queryCtx, collection, query)
	case "distinct":
		results, err = c.distinct(queryCtx, collection, query)
	default:
		return nil, base.NewConnectorError(c.Name(), "Query",
			fmt.Sprintf("unsupported operation: %s", operation), nil)
	}

	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "query execution failed", err)
	}

	duration := time.Since(start)

	c.logger.Printf("Query executed (%s.%s): %d results in %v",
		operation, collectionName, len(results), duration)

	return &base.QueryResult{
		Rows:      results,
		RowCount:  len(results),
		Duration:  duration,
		Cached:    false,
		Connector: c.Name(),
	}, nil
}

// Execute runs write operations (insert, update, delete, bulkWrite)
func (c *MongoDBConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "client not connected", nil)
	}

	// Apply timeout
	timeout := cmd.Timeout
	if timeout == 0 && c.config != nil {
		timeout = c.config.Timeout
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Parse statement for collection name
	_, collectionName := c.parseStatement(cmd.Statement)
	collection := c.database.Collection(collectionName)

	start := time.Now()
	var rowsAffected int
	var message string
	var err error

	switch strings.ToLower(cmd.Action) {
	case "insert", "insertone":
		rowsAffected, message, err = c.insertOne(execCtx, collection, cmd)
	case "insertmany":
		rowsAffected, message, err = c.insertMany(execCtx, collection, cmd)
	case "update", "updateone":
		rowsAffected, message, err = c.updateOne(execCtx, collection, cmd)
	case "updatemany":
		rowsAffected, message, err = c.updateMany(execCtx, collection, cmd)
	case "delete", "deleteone":
		rowsAffected, message, err = c.deleteOne(execCtx, collection, cmd)
	case "deletemany":
		rowsAffected, message, err = c.deleteMany(execCtx, collection, cmd)
	case "replace", "replaceone":
		rowsAffected, message, err = c.replaceOne(execCtx, collection, cmd)
	default:
		return nil, base.NewConnectorError(c.Name(), "Execute",
			fmt.Sprintf("unsupported action: %s", cmd.Action), nil)
	}

	duration := time.Since(start)

	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "command execution failed", err)
	}

	c.logger.Printf("Command executed (%s.%s): %d affected in %v",
		cmd.Action, collectionName, rowsAffected, duration)

	return &base.CommandResult{
		Success:      true,
		RowsAffected: rowsAffected,
		Duration:     duration,
		Message:      message,
		Connector:    c.Name(),
	}, nil
}

// Name returns the connector name
func (c *MongoDBConnector) Name() string {
	if c.config == nil {
		return "mongodb"
	}
	return c.config.Name
}

// Type returns the connector type
func (c *MongoDBConnector) Type() string {
	return "mongodb"
}

// Version returns the connector version
func (c *MongoDBConnector) Version() string {
	return "1.0.0"
}

// Capabilities returns the list of supported capabilities
func (c *MongoDBConnector) Capabilities() []string {
	return []string{
		"query",
		"execute",
		"aggregation",
		"connection_pooling",
		"transactions",
		"change_streams",
	}
}

// parseStatement extracts operation and collection from statement
// Format: "operation:collection" or just "collection"
func (c *MongoDBConnector) parseStatement(statement string) (string, string) {
	parts := strings.SplitN(statement, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	// Default operation is find, statement is collection name
	if c.collection != "" {
		return statement, c.collection
	}
	return "find", statement
}

// paramsToBSON converts query parameters to BSON filter
func (c *MongoDBConnector) paramsToBSON(params map[string]interface{}) (bson.M, error) {
	if params == nil {
		return bson.M{}, nil
	}

	// Check if params has a "filter" key (explicit filter)
	if filter, ok := params["filter"]; ok {
		return c.toBSON(filter)
	}

	// Check if params has a "$query" or "query" key
	if query, ok := params["$query"]; ok {
		return c.toBSON(query)
	}
	if query, ok := params["query"]; ok {
		return c.toBSON(query)
	}

	// Use params directly as filter (skip special keys)
	filter := bson.M{}
	for k, v := range params {
		// Skip special parameters
		if strings.HasPrefix(k, "_") || k == "sort" || k == "projection" ||
			k == "skip" || k == "limit" || k == "pipeline" || k == "documents" ||
			k == "update" || k == "field" {
			continue
		}
		filter[k] = v
	}
	return filter, nil
}

// toBSON converts interface{} to bson.M
func (c *MongoDBConnector) toBSON(v interface{}) (bson.M, error) {
	switch val := v.(type) {
	case bson.M:
		return val, nil
	case map[string]interface{}:
		result := bson.M{}
		for k, v := range val {
			result[k] = c.convertToBSONValue(v)
		}
		return result, nil
	case string:
		// Try to parse as JSON
		var result bson.M
		if err := json.Unmarshal([]byte(val), &result); err != nil {
			return nil, fmt.Errorf("invalid BSON/JSON: %w", err)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot convert %T to BSON", v)
	}
}

// convertToBSONValue converts Go types to BSON-compatible types
func (c *MongoDBConnector) convertToBSONValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		// Check for special MongoDB types
		if oid, ok := val["$oid"].(string); ok {
			if objectID, err := primitive.ObjectIDFromHex(oid); err == nil {
				return objectID
			}
		}
		if date, ok := val["$date"].(string); ok {
			if t, err := time.Parse(time.RFC3339, date); err == nil {
				return t
			}
		}
		// Regular map - convert recursively
		result := bson.M{}
		for k, v := range val {
			result[k] = c.convertToBSONValue(v)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = c.convertToBSONValue(v)
		}
		return result
	default:
		return val
	}
}

// find executes a find query
func (c *MongoDBConnector) find(ctx context.Context, collection *mongo.Collection, query *base.Query) ([]map[string]interface{}, error) {
	filter, err := c.paramsToBSON(query.Parameters)
	if err != nil {
		return nil, err
	}

	opts := options.Find()

	// Apply limit
	if query.Limit > 0 {
		opts.SetLimit(int64(query.Limit))
	} else if limit, ok := query.Parameters["limit"].(float64); ok {
		opts.SetLimit(int64(limit))
	}

	// Apply skip
	if skip, ok := query.Parameters["skip"].(float64); ok {
		opts.SetSkip(int64(skip))
	}

	// Apply sort
	if sort, ok := query.Parameters["sort"].(map[string]interface{}); ok {
		sortBSON := bson.D{}
		for k, v := range sort {
			if order, ok := v.(float64); ok {
				sortBSON = append(sortBSON, bson.E{Key: k, Value: int(order)})
			}
		}
		opts.SetSort(sortBSON)
	}

	// Apply projection
	if projection, ok := query.Parameters["projection"].(map[string]interface{}); ok {
		opts.SetProjection(projection)
	}

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cursor.Close(ctx) }()

	return c.decodeCursor(ctx, cursor)
}

// findOne executes a findOne query
func (c *MongoDBConnector) findOne(ctx context.Context, collection *mongo.Collection, query *base.Query) ([]map[string]interface{}, error) {
	filter, err := c.paramsToBSON(query.Parameters)
	if err != nil {
		return nil, err
	}

	opts := options.FindOne()

	// Apply projection
	if projection, ok := query.Parameters["projection"].(map[string]interface{}); ok {
		opts.SetProjection(projection)
	}

	var result bson.M
	err = collection.FindOne(ctx, filter, opts).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return []map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	return []map[string]interface{}{c.bsonToMap(result)}, nil
}

// aggregate executes an aggregation pipeline
func (c *MongoDBConnector) aggregate(ctx context.Context, collection *mongo.Collection, query *base.Query) ([]map[string]interface{}, error) {
	// Pipeline should be in parameters["pipeline"]
	pipelineRaw, ok := query.Parameters["pipeline"]
	if !ok {
		return nil, fmt.Errorf("aggregation requires 'pipeline' parameter")
	}

	var pipeline mongo.Pipeline

	switch p := pipelineRaw.(type) {
	case []interface{}:
		for _, stage := range p {
			stageMap, ok := stage.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid pipeline stage type: %T", stage)
			}
			bsonStage := bson.D{}
			for k, v := range stageMap {
				bsonStage = append(bsonStage, bson.E{Key: k, Value: c.convertToBSONValue(v)})
			}
			pipeline = append(pipeline, bsonStage)
		}
	case string:
		// Try to parse as JSON array
		var stages []bson.M
		if err := json.Unmarshal([]byte(p), &stages); err != nil {
			return nil, fmt.Errorf("invalid pipeline JSON: %w", err)
		}
		for _, stage := range stages {
			bsonStage := bson.D{}
			for k, v := range stage {
				bsonStage = append(bsonStage, bson.E{Key: k, Value: v})
			}
			pipeline = append(pipeline, bsonStage)
		}
	default:
		return nil, fmt.Errorf("pipeline must be an array or JSON string, got %T", pipelineRaw)
	}

	opts := options.Aggregate()

	// Allow disk use for large aggregations
	if allowDisk, ok := query.Parameters["allowDiskUse"].(bool); ok && allowDisk {
		opts.SetAllowDiskUse(true)
	}

	cursor, err := collection.Aggregate(ctx, pipeline, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cursor.Close(ctx) }()

	return c.decodeCursor(ctx, cursor)
}

// count executes a count query
func (c *MongoDBConnector) count(ctx context.Context, collection *mongo.Collection, query *base.Query) ([]map[string]interface{}, error) {
	filter, err := c.paramsToBSON(query.Parameters)
	if err != nil {
		return nil, err
	}

	opts := options.Count()

	// Apply limit
	if limit, ok := query.Parameters["limit"].(float64); ok {
		opts.SetLimit(int64(limit))
	}

	// Apply skip
	if skip, ok := query.Parameters["skip"].(float64); ok {
		opts.SetSkip(int64(skip))
	}

	count, err := collection.CountDocuments(ctx, filter, opts)
	if err != nil {
		return nil, err
	}

	return []map[string]interface{}{
		{"count": count},
	}, nil
}

// distinct executes a distinct query
func (c *MongoDBConnector) distinct(ctx context.Context, collection *mongo.Collection, query *base.Query) ([]map[string]interface{}, error) {
	field, ok := query.Parameters["field"].(string)
	if !ok {
		return nil, fmt.Errorf("distinct requires 'field' parameter")
	}

	filter, err := c.paramsToBSON(query.Parameters)
	if err != nil {
		return nil, err
	}

	values, err := collection.Distinct(ctx, field, filter)
	if err != nil {
		return nil, err
	}

	results := make([]map[string]interface{}, len(values))
	for i, v := range values {
		results[i] = map[string]interface{}{field: v}
	}

	return results, nil
}

// insertOne inserts a single document
func (c *MongoDBConnector) insertOne(ctx context.Context, collection *mongo.Collection, cmd *base.Command) (int, string, error) {
	doc, ok := cmd.Parameters["document"]
	if !ok {
		// Use parameters directly as document
		doc = cmd.Parameters
	}

	result, err := collection.InsertOne(ctx, c.convertToBSONValue(doc))
	if err != nil {
		return 0, "", err
	}

	insertedID := fmt.Sprintf("%v", result.InsertedID)
	return 1, fmt.Sprintf("Inserted 1 document (id=%s)", insertedID), nil
}

// insertMany inserts multiple documents
func (c *MongoDBConnector) insertMany(ctx context.Context, collection *mongo.Collection, cmd *base.Command) (int, string, error) {
	docsRaw, ok := cmd.Parameters["documents"]
	if !ok {
		return 0, "", fmt.Errorf("insertMany requires 'documents' parameter")
	}

	docsSlice, ok := docsRaw.([]interface{})
	if !ok {
		return 0, "", fmt.Errorf("documents must be an array")
	}

	docs := make([]interface{}, len(docsSlice))
	for i, doc := range docsSlice {
		docs[i] = c.convertToBSONValue(doc)
	}

	opts := options.InsertMany()
	if ordered, ok := cmd.Parameters["ordered"].(bool); ok {
		opts.SetOrdered(ordered)
	}

	result, err := collection.InsertMany(ctx, docs, opts)
	if err != nil {
		return 0, "", err
	}

	return len(result.InsertedIDs), fmt.Sprintf("Inserted %d documents", len(result.InsertedIDs)), nil
}

// updateOne updates a single document
func (c *MongoDBConnector) updateOne(ctx context.Context, collection *mongo.Collection, cmd *base.Command) (int, string, error) {
	filter, err := c.paramsToBSON(cmd.Parameters)
	if err != nil {
		return 0, "", err
	}

	updateRaw, ok := cmd.Parameters["update"]
	if !ok {
		return 0, "", fmt.Errorf("updateOne requires 'update' parameter")
	}

	update, err := c.toBSON(updateRaw)
	if err != nil {
		return 0, "", err
	}

	opts := options.Update()
	if upsert, ok := cmd.Parameters["upsert"].(bool); ok {
		opts.SetUpsert(upsert)
	}

	result, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return 0, "", err
	}

	affected := int(result.ModifiedCount)
	if result.UpsertedCount > 0 {
		affected = int(result.UpsertedCount)
		return affected, fmt.Sprintf("Upserted 1 document (id=%v)", result.UpsertedID), nil
	}

	return affected, fmt.Sprintf("Updated %d document(s)", affected), nil
}

// updateMany updates multiple documents
func (c *MongoDBConnector) updateMany(ctx context.Context, collection *mongo.Collection, cmd *base.Command) (int, string, error) {
	filter, err := c.paramsToBSON(cmd.Parameters)
	if err != nil {
		return 0, "", err
	}

	updateRaw, ok := cmd.Parameters["update"]
	if !ok {
		return 0, "", fmt.Errorf("updateMany requires 'update' parameter")
	}

	update, err := c.toBSON(updateRaw)
	if err != nil {
		return 0, "", err
	}

	opts := options.Update()
	if upsert, ok := cmd.Parameters["upsert"].(bool); ok {
		opts.SetUpsert(upsert)
	}

	result, err := collection.UpdateMany(ctx, filter, update, opts)
	if err != nil {
		return 0, "", err
	}

	affected := int(result.ModifiedCount)
	return affected, fmt.Sprintf("Updated %d document(s)", affected), nil
}

// deleteOne deletes a single document
func (c *MongoDBConnector) deleteOne(ctx context.Context, collection *mongo.Collection, cmd *base.Command) (int, string, error) {
	filter, err := c.paramsToBSON(cmd.Parameters)
	if err != nil {
		return 0, "", err
	}

	result, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		return 0, "", err
	}

	return int(result.DeletedCount), fmt.Sprintf("Deleted %d document(s)", result.DeletedCount), nil
}

// deleteMany deletes multiple documents
func (c *MongoDBConnector) deleteMany(ctx context.Context, collection *mongo.Collection, cmd *base.Command) (int, string, error) {
	filter, err := c.paramsToBSON(cmd.Parameters)
	if err != nil {
		return 0, "", err
	}

	result, err := collection.DeleteMany(ctx, filter)
	if err != nil {
		return 0, "", err
	}

	return int(result.DeletedCount), fmt.Sprintf("Deleted %d document(s)", result.DeletedCount), nil
}

// replaceOne replaces a single document
func (c *MongoDBConnector) replaceOne(ctx context.Context, collection *mongo.Collection, cmd *base.Command) (int, string, error) {
	filter, err := c.paramsToBSON(cmd.Parameters)
	if err != nil {
		return 0, "", err
	}

	replacementRaw, ok := cmd.Parameters["replacement"]
	if !ok {
		return 0, "", fmt.Errorf("replaceOne requires 'replacement' parameter")
	}

	replacement, err := c.toBSON(replacementRaw)
	if err != nil {
		return 0, "", err
	}

	opts := options.Replace()
	if upsert, ok := cmd.Parameters["upsert"].(bool); ok {
		opts.SetUpsert(upsert)
	}

	result, err := collection.ReplaceOne(ctx, filter, replacement, opts)
	if err != nil {
		return 0, "", err
	}

	affected := int(result.ModifiedCount)
	if result.UpsertedCount > 0 {
		return 1, fmt.Sprintf("Upserted 1 document (id=%v)", result.UpsertedID), nil
	}

	return affected, fmt.Sprintf("Replaced %d document(s)", affected), nil
}

// decodeCursor decodes all documents from a cursor
func (c *MongoDBConnector) decodeCursor(ctx context.Context, cursor *mongo.Cursor) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			return nil, err
		}
		results = append(results, c.bsonToMap(doc))
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// bsonToMap converts BSON document to Go map with proper type handling
func (c *MongoDBConnector) bsonToMap(doc bson.M) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range doc {
		result[k] = c.convertFromBSON(v)
	}
	return result
}

// convertFromBSON converts BSON types to JSON-serializable Go types
func (c *MongoDBConnector) convertFromBSON(v interface{}) interface{} {
	switch val := v.(type) {
	case primitive.ObjectID:
		return val.Hex()
	case primitive.DateTime:
		return val.Time()
	case primitive.Timestamp:
		return map[string]interface{}{
			"t": val.T,
			"i": val.I,
		}
	case primitive.Binary:
		return val.Data
	case bson.M:
		return c.bsonToMap(val)
	case bson.A:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = c.convertFromBSON(item)
		}
		return result
	case primitive.D:
		result := make(map[string]interface{})
		for _, elem := range val {
			result[elem.Key] = c.convertFromBSON(elem.Value)
		}
		return result
	default:
		return val
	}
}
