// Package storage provides database clients for MongoDB and Redis
package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// MongoClient wraps the MongoDB client
type MongoClient struct {
	client   *mongo.Client
	database *mongo.Database
}

// Collection names
const (
	CollectionDecisions        = "decisions"
	CollectionConsultations    = "consultations"
	CollectionFindings         = "findings"
	CollectionSessions         = "sessions"
	CollectionToolRuns         = "tool_runs"
	CollectionPrograms         = "programs"
	CollectionScriptExecutions = "script_executions"
	CollectionVectorStatuses   = "vector_statuses"

	// v2 review pipeline collections
	CollectionReviews        = "reviews"         // adversarial panel reviews
	CollectionTriageOutcomes = "triage_outcomes" // real-world submission verdicts (the feedback loop)
	CollectionLessons        = "lessons"         // curated FP-class / mistake grounding
	CollectionHypotheses     = "hypotheses"      // director-proposed untried attack ideas
)

// NewMongoClient creates a new MongoDB client. dbName selects the database;
// if empty it falls back to "hack_ai_v2".
func NewMongoClient(ctx context.Context, uri, dbName string) (*MongoClient, error) {
	if dbName == "" {
		dbName = "hack_ai_v2"
	}
	clientOptions := options.Client().ApplyURI(uri).SetConnectTimeout(5 * time.Second)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	mc := &MongoClient{
		client:   client,
		database: client.Database(dbName),
	}

	// Create indexes for performance
	mc.EnsureIndexes(ctx)

	return mc, nil
}

// Close closes the MongoDB connection
func (m *MongoClient) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}

// EnsureIndexes creates compound indexes for fast per-program queries
func (m *MongoClient) EnsureIndexes(ctx context.Context) {
	indexes := map[string][]mongo.IndexModel{
		CollectionFindings: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "detected_at", Value: -1}}},
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "severity", Value: 1}}},
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "state", Value: 1}}},
			{Keys: bson.D{{Key: "vuln_type", Value: 1}}},
		},
		CollectionDecisions: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "session_id", Value: 1}, {Key: "timestamp", Value: -1}}},
		},
		CollectionToolRuns: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "tool_name", Value: 1}}},
		},
		CollectionSessions: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "last_active", Value: -1}}},
		},
		CollectionPrograms: {
			{Keys: bson.D{{Key: "slug", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		CollectionScriptExecutions: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "session_id", Value: 1}}},
		},
		CollectionVectorStatuses: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "vector_id", Value: 1}}},
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "state", Value: 1}}},
		},
		CollectionReviews: {
			{Keys: bson.D{{Key: "finding_id", Value: 1}, {Key: "round", Value: 1}}},
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "timestamp", Value: -1}}},
		},
		CollectionTriageOutcomes: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "recorded_at", Value: -1}}},
			{Keys: bson.D{{Key: "state", Value: 1}}},
			{Keys: bson.D{{Key: "finding_id", Value: 1}}},
		},
		CollectionLessons: {
			{Keys: bson.D{{Key: "program", Value: 1}}},
			{Keys: bson.D{{Key: "vuln_type", Value: 1}}},
			{Keys: bson.D{{Key: "fp_class", Value: 1}}},
		},
		CollectionHypotheses: {
			{Keys: bson.D{{Key: "program", Value: 1}, {Key: "created_at", Value: -1}}},
		},
	}

	for collection, idxModels := range indexes {
		m.database.Collection(collection).Indexes().CreateMany(ctx, idxModels)
	}
}

// ============================================================================
// BOUNTY PROGRAMS
// ============================================================================

// SaveProgram upserts a bounty program
func (m *MongoClient) SaveProgram(ctx context.Context, program *types.BountyProgram) error {
	filter := bson.D{{Key: "_id", Value: program.ID}}
	opts := options.Replace().SetUpsert(true)
	_, err := m.database.Collection(CollectionPrograms).ReplaceOne(ctx, filter, program, opts)
	return err
}

// GetProgram retrieves a program by slug
func (m *MongoClient) GetProgram(ctx context.Context, slug string) (*types.BountyProgram, error) {
	filter := bson.D{{Key: "slug", Value: slug}}
	var program types.BountyProgram
	if err := m.database.Collection(CollectionPrograms).FindOne(ctx, filter).Decode(&program); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &program, nil
}

// ListPrograms retrieves all bounty programs
func (m *MongoClient) ListPrograms(ctx context.Context) ([]*types.BountyProgram, error) {
	opts := options.Find().SetSort(bson.D{{Key: "last_active", Value: -1}})
	cursor, err := m.database.Collection(CollectionPrograms).Find(ctx, bson.D{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var programs []*types.BountyProgram
	if err := cursor.All(ctx, &programs); err != nil {
		return nil, err
	}
	return programs, nil
}

// GetFindingsByProgram retrieves all findings for a bounty program
func (m *MongoClient) GetFindingsByProgram(ctx context.Context, program string) ([]*types.Finding, error) {
	filter := bson.D{{Key: "program", Value: program}}
	opts := options.Find().SetSort(bson.D{{Key: "detected_at", Value: -1}})

	cursor, err := m.database.Collection(CollectionFindings).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var findings []*types.Finding
	if err := cursor.All(ctx, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// GetDecisionsByProgram retrieves all decisions for a bounty program
func (m *MongoClient) GetDecisionsByProgram(ctx context.Context, program string, limit int) ([]*types.DecisionLog, error) {
	filter := bson.D{{Key: "program", Value: program}}
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := m.database.Collection(CollectionDecisions).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var decisions []*types.DecisionLog
	if err := cursor.All(ctx, &decisions); err != nil {
		return nil, err
	}
	return decisions, nil
}

// GetProgramStats retrieves summary statistics for a bounty program
func (m *MongoClient) GetProgramStats(ctx context.Context, program string) (map[string]interface{}, error) {
	stats := map[string]interface{}{"program": program}

	// Count findings by severity
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "program", Value: program}}}},
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$severity"},
			{Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}},
		}}},
	}

	cursor, err := m.database.Collection(CollectionFindings).Aggregate(ctx, pipeline)
	if err != nil {
		return stats, err
	}
	defer cursor.Close(ctx)

	severityCounts := map[string]int64{}
	for cursor.Next(ctx) {
		var result struct {
			Severity string `bson:"_id"`
			Count    int64  `bson:"count"`
		}
		if cursor.Decode(&result) == nil {
			severityCounts[result.Severity] = result.Count
		}
	}
	stats["findings_by_severity"] = severityCounts

	// Count tool runs
	runCount, _ := m.database.Collection(CollectionToolRuns).CountDocuments(ctx,
		bson.D{{Key: "program", Value: program}})
	stats["tool_runs"] = runCount

	// Count sessions
	sessionCount, _ := m.database.Collection(CollectionSessions).CountDocuments(ctx,
		bson.D{{Key: "program", Value: program}})
	stats["sessions"] = sessionCount

	return stats, nil
}

// ============================================================================
// DECISION LOGGING
// ============================================================================

// LogDecision saves a decision to MongoDB
func (m *MongoClient) LogDecision(ctx context.Context, decision *types.DecisionLog) error {
	decision.ID = primitive.NewObjectID()
	if decision.Timestamp.IsZero() {
		decision.Timestamp = time.Now()
	}

	_, err := m.database.Collection(CollectionDecisions).InsertOne(ctx, decision)
	return err
}

// GetRecentDecisions retrieves recent decisions
func (m *MongoClient) GetRecentDecisions(ctx context.Context, limit int) ([]*types.DecisionLog, error) {
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := m.database.Collection(CollectionDecisions).Find(ctx, bson.D{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var decisions []*types.DecisionLog
	if err := cursor.All(ctx, &decisions); err != nil {
		return nil, err
	}

	return decisions, nil
}

// GetDecisionsBySession retrieves decisions for a specific session
func (m *MongoClient) GetDecisionsBySession(ctx context.Context, sessionID string) ([]*types.DecisionLog, error) {
	filter := bson.D{{Key: "session_id", Value: sessionID}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})

	cursor, err := m.database.Collection(CollectionDecisions).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var decisions []*types.DecisionLog
	if err := cursor.All(ctx, &decisions); err != nil {
		return nil, err
	}

	return decisions, nil
}

// GetDecisionsByTags retrieves decisions with specific tags
func (m *MongoClient) GetDecisionsByTags(ctx context.Context, tags []string, limit int) ([]*types.DecisionLog, error) {
	filter := bson.D{{Key: "tags", Value: bson.D{{Key: "$in", Value: tags}}}}
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := m.database.Collection(CollectionDecisions).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var decisions []*types.DecisionLog
	if err := cursor.All(ctx, &decisions); err != nil {
		return nil, err
	}

	return decisions, nil
}

// ============================================================================
// CONSULTATIONS
// ============================================================================

// LogConsultation saves a consultation to MongoDB
func (m *MongoClient) LogConsultation(ctx context.Context, consultation *types.Consultation) error {
	consultation.ID = primitive.NewObjectID()
	if consultation.Timestamp.IsZero() {
		consultation.Timestamp = time.Now()
	}

	_, err := m.database.Collection(CollectionConsultations).InsertOne(ctx, consultation)
	return err
}

// UpdateConsultationResponse updates a consultation with the human's response
func (m *MongoClient) UpdateConsultationResponse(ctx context.Context, id primitive.ObjectID, response string) error {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "response", Value: response},
		{Key: "responded_at", Value: time.Now()},
	}}}

	_, err := m.database.Collection(CollectionConsultations).UpdateOne(ctx, filter, update)
	return err
}

// GetPendingConsultations retrieves consultations without responses
func (m *MongoClient) GetPendingConsultations(ctx context.Context) ([]*types.Consultation, error) {
	filter := bson.D{{Key: "response", Value: bson.D{{Key: "$exists", Value: false}}}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}})

	cursor, err := m.database.Collection(CollectionConsultations).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var consultations []*types.Consultation
	if err := cursor.All(ctx, &consultations); err != nil {
		return nil, err
	}

	return consultations, nil
}

// ============================================================================
// FINDINGS
// ============================================================================

// SaveFinding saves or updates a finding
func (m *MongoClient) SaveFinding(ctx context.Context, finding *types.Finding) error {
	filter := bson.D{{Key: "_id", Value: finding.ID}}
	opts := options.Replace().SetUpsert(true)

	_, err := m.database.Collection(CollectionFindings).ReplaceOne(ctx, filter, finding, opts)
	return err
}

// GetFinding retrieves a finding by ID
func (m *MongoClient) GetFinding(ctx context.Context, id string) (*types.Finding, error) {
	filter := bson.D{{Key: "_id", Value: id}}

	var finding types.Finding
	if err := m.database.Collection(CollectionFindings).FindOne(ctx, filter).Decode(&finding); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &finding, nil
}

// GetFindingsByState retrieves findings by state
func (m *MongoClient) GetFindingsByState(ctx context.Context, state types.FindingState) ([]*types.Finding, error) {
	filter := bson.D{{Key: "state", Value: state}}
	opts := options.Find().SetSort(bson.D{{Key: "detected_at", Value: -1}})

	cursor, err := m.database.Collection(CollectionFindings).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var findings []*types.Finding
	if err := cursor.All(ctx, &findings); err != nil {
		return nil, err
	}

	return findings, nil
}

// GetFindingsBySession retrieves all findings for a session
func (m *MongoClient) GetFindingsBySession(ctx context.Context, sessionID string) ([]*types.Finding, error) {
	// First get session to get finding IDs
	filter := bson.D{{Key: "_id", Value: sessionID}}

	var session types.Session
	if err := m.database.Collection(CollectionSessions).FindOne(ctx, filter).Decode(&session); err != nil {
		return nil, err
	}

	// Get all findings
	findingsFilter := bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: session.FindingsIDs}}}}
	cursor, err := m.database.Collection(CollectionFindings).Find(ctx, findingsFilter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var findings []*types.Finding
	if err := cursor.All(ctx, &findings); err != nil {
		return nil, err
	}

	return findings, nil
}

// ============================================================================
// SESSIONS
// ============================================================================

// SaveSession saves or updates a session
func (m *MongoClient) SaveSession(ctx context.Context, session *types.Session) error {
	filter := bson.D{{Key: "_id", Value: session.ID}}
	opts := options.Replace().SetUpsert(true)

	_, err := m.database.Collection(CollectionSessions).ReplaceOne(ctx, filter, session, opts)
	return err
}

// GetSession retrieves a session by ID
func (m *MongoClient) GetSession(ctx context.Context, id string) (*types.Session, error) {
	filter := bson.D{{Key: "_id", Value: id}}

	var session types.Session
	if err := m.database.Collection(CollectionSessions).FindOne(ctx, filter).Decode(&session); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &session, nil
}

// GetActiveSessions retrieves all active sessions
func (m *MongoClient) GetActiveSessions(ctx context.Context) ([]*types.Session, error) {
	filter := bson.D{{Key: "status", Value: "active"}}
	opts := options.Find().SetSort(bson.D{{Key: "last_active", Value: -1}})

	cursor, err := m.database.Collection(CollectionSessions).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []*types.Session
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}

	return sessions, nil
}

// ============================================================================
// TOOL RUNS (for analysis)
// ============================================================================

// ToolRun represents a single tool execution
type ToolRun struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Program   string             `bson:"program"`
	Timestamp time.Time          `bson:"timestamp"`
	SessionID string             `bson:"session_id"`
	ToolName  string             `bson:"tool_name"`
	Args      string             `bson:"args"`
	Output    string             `bson:"output"`
	Duration  time.Duration      `bson:"duration"`
	Success   bool               `bson:"success"`
	Error     string             `bson:"error,omitempty"`
}

// LogToolRun saves a tool execution to MongoDB
func (m *MongoClient) LogToolRun(ctx context.Context, run *ToolRun) error {
	run.ID = primitive.NewObjectID()
	if run.Timestamp.IsZero() {
		run.Timestamp = time.Now()
	}

	_, err := m.database.Collection(CollectionToolRuns).InsertOne(ctx, run)
	return err
}

// GetToolRunsBySession retrieves all tool runs for a session
func (m *MongoClient) GetToolRunsBySession(ctx context.Context, sessionID string) ([]*ToolRun, error) {
	filter := bson.D{{Key: "session_id", Value: sessionID}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})

	cursor, err := m.database.Collection(CollectionToolRuns).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var runs []*ToolRun
	if err := cursor.All(ctx, &runs); err != nil {
		return nil, err
	}

	return runs, nil
}

// ============================================================================
// STATISTICS (for future RAG)
// ============================================================================

// GetToolUsageStats returns statistics on tool usage
func (m *MongoClient) GetToolUsageStats(ctx context.Context) (map[string]int64, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$tool_name"},
			{Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}},
		}}},
	}

	cursor, err := m.database.Collection(CollectionToolRuns).Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	stats := make(map[string]int64)
	for cursor.Next(ctx) {
		var result struct {
			Tool  string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		if err := cursor.Decode(&result); err != nil {
			continue
		}
		stats[result.Tool] = result.Count
	}

	return stats, nil
}

// GetSuccessfulDecisionPatterns retrieves successful decision patterns for learning
func (m *MongoClient) GetSuccessfulDecisionPatterns(ctx context.Context, tags []string, limit int) ([]*types.DecisionLog, error) {
	filter := bson.D{
		{Key: "success", Value: true},
		{Key: "tags", Value: bson.D{{Key: "$in", Value: tags}}},
	}
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := m.database.Collection(CollectionDecisions).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var decisions []*types.DecisionLog
	if err := cursor.All(ctx, &decisions); err != nil {
		return nil, err
	}

	return decisions, nil
}

// ============================================================================
// SANDBOX EXECUTIONS
// ============================================================================

// LogScriptExecution saves a sandboxed script execution to MongoDB
func (m *MongoClient) LogScriptExecution(ctx context.Context, exec *types.ScriptExecution) error {
	exec.ID = primitive.NewObjectID()
	if exec.Timestamp.IsZero() {
		exec.Timestamp = time.Now()
	}

	_, err := m.database.Collection(CollectionScriptExecutions).InsertOne(ctx, exec)
	return err
}

// ============================================================================
// VECTOR STATUSES (Exhaustion Ledger)
// ============================================================================

// LogVectorStatus saves an attack vector status to MongoDB
func (m *MongoClient) LogVectorStatus(ctx context.Context, status *types.VectorStatus) error {
	status.ID = primitive.NewObjectID()
	if status.Timestamp.IsZero() {
		status.Timestamp = time.Now()
	}

	_, err := m.database.Collection(CollectionVectorStatuses).InsertOne(ctx, status)
	return err
}

// GetVectorStatuses retrieves all vector statuses for a program
func (m *MongoClient) GetVectorStatuses(ctx context.Context, program string) ([]*types.VectorStatus, error) {
	filter := bson.D{{Key: "program", Value: program}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}})

	cursor, err := m.database.Collection(CollectionVectorStatuses).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var statuses []*types.VectorStatus
	if err := cursor.All(ctx, &statuses); err != nil {
		return nil, err
	}

	return statuses, nil
}
