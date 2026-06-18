package storage

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// REVIEWS
// ============================================================================

// SaveReview persists an adversarial panel review round.
func (m *MongoClient) SaveReview(ctx context.Context, r *types.Review) error {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	_, err := m.database.Collection(CollectionReviews).InsertOne(ctx, r)
	return err
}

// GetReviewsByFinding returns all review rounds for a finding, oldest first.
func (m *MongoClient) GetReviewsByFinding(ctx context.Context, findingID string) ([]*types.Review, error) {
	filter := bson.D{{Key: "finding_id", Value: findingID}}
	opts := options.Find().SetSort(bson.D{{Key: "round", Value: 1}})
	cursor, err := m.database.Collection(CollectionReviews).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var reviews []*types.Review
	if err := cursor.All(ctx, &reviews); err != nil {
		return nil, err
	}
	return reviews, nil
}

// NextReviewRound returns the round number to use for the next review of a finding.
func (m *MongoClient) NextReviewRound(ctx context.Context, findingID string) int {
	count, _ := m.database.Collection(CollectionReviews).CountDocuments(ctx,
		bson.D{{Key: "finding_id", Value: findingID}})
	return int(count) + 1
}

// ============================================================================
// TRIAGE OUTCOMES (the feedback loop)
// ============================================================================

// LogTriageOutcome records a real-world submission verdict.
func (m *MongoClient) LogTriageOutcome(ctx context.Context, o *types.TriageOutcome) error {
	if o.RecordedAt.IsZero() {
		o.RecordedAt = time.Now()
	}
	_, err := m.database.Collection(CollectionTriageOutcomes).InsertOne(ctx, o)
	return err
}

// GetTriageOutcomes returns outcomes, optionally filtered by program (empty = all).
func (m *MongoClient) GetTriageOutcomes(ctx context.Context, program string) ([]*types.TriageOutcome, error) {
	filter := bson.D{}
	if program != "" {
		filter = bson.D{{Key: "program", Value: program}}
	}
	opts := options.Find().SetSort(bson.D{{Key: "recorded_at", Value: -1}})
	cursor, err := m.database.Collection(CollectionTriageOutcomes).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var outcomes []*types.TriageOutcome
	if err := cursor.All(ctx, &outcomes); err != nil {
		return nil, err
	}
	return outcomes, nil
}

// OutcomeStats is the real scoreboard computed from triage outcomes.
type OutcomeStats struct {
	Program       string                 `json:"program"`
	Total         int                    `json:"total"`
	ByState       map[string]int         `json:"by_state"`
	TotalReward   float64                `json:"total_reward"`
	PaidCount     int                    `json:"paid_count"`
	AcceptRate    float64                `json:"accept_rate"` // ACCEPTED / total
	ValidCount    int                    `json:"valid_count"` // ACCEPTED + DUPLICATE (findings that were real)
	ValidRate     float64                `json:"valid_rate"`  // ValidCount / total
	RewardByType  map[string]float64     `json:"reward_by_type"`
}

// GetOutcomeStats computes the true (outcome-based) scoreboard for a program
// (empty = all). Unlike v1's self-labelled "hit rate", this reflects reality.
func (m *MongoClient) GetOutcomeStats(ctx context.Context, program string) (*OutcomeStats, error) {
	outcomes, err := m.GetTriageOutcomes(ctx, program)
	if err != nil {
		return nil, err
	}
	stats := &OutcomeStats{
		Program:      program,
		ByState:      map[string]int{},
		RewardByType: map[string]float64{},
	}
	for _, o := range outcomes {
		stats.Total++
		stats.ByState[string(o.State)]++
		stats.TotalReward += o.RewardAmount
		if o.RewardAmount > 0 {
			stats.PaidCount++
		}
		if o.State == types.TriageAccepted {
			stats.RewardByType[o.VulnType] += o.RewardAmount
		}
	}
	// "Valid" = the finding was real, whether or not we were first: ACCEPTED
	// (real + first, paid) plus DUPLICATE (real but someone beat us → $0). A
	// duplicate is a positive signal about finding quality but a saturation
	// warning about earning — hence tracked separately from accept-rate.
	stats.ValidCount = stats.ByState[string(types.TriageAccepted)] + stats.ByState[string(types.TriageDuplicate)]
	if stats.Total > 0 {
		stats.AcceptRate = float64(stats.ByState[string(types.TriageAccepted)]) / float64(stats.Total)
		stats.ValidRate = float64(stats.ValidCount) / float64(stats.Total)
	}
	return stats, nil
}

// ============================================================================
// TRIAGE THREADS — semantic retrieval (lightweight, brute-force cosine)
// ============================================================================

// ThreadVec is a triage thread with its stored embedding, for similarity search.
type ThreadVec struct {
	ID        string    `bson:"_id"`
	Program   string    `bson:"program"`
	Title     string    `bson:"title"`
	State     string    `bson:"state"`
	Snippet   string    `bson:"snippet"`   // compact text for prompt injection
	Embedding []float32 `bson:"embedding"` // may be empty until embedded
}

// GetThreadsForEmbedding returns triage threads that still need an embedding,
// with the raw messages so the caller can build the text to embed.
func (m *MongoClient) GetThreadsForEmbedding(ctx context.Context) ([]bson.M, error) {
	filter := bson.D{{Key: "embedding", Value: bson.D{{Key: "$exists", Value: false}}}}
	cur, err := m.database.Collection("triage_threads").Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var docs []bson.M
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	return docs, nil
}

// SetThreadEmbedding stores an embedding + compact snippet on a thread.
func (m *MongoClient) SetThreadEmbedding(ctx context.Context, id string, snippet string, vec []float32) error {
	_, err := m.database.Collection("triage_threads").UpdateOne(ctx,
		bson.D{{Key: "_id", Value: id}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "snippet", Value: snippet},
			{Key: "embedding", Value: vec},
		}}})
	return err
}

// ClearThreadEmbeddings removes stored embeddings (for a full re-embed).
func (m *MongoClient) ClearThreadEmbeddings(ctx context.Context) {
	m.database.Collection("triage_threads").UpdateMany(ctx, bson.D{},
		bson.D{{Key: "$unset", Value: bson.D{{Key: "embedding", Value: ""}, {Key: "snippet", Value: ""}}}})
}

// AllThreadVecs loads every thread that has an embedding (for cosine search).
func (m *MongoClient) AllThreadVecs(ctx context.Context) ([]ThreadVec, error) {
	filter := bson.D{{Key: "embedding", Value: bson.D{{Key: "$exists", Value: true}}}}
	cur, err := m.database.Collection("triage_threads").Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var vecs []ThreadVec
	if err := cur.All(ctx, &vecs); err != nil {
		return nil, err
	}
	return vecs, nil
}

// ============================================================================
// LESSONS (reviewer grounding)
// ============================================================================

// SaveLesson persists a curated lesson.
func (m *MongoClient) SaveLesson(ctx context.Context, l *types.Lesson) error {
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	_, err := m.database.Collection(CollectionLessons).InsertOne(ctx, l)
	return err
}

// GetLessons returns global lessons plus any scoped to the given program and/or
// vuln type. All filters are optional.
func (m *MongoClient) GetLessons(ctx context.Context, program, vulnType string) ([]*types.Lesson, error) {
	// Global lessons (no program) OR matching program.
	programClause := bson.A{
		bson.D{{Key: "program", Value: ""}},
		bson.D{{Key: "program", Value: bson.D{{Key: "$exists", Value: false}}}},
	}
	if program != "" {
		programClause = append(programClause, bson.D{{Key: "program", Value: program}})
	}
	filter := bson.D{{Key: "$or", Value: programClause}}
	if vulnType != "" {
		filter = bson.D{
			{Key: "$or", Value: programClause},
			{Key: "$or", Value: bson.A{
				bson.D{{Key: "vuln_type", Value: ""}},
				bson.D{{Key: "vuln_type", Value: bson.D{{Key: "$exists", Value: false}}}},
				bson.D{{Key: "vuln_type", Value: vulnType}},
			}},
		}
	}

	cursor, err := m.database.Collection(CollectionLessons).Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var lessons []*types.Lesson
	if err := cursor.All(ctx, &lessons); err != nil {
		return nil, err
	}
	return lessons, nil
}

// ============================================================================
// HYPOTHESES (director output)
// ============================================================================

// SaveHypothesis persists a director-proposed attack idea.
func (m *MongoClient) SaveHypothesis(ctx context.Context, h *types.Hypothesis) error {
	if h.CreatedAt.IsZero() {
		h.CreatedAt = time.Now()
	}
	_, err := m.database.Collection(CollectionHypotheses).InsertOne(ctx, h)
	return err
}

// GetHypotheses returns hypotheses for a program, newest first.
func (m *MongoClient) GetHypotheses(ctx context.Context, program string) ([]*types.Hypothesis, error) {
	filter := bson.D{{Key: "program", Value: program}}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.database.Collection(CollectionHypotheses).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var hyps []*types.Hypothesis
	if err := cursor.All(ctx, &hyps); err != nil {
		return nil, err
	}
	return hyps, nil
}

// ============================================================================
// FINDING STATE
// ============================================================================

// UpdateFindingState advances a finding to a new lifecycle state.
func (m *MongoClient) UpdateFindingState(ctx context.Context, findingID string, state types.FindingState) error {
	filter := bson.D{{Key: "_id", Value: findingID}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: state}}}}
	_, err := m.database.Collection(CollectionFindings).UpdateOne(ctx, filter, update)
	return err
}
