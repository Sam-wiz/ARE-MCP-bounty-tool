package storage

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Transcript collections. transcripts holds one document per transcript line
// (keyed by the line's own uuid so re-imports are idempotent). transcript_sync
// tracks how many bytes of each session file have already been imported, so the
// Stop hook can run incrementally instead of re-reading the whole file.
const (
	CollectionTranscripts    = "transcripts"
	CollectionTranscriptSync = "transcript_sync"
)

// TranscriptMessage is one line of a Claude Code transcript, stored losslessly.
// The full original JSON line is kept in Raw for perfect fidelity (RLHF), while
// the extracted fields make it queryable (filter by session/role/tool).
type TranscriptMessage struct {
	UUID       string    `bson:"_id"`         // the line's own uuid — deterministic, idempotent
	SessionID  string    `bson:"session_id"`
	Project    string    `bson:"project"`
	Type       string    `bson:"type"`                  // user | assistant | system | tool-result | ...
	Role       string    `bson:"role,omitempty"`        // message.role when present
	ParentUUID string    `bson:"parent_uuid,omitempty"` // conversation threading
	GitBranch  string    `bson:"git_branch,omitempty"`
	CWD        string    `bson:"cwd,omitempty"`
	Version    string    `bson:"version,omitempty"`
	Timestamp  time.Time `bson:"timestamp,omitempty"`
	Seq        int       `bson:"seq"` // line number within the file
	Raw        string    `bson:"raw"` // the full original JSONL line (lossless, exact)
	ImportedAt time.Time `bson:"imported_at"`
}

// EnsureTranscriptCollection creates the transcripts collection with zstd block
// compression (better ratio than the default snappy) if it does not yet exist.
// On tiers that reject custom storage options it falls back to a plain create.
func (m *MongoClient) EnsureTranscriptCollection(ctx context.Context) {
	names, _ := m.database.ListCollectionNames(ctx, bson.D{{Key: "name", Value: CollectionTranscripts}})
	if len(names) == 0 {
		opts := options.CreateCollection().SetStorageEngine(bson.M{
			"wiredTiger": bson.M{"configString": "block_compressor=zstd"},
		})
		if err := m.database.CreateCollection(ctx, CollectionTranscripts, opts); err != nil {
			// zstd not permitted (e.g. shared tier) — create with defaults.
			_ = m.database.CreateCollection(ctx, CollectionTranscripts)
		}
	}
	m.database.Collection(CollectionTranscripts).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "session_id", Value: 1}, {Key: "seq", Value: 1}}},
		{Keys: bson.D{{Key: "project", Value: 1}, {Key: "timestamp", Value: 1}}},
		{Keys: bson.D{{Key: "type", Value: 1}}},
	})
}

// UpsertTranscriptMessages idempotently writes a batch of transcript lines.
// Deterministic _id (uuid) means re-importing the same lines is a no-op.
func (m *MongoClient) UpsertTranscriptMessages(ctx context.Context, msgs []TranscriptMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	coll := m.database.Collection(CollectionTranscripts)
	const chunk = 200 // keep each BulkWrite request modest (messages can be large)
	written := 0
	for start := 0; start < len(msgs); start += chunk {
		end := start + chunk
		if end > len(msgs) {
			end = len(msgs)
		}
		models := make([]mongo.WriteModel, 0, end-start)
		for i := start; i < end; i++ {
			msgs[i].ImportedAt = time.Now()
			models = append(models, mongo.NewReplaceOneModel().
				SetFilter(bson.D{{Key: "_id", Value: msgs[i].UUID}}).
				SetReplacement(msgs[i]).
				SetUpsert(true))
		}
		res, err := coll.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
		if err != nil {
			return written, err
		}
		written += int(res.UpsertedCount + res.ModifiedCount)
	}
	return written, nil
}

// GetSyncState returns the byte offset and last line number already imported
// for a session file (0, 0 if never synced).
func (m *MongoClient) GetSyncState(ctx context.Context, sessionID string) (offset int64, seq int) {
	var doc struct {
		Offset  int64 `bson:"offset"`
		LastSeq int   `bson:"last_seq"`
	}
	if err := m.database.Collection(CollectionTranscriptSync).
		FindOne(ctx, bson.D{{Key: "_id", Value: sessionID}}).Decode(&doc); err != nil {
		return 0, 0
	}
	return doc.Offset, doc.LastSeq
}

// SetSyncOffset records how many bytes of a session file have been imported.
func (m *MongoClient) SetSyncOffset(ctx context.Context, sessionID string, offset int64, seq int) error {
	_, err := m.database.Collection(CollectionTranscriptSync).UpdateOne(ctx,
		bson.D{{Key: "_id", Value: sessionID}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "offset", Value: offset},
			{Key: "last_seq", Value: seq},
			{Key: "updated_at", Value: time.Now()},
		}}},
		options.Update().SetUpsert(true))
	return err
}

// TranscriptCollectionStats returns document count and compressed on-disk size.
func (m *MongoClient) TranscriptCollectionStats(ctx context.Context) (count int64, storageBytes int64, err error) {
	var stats struct {
		Count       int64 `bson:"count"`
		StorageSize int64 `bson:"storageSize"`
	}
	cmd := bson.D{{Key: "collStats", Value: CollectionTranscripts}}
	if e := m.database.RunCommand(ctx, cmd).Decode(&stats); e != nil {
		return 0, 0, e
	}
	return stats.Count, stats.StorageSize, nil
}
