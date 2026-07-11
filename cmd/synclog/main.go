// Command synclog archives Claude Code transcripts into MongoDB so they survive
// local cleanup (for RLHF corpora / interpretability). It runs two ways:
//
//   - As a Claude Code Stop hook: reads the hook JSON from stdin
//     ({"session_id","transcript_path",...}) and incrementally imports only the
//     new lines of that session's transcript.
//   - Manually: `synclog -transcript <file.jsonl>` for one file, or
//     `synclog -all` to backfill every transcript in the project directory.
//
// Each transcript line is stored losslessly (full raw line) and keyed by its own
// uuid, so firing on every Stop is idempotent and cheap (byte-offset resume).
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/storage"
)

func main() {
	transcript := flag.String("transcript", "", "path to a single transcript .jsonl to import")
	all := flag.Bool("all", false, "backfill every transcript in the project transcript dir")
	dir := flag.String("dir", "", "transcript directory (default: derived from CLAUDE_PROJECT_DIR)")
	flag.Parse()

	// Load .env from the project dir (hooks run with CLAUDE_PROJECT_DIR set).
	projectDir := os.Getenv("CLAUDE_PROJECT_DIR")
	if projectDir != "" {
		config.LoadDotEnv(filepath.Join(projectDir, ".env"))
	}
	config.LoadDotEnv() // also try ./.env

	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		log.Fatal("MONGODB_URI not set (need .env with the Atlas URI)")
	}
	dbName := os.Getenv("MONGODB_DATABASE")
	if dbName == "" {
		dbName = "hack_ai_v2"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	mc, err := storage.NewMongoClient(ctx, uri, dbName)
	if err != nil {
		log.Fatalf("mongo connect: %v", err)
	}
	defer mc.Close(ctx)
	mc.EnsureTranscriptCollection(ctx)

	// Determine which files to import.
	var files []string
	switch {
	case *transcript != "":
		files = []string{*transcript}
	case *all:
		d := transcriptDir(*dir)
		matches, _ := filepath.Glob(filepath.Join(d, "*.jsonl"))
		files = matches
	default:
		// Hook mode: read {"transcript_path",...} from stdin.
		if p := transcriptFromHookStdin(); p != "" {
			files = []string{p}
		}
	}
	if len(files) == 0 {
		log.Println("synclog: no transcript to import (pass -transcript, -all, or pipe hook JSON)")
		return
	}

	total := 0
	for _, f := range files {
		n, err := importTranscript(ctx, mc, f)
		if err != nil {
			log.Printf("  %s: ERROR %v", filepath.Base(f), err)
			continue
		}
		if n > 0 {
			log.Printf("  %s: +%d messages", filepath.Base(f), n)
		}
		total += n
	}
	if count, size, err := mc.TranscriptCollectionStats(ctx); err == nil {
		log.Printf("synclog done: +%d new · %d messages total · %.2f MB on disk", total, count, float64(size)/1e6)
	} else {
		log.Printf("synclog done: +%d new", total)
	}
}

func transcriptDir(override string) string {
	if override != "" {
		return override
	}
	if pd := os.Getenv("CLAUDE_PROJECT_DIR"); pd != "" {
		// Transcripts live under ~/.claude/projects/<encoded-project-path>/
		home, _ := os.UserHomeDir()
		encoded := strings.ReplaceAll(pd, "/", "-")
		return filepath.Join(home, ".claude", "projects", encoded)
	}
	return "."
}

func transcriptFromHookStdin() string {
	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return ""
	}
	var hook struct {
		TranscriptPath string `json:"transcript_path"`
	}
	if json.Unmarshal(data, &hook) == nil {
		return hook.TranscriptPath
	}
	return ""
}

// importTranscript imports only the bytes of a transcript file that have not
// been imported yet (byte-offset resume), then advances the sync offset.
func importTranscript(ctx context.Context, mc *storage.MongoClient, path string) (int, error) {
	sessionID := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	project := filepath.Base(filepath.Dir(path))

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	fi, _ := f.Stat()
	offset, seq := mc.GetSyncState(ctx, sessionID)
	if offset > fi.Size() {
		offset, seq = 0, 0 // file was truncated/rotated → re-import
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}

	reader := bufio.NewReaderSize(f, 1<<20)
	var msgs []storage.TranscriptMessage
	var consumed int64
	lastNewlineConsumed := int64(0)
	lastSeqAtNewline := seq

	for {
		line, err := reader.ReadBytes('\n')
		consumed += int64(len(line))
		trimmed := bytes.TrimSpace(line)
		hadNewline := len(line) > 0 && line[len(line)-1] == '\n'

		if len(trimmed) > 0 && hadNewline {
			seq++
			if m, ok := parseLine(trimmed, sessionID, project, seq); ok {
				msgs = append(msgs, m)
			}
		}
		if hadNewline {
			lastNewlineConsumed = consumed
			lastSeqAtNewline = seq
		}
		if err != nil { // EOF or read error: stop (ignore trailing partial line)
			break
		}
	}

	n, err := mc.UpsertTranscriptMessages(ctx, msgs)
	if err != nil {
		return 0, err
	}
	// Advance offset only past complete (newline-terminated) lines.
	newOffset := offset + lastNewlineConsumed
	_ = mc.SetSyncOffset(ctx, sessionID, newOffset, lastSeqAtNewline)
	return n, nil
}

func parseLine(line []byte, sessionID, project string, seq int) (storage.TranscriptMessage, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return storage.TranscriptMessage{}, false
	}

	m := storage.TranscriptMessage{
		SessionID: strget(raw, "sessionId"),
		Project:   project,
		Type:      strget(raw, "type"),
		Raw:       string(line),
		Seq:       seq,
	}
	if m.SessionID == "" {
		m.SessionID = sessionID
	}
	m.UUID = strget(raw, "uuid")
	if m.UUID == "" { // metadata lines (mode, permission-mode, ...) have no uuid
		m.UUID = fmt.Sprintf("%s:%d", sessionID, seq)
	}
	m.ParentUUID = strget(raw, "parentUuid")
	m.GitBranch = strget(raw, "gitBranch")
	m.CWD = strget(raw, "cwd")
	m.Version = strget(raw, "version")
	if ts := strget(raw, "timestamp"); ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			m.Timestamp = t
		}
	}
	// Extract the role for querying; the full message stays losslessly in Raw.
	if msgRaw, ok := raw["message"]; ok {
		var mm struct {
			Role string `json:"role"`
		}
		if json.Unmarshal(msgRaw, &mm) == nil {
			m.Role = mm.Role
		}
	}
	return m, true
}

func strget(raw map[string]json.RawMessage, key string) string {
	if v, ok := raw[key]; ok {
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s
		}
	}
	return ""
}
