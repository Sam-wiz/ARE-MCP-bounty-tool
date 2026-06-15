package config

import (
	"bufio"
	"os"
	"strings"
)

// LoadDotEnv loads KEY=VALUE pairs from a .env file into the process
// environment. Existing environment variables always win (so a real exported
// env var overrides the file), which lets deployments inject secrets without
// touching disk. Missing files are ignored silently — .env is optional.
//
// No third-party dependency: this is a deliberately small parser that supports
// comments (#), blank lines, optional surrounding quotes, and inline
// "export KEY=VALUE" prefixes.
func LoadDotEnv(paths ...string) {
	if len(paths) == 0 {
		paths = []string{".env"}
	}
	for _, path := range paths {
		loadDotEnvFile(path)
	}
}

func loadDotEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // optional file
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			continue
		}

		// Strip a single layer of matching quotes.
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}

		// Do not clobber an already-set environment variable.
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		os.Setenv(key, val)
	}
}
