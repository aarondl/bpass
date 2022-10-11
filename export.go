package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

func export(u *uiContext) error {
	var entries []string
	keysSet := make(map[string]struct{})

	for entry, blob := range u.store.DB.Snapshot {
		entries = append(entries, entry)
		for k := range blob {
			keysSet[k] = struct{}{}
		}
	}

	slices.Sort(entries)
	keys := maps.Keys(keysSet)
	slices.Sort(keys)

	if flagExportFormat != "CSV" {
		return errors.New("only supported format for export is csv")
	}

	f, err := os.Create(flagExportFilename)
	if err != nil {
		return fmt.Errorf("failed to create file (%s): %w", flagExportFilename, err)
	}
	defer f.Close()
	out := csv.NewWriter(f)

	out.Write(keys)

	for _, entry := range entries {
		blob := u.store.DB.Snapshot[entry]

		record := make([]string, len(keys))
		for i, key := range keys {
			record[i] = blob[key]
		}

		out.Write(record)
	}

	out.Flush()
	if err := out.Error(); err != nil {
		return fmt.Errorf("failed to flush csv file: %w", err)
	}

	return nil
}
