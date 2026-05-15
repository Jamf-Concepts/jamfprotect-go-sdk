// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"log"
	"path/filepath"
)

func main() {
	configPath := flag.String("config", "config.json", "path to generator config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	base := filepath.Dir(*configPath)
	schemaPath := filepath.Join(base, cfg.SchemaPath)
	outputDir := filepath.Join(base, cfg.OutputDir)

	schema, err := loadSchema(schemaPath)
	if err != nil {
		log.Fatalf("load schema: %v", err)
	}

	if err := validateConfig(schema, cfg); err != nil {
		log.Fatalf("config validation: %v", err)
	}

	for _, res := range cfg.Resources {
		ir, err := buildIR(cfg, schema, res)
		if err != nil {
			log.Fatalf("build IR for %s: %v", res.File, err)
		}
		outPath := filepath.Join(outputDir, res.File)
		if err := emitFile(ir, outPath); err != nil {
			log.Fatalf("emit %s: %v", res.File, err)
		}
		log.Printf("generated %s", outPath)
	}

	for _, s := range cfg.Statics {
		srcPath := filepath.Join(base, s.Source)
		dstPath := filepath.Join(outputDir, s.Dest)
		if err := emitStatic(srcPath, dstPath); err != nil {
			log.Fatalf("emit static %s: %v", s.Dest, err)
		}
		log.Printf("static %s", dstPath)
	}
}
