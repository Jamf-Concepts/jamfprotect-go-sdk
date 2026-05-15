// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/format"
	"os"
	"text/template"
)

//go:embed templates/resource.go.tmpl
var resourceTmpl string

func emitStatic(srcPath, dstPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	formatted, err := format.Source(data)
	if err != nil {
		return fmt.Errorf("format %s: %w", srcPath, err)
	}
	return os.WriteFile(dstPath, formatted, 0644)
}

func emitFile(ir IRResource, outPath string) error {
	tmpl, err := template.New("resource").Parse(resourceTmpl)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ir); err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("format source (%s):\n%s\n\nerr: %w", outPath, buf.String(), err)
	}

	if err := os.WriteFile(outPath, formatted, 0644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}
