// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
	"html/template"
	"net/http"
	"path/filepath"
)

func loadTemplates(resourcePath string) (*template.Template, error) {
	return template.New("").ParseGlob(filepath.Join(resourcePath, "templates", "*"))
}

func staticFS(resourcePath string) http.FileSystem {
	return http.Dir(filepath.Join(resourcePath, "static"))
}
