// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// +build go1.16

package main

import (
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"

	"gopkg.in/canonical/candid.v2"
)

func loadTemplates(resourcePath string) (*template.Template, error) {
	if resourcePath == "" {
		templateFS, err := fs.Sub(candid.ResourceFS, "templates")
		if err != nil {
			panic(err)
		}
		return template.New("").ParseFS(templateFS, "*")
	}
	return template.New("").ParseGlob(filepath.Join(resourcePath, "templates", "*"))
}

func staticFS(resourcePath string) http.FileSystem {
	if resourcePath == "" {
		staticFS, err := fs.Sub(candid.ResourceFS, "static")
		if err != nil {
			panic(err)
		}
		return http.FS(staticFS)
	}
	return http.Dir(filepath.Join(resourcePath, "static"))
}
