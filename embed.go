// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package candid

import "embed"

// ResourceFS contains embeded resource files (templates and static
// content).
//
//go:embed static
//go:embed templates
var ResourceFS embed.FS
