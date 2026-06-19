//go:build tools

package api

import (
	_ "github.com/testcontainers/testcontainers-go"
	_ "github.com/testcontainers/testcontainers-go/modules/mongodb"
)
