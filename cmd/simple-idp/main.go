package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/hectorm/simpleidp"
)

func main() {
	listen, srv, err := simpleidp.New(os.Environ(), os.Getenv, os.ReadFile)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("simpleidp listening", "address", listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
