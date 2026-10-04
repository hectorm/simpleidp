package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/hectorm/simpleidp"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check HTTP server health and exit")
	flag.Parse()

	if *healthcheck {
		if err := checkHealth(os.Getenv("SIMPLE_IDP_LISTEN")); err != nil {
			slog.Error("healthcheck failed", "error", err)
			os.Exit(1)
		}
		return
	}

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

func checkHealth(listen string) error {
	if listen == "" {
		listen = ":8227"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if host == "" {
		host = "127.0.0.1"
	} else if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() == nil {
			host = "::1"
		} else {
			host = "127.0.0.1"
		}
	}

	endpoint := url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: "/healthz"}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(endpoint.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected healthcheck status: %s", resp.Status)
	}

	return nil
}
