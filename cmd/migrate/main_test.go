package main

import (
	"slices"
	"strings"
	"testing"
)

func TestChildArgsPassPasswordInEnvironment(t *testing.T) {
	cases := []struct {
		name, dbURL, wantURL string
		wantEnv              []string
	}{
		{
			name:    "password",
			dbURL:   "postgres://app:s3cr3t@db:5432/qeet_id?sslmode=disable",
			wantURL: "postgres://app@db:5432/qeet_id?sslmode=disable",
			wantEnv: []string{"PGPASSWORD=s3cr3t"},
		},
		{
			name:    "escaped password",
			dbURL:   "postgres://app:s3cr%40t@db:5432/qeet_id",
			wantURL: "postgres://app@db:5432/qeet_id",
			wantEnv: []string{"PGPASSWORD=s3cr@t"},
		},
		{
			name:    "socket",
			dbURL:   "postgres://app:s3cr3t@/qeet_id?host=/var/run/postgresql",
			wantURL: "postgres://app@/qeet_id?host=/var/run/postgresql",
			wantEnv: []string{"PGPASSWORD=s3cr3t"},
		},
		{
			name:    "password parameter",
			dbURL:   "postgres://app@db:5432/qeet_id?password=s3cr3t&sslmode=disable",
			wantURL: "postgres://app@db:5432/qeet_id?sslmode=disable",
			wantEnv: []string{"PGPASSWORD=s3cr3t"},
		},
		{
			name:    "no password",
			dbURL:   "postgres://app@db:5432/qeet_id?sslmode=disable",
			wantURL: "postgres://app@db:5432/qeet_id?sslmode=disable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, env, err := childArgs(tc.dbURL, "down", []string{"1"})
			if err != nil {
				t.Fatalf("childArgs: %v", err)
			}
			want := []string{"-path", migrationsPath, "-database", tc.wantURL, "down", "1"}
			if !slices.Equal(args, want) {
				t.Errorf("args = %q, want %q", args, want)
			}
			if !slices.Equal(env, tc.wantEnv) {
				t.Errorf("env = %q, want %q", env, tc.wantEnv)
			}
			for _, arg := range args {
				if strings.Contains(arg, "s3cr") {
					t.Errorf("argument %q contains the password", arg)
				}
			}
		})
	}
}

func TestChildArgsRejectsNonURL(t *testing.T) {
	for _, dbURL := range []string{"host=db password=s3cr3t", "postgres://app:s3cr3t@db:bad-port/x"} {
		if _, _, err := childArgs(dbURL, "up", nil); err == nil {
			t.Errorf("childArgs(%q) accepted", dbURL)
		} else if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("error %q contains the password", err)
		}
	}
}
