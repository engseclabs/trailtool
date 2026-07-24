package view

import (
	"reflect"
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func TestClientPlatform(t *testing.T) {
	tests := []struct {
		name string
		c    models.ClientAggregate
		want string
	}{
		{
			name: "full aws-cli platform",
			c:    models.ClientAggregate{OS: "macos", OSVersion: "25.2.0", Architecture: "arm64", Runtime: "python 3.14.4"},
			want: "macos 25.2.0 · arm64 · python 3.14.4",
		},
		{
			name: "browser with os only",
			c:    models.ClientAggregate{OS: "windows"},
			want: "windows",
		},
		{
			name: "os without version",
			c:    models.ClientAggregate{OS: "linux", Architecture: "amd64"},
			want: "linux · amd64",
		},
		{
			name: "empty",
			c:    models.ClientAggregate{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientPlatform(tt.c); got != tt.want {
				t.Errorf("clientPlatform() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTopCommands(t *testing.T) {
	tests := []struct {
		name     string
		commands map[string]int
		max      int
		want     string
	}{
		{
			name:     "sorted by count desc",
			commands: map[string]int{"PutObject": 18, "CreateBucket": 2, "DeleteFunction": 1},
			max:      5,
			want:     "PutObject (18), CreateBucket (2), DeleteFunction (1)",
		},
		{
			name:     "capped at max, ties broken by name",
			commands: map[string]int{"A": 1, "B": 1, "C": 1},
			max:      2,
			want:     "A (1), B (1)",
		},
		{
			name:     "empty",
			commands: nil,
			max:      5,
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := topCommands(tt.commands, tt.max); got != tt.want {
				t.Errorf("topCommands() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplitCommandNamespaces(t *testing.T) {
	api, client := splitCommandNamespaces(map[string]int{
		"PutObject": 18,
		"GetObject": 4,
		"ua:s3.cp":  12,
		"ua:s3.rb":  1,
	})
	wantAPI := map[string]int{"PutObject": 18, "GetObject": 4}
	wantClient := map[string]int{"s3.cp": 12, "s3.rb": 1} // "ua:" stripped
	if !reflect.DeepEqual(api, wantAPI) {
		t.Errorf("apiEvents = %v, want %v", api, wantAPI)
	}
	if !reflect.DeepEqual(client, wantClient) {
		t.Errorf("clientCmds = %v, want %v", client, wantClient)
	}
}
