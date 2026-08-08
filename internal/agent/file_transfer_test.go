package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func newTestAgentWithFileTransfer(mock *mqttclient.MockMQTTClient, downloader FileTransferDownloader) *Agent {
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	a.fileTransferDownloader = downloader
	return a
}

func fileTransferCmd(cmdID string, files []FileTransferFile) Command {
	b, _ := json.Marshal(FileTransferPayload{Files: files})
	return Command{CmdID: cmdID, Type: "file_transfer", Payload: b}
}

func lastFileTransferAck(mock *mqttclient.MockMQTTClient) (status string, files []FileTransferFileResult) {
	for i := len(mock.Published) - 1; i >= 0; i-- {
		if !containsAckTopic(mock.Published[i].Topic) {
			continue
		}
		var a struct {
			Status string                   `json:"status"`
			Files  []FileTransferFileResult `json:"files"`
		}
		if err := json.Unmarshal(mock.Published[i].Payload, &a); err == nil {
			return a.Status, a.Files
		}
	}
	return "", nil
}

func containsAckTopic(topic string) bool {
	return len(topic) >= 4 && topic[len(topic)-4:] == "/ack"
}

func TestHandleFileTransfer_AllSucceed(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFileTransferDownloader{}
	a := newTestAgentWithFileTransfer(mock, downloader)

	cmd := fileTransferCmd("cmd-1", []FileTransferFile{
		{URL: "http://host/f1", SHA256: "abc", SizeBytes: 10, Path: "/tmp/f1"},
		{URL: "http://host/f2", SHA256: "def", SizeBytes: 20, Path: "/tmp/f2", Mode: "0755"},
	})
	a.handleFileTransfer(cmd)

	if len(downloader.Calls) != 2 {
		t.Fatalf("expected 2 download calls, got %d", len(downloader.Calls))
	}
	status, files := lastFileTransferAck(mock)
	if status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 file results, got %d", len(files))
	}
	for _, f := range files {
		if f.Status != "ok" {
			t.Errorf("file %s: status = %q, want ok", f.Path, f.Status)
		}
	}
}

func TestHandleFileTransfer_PartialFailure(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFileTransferDownloader{
		ErrByURL: map[string]error{
			"http://host/bad": fmt.Errorf("sha256 mismatch"),
		},
	}
	a := newTestAgentWithFileTransfer(mock, downloader)

	cmd := fileTransferCmd("cmd-2", []FileTransferFile{
		{URL: "http://host/good", SHA256: "abc", SizeBytes: 10, Path: "/tmp/good"},
		{URL: "http://host/bad", SHA256: "def", SizeBytes: 10, Path: "/tmp/bad"},
	})
	a.handleFileTransfer(cmd)

	if len(downloader.Calls) != 2 {
		t.Fatalf("expected both files attempted independently, got %d calls", len(downloader.Calls))
	}
	status, files := lastFileTransferAck(mock)
	if status != "error" {
		t.Errorf("overall status = %q, want error", status)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 file results, got %d", len(files))
	}
	byPath := map[string]FileTransferFileResult{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	if byPath["/tmp/good"].Status != "ok" {
		t.Errorf("expected /tmp/good to still succeed, got %+v", byPath["/tmp/good"])
	}
	if byPath["/tmp/bad"].Status != "error" || byPath["/tmp/bad"].Error == "" {
		t.Errorf("expected /tmp/bad to report an error, got %+v", byPath["/tmp/bad"])
	}
}

func TestHandleFileTransfer_EmptyFilesList(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFileTransferDownloader{}
	a := newTestAgentWithFileTransfer(mock, downloader)

	a.handleFileTransfer(fileTransferCmd("cmd-3", nil))

	if len(downloader.Calls) != 0 {
		t.Errorf("expected no download calls for empty file list, got %+v", downloader.Calls)
	}
	status, _ := lastFileTransferAck(mock)
	if status != "error" {
		t.Errorf("status = %q, want error", status)
	}
}

func TestHandleFileTransfer_MissingFields(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFileTransferDownloader{}
	a := newTestAgentWithFileTransfer(mock, downloader)

	cmd := fileTransferCmd("cmd-4", []FileTransferFile{
		{URL: "", SHA256: "abc", SizeBytes: 10, Path: "/tmp/missing-url"},
		{URL: "http://host/ok", SHA256: "abc", SizeBytes: 10, Path: "/tmp/ok"},
	})
	a.handleFileTransfer(cmd)

	if len(downloader.Calls) != 1 {
		t.Fatalf("expected only the valid entry to call the downloader, got %d calls", len(downloader.Calls))
	}
	status, files := lastFileTransferAck(mock)
	if status != "error" {
		t.Errorf("overall status = %q, want error", status)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 file results, got %d", len(files))
	}
}

func TestHandleFileTransfer_InvalidPayloadRejectedWithoutDownload(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFileTransferDownloader{}
	a := newTestAgentWithFileTransfer(mock, downloader)

	a.handleFileTransfer(Command{CmdID: "cmd-5", Type: "file_transfer", Payload: []byte(`not-json`)})

	if len(downloader.Calls) != 0 {
		t.Errorf("expected no download calls for undecodable payload, got %+v", downloader.Calls)
	}
}

func TestParseFileMode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want os.FileMode
	}{
		{"empty defaults to 0644", "", 0644},
		{"explicit mode passes through", "0755", 0755},
		{"invalid falls back to default", "not-octal", 0644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseFileMode(tt.in); got != tt.want {
				t.Errorf("parseFileMode(%q) = %o, want %o", tt.in, got, tt.want)
			}
		})
	}
}

func TestHTTPFileTransferDownloader_Success(t *testing.T) {
	content := []byte("hello file transfer")
	sum := sha256Hex(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "nested", "dest.bin")

	d := &HTTPFileTransferDownloader{}
	err := d.Download(context.Background(), srv.URL, dest, sum, int64(len(content))+1024, 0755)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if _, err := os.Stat(dest + ".waverms-tmp"); err == nil {
		t.Error("expected .waverms-tmp to be cleaned up on success")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("dest content = %q, want %q", data, content)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat dest: %v", err)
	}
	if fi.Mode().Perm() != 0755 {
		t.Errorf("dest mode = %o, want 0755", fi.Mode().Perm())
	}
}

func TestHTTPFileTransferDownloader_DestIsExistingDirectory(t *testing.T) {
	content := []byte("usteer-ng binary")
	sum := sha256Hex(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "usteer-ng")
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	d := &HTTPFileTransferDownloader{}
	err := d.Download(context.Background(), srv.URL, dest, sum, int64(len(content))+1024, 0755)
	if err == nil {
		t.Fatal("expected an error when the target path is an existing directory")
	}
	if !strings.Contains(err.Error(), "existing directory") {
		t.Errorf("error = %q, want it to mention the target is an existing directory", err.Error())
	}
	if _, statErr := os.Stat(filepath.Join(dest, ".waverms-tmp")); statErr == nil {
		t.Error("expected no .waverms-tmp to be left behind inside the directory")
	}
}

func TestHTTPFileTransferDownloader_ChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("actual content"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")

	d := &HTTPFileTransferDownloader{}
	err := d.Download(context.Background(), srv.URL, dest, "deadbeef", 1024, 0644)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("expected dest to not exist after checksum mismatch")
	}
	if _, statErr := os.Stat(dest + ".waverms-tmp"); statErr == nil {
		t.Error("expected .waverms-tmp to be cleaned up on checksum mismatch")
	}
}

func TestHTTPFileTransferDownloader_SizeExceeded(t *testing.T) {
	content := []byte("this content is definitely too long for the limit")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")

	d := &HTTPFileTransferDownloader{}
	err := d.Download(context.Background(), srv.URL, dest, sha256Hex(content), 5, 0644)
	if err == nil {
		t.Fatal("expected size-exceeded error")
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("expected dest to not exist after size-exceeded failure")
	}
}

func TestHTTPFileTransferDownloader_CreatesParentDirs(t *testing.T) {
	content := []byte("x")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "a", "b", "c", "dest.bin")

	d := &HTTPFileTransferDownloader{}
	if err := d.Download(context.Background(), srv.URL, dest, sha256Hex(content), 1024, 0644); err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if fi, err := os.Stat(filepath.Dir(dest)); err != nil || !fi.IsDir() {
		t.Errorf("expected parent dir to be created, err=%v", err)
	}
}

func TestHTTPFileTransferDownloader_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")

	d := &HTTPFileTransferDownloader{}
	if err := d.Download(context.Background(), srv.URL, dest, "abc", 1024, 0644); err == nil {
		t.Fatal("expected HTTP error to propagate")
	}
}

func TestPublishInfo_CapabilitiesContainFileTransfer(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	if err := a.publishInfo(context.Background()); err != nil {
		t.Fatalf("publishInfo: %v", err)
	}

	var info InfoPayload
	if err := json.Unmarshal(mqttMock.Published[0].Payload, &info); err != nil {
		t.Fatalf("unmarshal info: %v", err)
	}
	found := false
	for _, c := range info.Capabilities {
		if c == "file_transfer" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected capabilities to contain file_transfer, got %+v", info.Capabilities)
	}
}
