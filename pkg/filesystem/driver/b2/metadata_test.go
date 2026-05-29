package b2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientGetMetadataUsesAuthorizeBucket(t *testing.T) {
	contentMD5 := "0123456789abcdef0123456789abcdef"
	contentSHA1 := "0123456789abcdef0123456789abcdef01234567"
	server, counts := newMetadataServer(t, metadataServerOptions{
		AuthorizeBucketID:   "bucket-id",
		AuthorizeBucketName: "bucket",
		FileInfo: fileInfo{
			FileID:      "file-id",
			FileName:    "stored/object.txt",
			ContentType: "text/plain",
			ContentMD5:  &contentMD5,
			ContentSHA1: &contentSHA1,
		},
	})
	defer server.Close()

	client, err := NewMetadataClientWithOptions(&model.Policy{
		BucketName: "bucket",
		AccessKey:  "account-id",
		SecretKey:  "application-key",
	}, server.Client(), server.URL+"/b2api/v4/b2_authorize_account")
	require.NoError(t, err)

	metadata, err := client.GetMetadata(context.Background(), "stored/object.txt")

	require.NoError(t, err)
	assert.Equal(t, "text/plain", metadata.ContentType)
	require.NotNil(t, metadata.Hash)
	require.NotNil(t, metadata.HashType)
	assert.Equal(t, contentMD5, *metadata.Hash)
	assert.Equal(t, HashTypeMD5, *metadata.HashType)
	assert.Equal(t, 1, counts.Authorize)
	assert.Equal(t, 0, counts.ListBuckets)
	assert.Equal(t, 1, counts.ListFileNames)
	assert.Equal(t, 0, counts.GetFileInfo)

	_, err = client.GetMetadata(context.Background(), "stored/object.txt")
	require.NoError(t, err)
	assert.Equal(t, 1, counts.Authorize)
	assert.Equal(t, 0, counts.ListBuckets)
	assert.Equal(t, 2, counts.ListFileNames)
	assert.Equal(t, 0, counts.GetFileInfo)
}

func TestClientGetMetadataResolvesBucketFromListBuckets(t *testing.T) {
	contentSHA1 := "0123456789abcdef0123456789abcdef01234567"
	server, counts := newMetadataServer(t, metadataServerOptions{
		Buckets: []bucketEntry{{BucketID: "bucket-id", BucketName: "bucket"}},
		FileInfo: fileInfo{
			FileID:      "file-id",
			FileName:    "stored/object.txt",
			ContentType: "application/octet-stream",
			ContentSHA1: &contentSHA1,
		},
	})
	defer server.Close()

	client, err := NewMetadataClientWithOptions(&model.Policy{
		BucketName: "bucket",
		AccessKey:  "account-id",
		SecretKey:  "application-key",
	}, server.Client(), server.URL+"/b2api/v4/b2_authorize_account")
	require.NoError(t, err)

	metadata, err := client.GetMetadata(context.Background(), "stored/object.txt")

	require.NoError(t, err)
	require.NotNil(t, metadata.Hash)
	require.NotNil(t, metadata.HashType)
	assert.Equal(t, contentSHA1, *metadata.Hash)
	assert.Equal(t, HashTypeSHA1, *metadata.HashType)
	assert.Equal(t, 1, counts.ListBuckets)
	assert.Equal(t, 0, counts.GetFileInfo)
}

func TestClientGetMetadataFallsBackToFileInfo(t *testing.T) {
	contentSHA1 := "0123456789abcdef0123456789abcdef01234567"
	listInfo := fileInfo{FileID: "file-id", FileName: "stored/object.txt"}
	server, counts := newMetadataServer(t, metadataServerOptions{
		AuthorizeBucketID:   "bucket-id",
		AuthorizeBucketName: "bucket",
		ListFileInfo:        &listInfo,
		FileInfo: fileInfo{
			FileID:      "file-id",
			FileName:    "stored/object.txt",
			ContentType: "application/octet-stream",
			ContentSHA1: &contentSHA1,
		},
	})
	defer server.Close()

	client, err := NewMetadataClientWithOptions(&model.Policy{
		BucketName: "bucket",
		AccessKey:  "account-id",
		SecretKey:  "application-key",
	}, server.Client(), server.URL+"/b2api/v4/b2_authorize_account")
	require.NoError(t, err)

	metadata, err := client.GetMetadata(context.Background(), "stored/object.txt")

	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", metadata.ContentType)
	require.NotNil(t, metadata.Hash)
	require.NotNil(t, metadata.HashType)
	assert.Equal(t, contentSHA1, *metadata.Hash)
	assert.Equal(t, HashTypeSHA1, *metadata.HashType)
	assert.Equal(t, 1, counts.GetFileInfo)
}

func TestClientGetMetadataErrorsWhenBucketCannotBeResolved(t *testing.T) {
	server, _ := newMetadataServer(t, metadataServerOptions{})
	defer server.Close()

	client, err := NewMetadataClientWithOptions(&model.Policy{
		BucketName: "bucket",
		AccessKey:  "account-id",
		SecretKey:  "application-key",
	}, server.Client(), server.URL+"/b2api/v4/b2_authorize_account")
	require.NoError(t, err)

	_, err = client.GetMetadata(context.Background(), "stored/object.txt")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to resolve bucket id")
}

func TestSelectHashFallbacks(t *testing.T) {
	md5 := "0123456789abcdef0123456789abcdef"
	sha1 := "0123456789abcdef0123456789abcdef01234567"
	empty := ""
	none := "none"

	tests := []struct {
		name     string
		md5      *string
		sha1     *string
		expected *string
		typeName *string
	}{
		{name: "md5", md5: &md5, sha1: &sha1, expected: &md5, typeName: stringPtr(HashTypeMD5)},
		{name: "sha1 fallback", md5: &empty, sha1: &sha1, expected: &sha1, typeName: stringPtr(HashTypeSHA1)},
		{name: "nil md5 sha1 fallback", sha1: &sha1, expected: &sha1, typeName: stringPtr(HashTypeSHA1)},
		{name: "empty", md5: &empty, sha1: &empty},
		{name: "none", md5: &none, sha1: &none},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash, hashType := selectHash(test.md5, test.sha1)
			if test.expected == nil {
				assert.Nil(t, hash)
				assert.Nil(t, hashType)
				return
			}
			require.NotNil(t, hash)
			require.NotNil(t, hashType)
			assert.Equal(t, *test.expected, *hash)
			assert.Equal(t, *test.typeName, *hashType)
		})
	}
}

type metadataServerOptions struct {
	AuthorizeBucketID   string
	AuthorizeBucketName string
	Buckets             []bucketEntry
	ListFileInfo        *fileInfo
	FileInfo            fileInfo
}

type metadataServerCounts struct {
	Authorize     int
	ListBuckets   int
	ListFileNames int
	GetFileInfo   int
}

func newMetadataServer(t *testing.T, options metadataServerOptions) (*httptest.Server, *metadataServerCounts) {
	t.Helper()
	counts := &metadataServerCounts{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/b2api/v4/b2_authorize_account":
			counts.Authorize++
			assert.Equal(t, http.MethodGet, r.Method)
			user, password, ok := r.BasicAuth()
			require.True(t, ok)
			assert.Equal(t, "account-id", user)
			assert.Equal(t, "application-key", password)
			writeJSON(t, w, authorizeResponse{
				AccountID:          "account-id",
				AuthorizationToken: "authorization-token",
				APIInfo: apiInfo{StorageAPI: storageAPIInfo{
					APIURL: server.URL,
					Allowed: allowedInfo{Buckets: []bucketEntry{{
						ID:   options.AuthorizeBucketID,
						Name: options.AuthorizeBucketName,
					}}},
				}},
			})
		case "/b2api/v4/b2_list_buckets":
			counts.ListBuckets++
			assertAuthorized(t, r)
			var req listBucketsRequest
			decodeJSON(t, r, &req)
			assert.Equal(t, "account-id", req.AccountID)
			writeJSON(t, w, listBucketsResponse{Buckets: options.Buckets})
		case "/b2api/v4/b2_list_file_names":
			counts.ListFileNames++
			assertAuthorized(t, r)
			var req listFileNamesRequest
			decodeJSON(t, r, &req)
			assert.Equal(t, "bucket-id", req.BucketID)
			assert.Equal(t, "stored/object.txt", req.Prefix)
			assert.Equal(t, 1, req.MaxFileCount)
			listInfo := options.FileInfo
			if options.ListFileInfo != nil {
				listInfo = *options.ListFileInfo
			}
			if listInfo.FileID == "" {
				listInfo.FileID = "file-id"
			}
			if listInfo.FileName == "" {
				listInfo.FileName = req.Prefix
			}
			writeJSON(t, w, listFileNamesResponse{Files: []fileInfo{listInfo}})
		case "/b2api/v4/b2_get_file_info":
			counts.GetFileInfo++
			assertAuthorized(t, r)
			var req getFileInfoRequest
			decodeJSON(t, r, &req)
			assert.Equal(t, "file-id", req.FileID)
			writeJSON(t, w, options.FileInfo)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	return server, counts
}

func assertAuthorized(t *testing.T, r *http.Request) {
	t.Helper()
	assert.Equal(t, "authorization-token", r.Header.Get("Authorization"))
	assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
}

func decodeJSON(t *testing.T, r *http.Request, out interface{}) {
	t.Helper()
	require.NoError(t, json.NewDecoder(r.Body).Decode(out))
}

func writeJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}

func stringPtr(value string) *string {
	return &value
}
