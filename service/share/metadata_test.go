package share

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/cloudreve/Cloudreve/v3/pkg/filesystem/driver/b2"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMetadataClient struct {
	entries map[string]fakeMetadataResult
	calls   []string
}

type fakeMetadataResult struct {
	metadata *b2.Metadata
	err      error
}

func (c *fakeMetadataClient) GetMetadata(ctx context.Context, objectPath string) (*b2.Metadata, error) {
	c.calls = append(c.calls, objectPath)
	result, ok := c.entries[objectPath]
	if !ok {
		return nil, errors.New("unexpected object path")
	}
	return result.metadata, result.err
}

func TestShareMetadataSingleFile(t *testing.T) {
	setupMetadataTestDB(t)
	policy := createMetadataPolicy(t, "s3")
	user := createMetadataUser(t)
	folder := createMetadataFolder(t, user.ID, nil, "root")
	file := createMetadataFile(t, user.ID, folder.ID, policy.ID, "display.txt", "stored/key.txt", 123)

	hash := "0123456789abcdef0123456789abcdef"
	hashType := b2.HashTypeMD5
	client := &fakeMetadataClient{entries: map[string]fakeMetadataResult{
		"stored/key.txt": {metadata: &b2.Metadata{ContentType: "text/plain", Hash: &hash, HashType: &hashType}},
	}}
	factoryCalls := useMetadataClientFactory(t, policy.ID, client)

	res := (&Service{}).Metadata(newMetadataContext(&model.Share{UserID: user.ID, SourceID: file.ID}))

	assert.Equal(t, 0, res.Code)
	data := requireShareMetadataResponse(t, res)
	require.Len(t, data.Items, 1)
	assert.Equal(t, serializer.ShareMetadataItem{
		ObjectPath:  "stored/key.txt",
		Name:        "display.txt",
		Size:        123,
		ContentType: "text/plain",
		Hash:        &hash,
		HashType:    &hashType,
	}, data.Items[0])
	assert.Equal(t, []string{"stored/key.txt"}, client.calls)
	assert.Equal(t, 1, *factoryCalls)
}

func TestShareMetadataDirectoryRecursesFiles(t *testing.T) {
	setupMetadataTestDB(t)
	policy := createMetadataPolicy(t, "s3")
	user := createMetadataUser(t)
	root := createMetadataFolder(t, user.ID, nil, "root")
	child := createMetadataFolder(t, user.ID, &root.ID, "child")
	createMetadataFile(t, user.ID, root.ID, policy.ID, "root.bin", "objects/root.bin", 10)
	createMetadataFile(t, user.ID, child.ID, policy.ID, "child.bin", "objects/child.bin", 20)

	md5 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashType := b2.HashTypeMD5
	client := &fakeMetadataClient{entries: map[string]fakeMetadataResult{
		"objects/root.bin":  {metadata: &b2.Metadata{ContentType: "application/octet-stream", Hash: &md5, HashType: &hashType}},
		"objects/child.bin": {metadata: &b2.Metadata{ContentType: "application/octet-stream", Hash: &md5, HashType: &hashType}},
	}}
	factoryCalls := useMetadataClientFactory(t, policy.ID, client)

	res := (&Service{}).Metadata(newMetadataContext(&model.Share{UserID: user.ID, SourceID: root.ID, IsDir: true}))

	assert.Equal(t, 0, res.Code)
	data := requireShareMetadataResponse(t, res)
	require.Len(t, data.Items, 2)
	paths := []string{data.Items[0].ObjectPath, data.Items[1].ObjectPath}
	sort.Strings(paths)
	assert.Equal(t, []string{"objects/child.bin", "objects/root.bin"}, paths)
	assert.ElementsMatch(t, []string{"objects/root.bin", "objects/child.bin"}, client.calls)
	assert.Equal(t, 1, *factoryCalls)
}

func TestShareMetadataAllowsEmptyHash(t *testing.T) {
	setupMetadataTestDB(t)
	policy := createMetadataPolicy(t, "s3")
	user := createMetadataUser(t)
	folder := createMetadataFolder(t, user.ID, nil, "root")
	file := createMetadataFile(t, user.ID, folder.ID, policy.ID, "empty-hash.bin", "objects/empty-hash.bin", 30)

	client := &fakeMetadataClient{entries: map[string]fakeMetadataResult{
		"objects/empty-hash.bin": {metadata: &b2.Metadata{ContentType: "application/octet-stream"}},
	}}
	useMetadataClientFactory(t, policy.ID, client)

	res := (&Service{}).Metadata(newMetadataContext(&model.Share{UserID: user.ID, SourceID: file.ID}))

	assert.Equal(t, 0, res.Code)
	data := requireShareMetadataResponse(t, res)
	require.Len(t, data.Items, 1)
	assert.Nil(t, data.Items[0].Hash)
	assert.Nil(t, data.Items[0].HashType)
}

func TestShareMetadataReturnsErrorOnMetadataFailure(t *testing.T) {
	setupMetadataTestDB(t)
	policy := createMetadataPolicy(t, "s3")
	user := createMetadataUser(t)
	folder := createMetadataFolder(t, user.ID, nil, "root")
	file := createMetadataFile(t, user.ID, folder.ID, policy.ID, "broken.bin", "objects/broken.bin", 40)

	client := &fakeMetadataClient{entries: map[string]fakeMetadataResult{
		"objects/broken.bin": {err: errors.New("b2 unavailable")},
	}}
	useMetadataClientFactory(t, policy.ID, client)

	res := (&Service{}).Metadata(newMetadataContext(&model.Share{UserID: user.ID, SourceID: file.ID}))

	assert.Equal(t, serializer.CodeQueryMetaFailed, res.Code)
	assert.Equal(t, "Failed to query B2 metadata", res.Msg)
}

func TestShareMetadataRejectsUnsupportedPolicy(t *testing.T) {
	setupMetadataTestDB(t)
	policy := createMetadataPolicy(t, "local")
	user := createMetadataUser(t)
	folder := createMetadataFolder(t, user.ID, nil, "root")
	file := createMetadataFile(t, user.ID, folder.ID, policy.ID, "local.bin", "objects/local.bin", 50)

	factoryCalled := false
	oldFactory := newB2MetadataClient
	newB2MetadataClient = func(policy *model.Policy) (metadataClient, error) {
		factoryCalled = true
		return nil, nil
	}
	t.Cleanup(func() { newB2MetadataClient = oldFactory })

	res := (&Service{}).Metadata(newMetadataContext(&model.Share{UserID: user.ID, SourceID: file.ID}))

	assert.Equal(t, serializer.CodePolicyNotAllowed, res.Code)
	assert.False(t, factoryCalled)
}

func TestShareMetadataRejectsGenericS3Policy(t *testing.T) {
	setupMetadataTestDB(t)
	policy := createMetadataPolicy(t, "s3")
	policy.Server = "https://s3.amazonaws.com"
	require.NoError(t, model.DB.Save(&policy).Error)
	policy.ClearCache()
	user := createMetadataUser(t)
	folder := createMetadataFolder(t, user.ID, nil, "root")
	file := createMetadataFile(t, user.ID, folder.ID, policy.ID, "aws.bin", "objects/aws.bin", 60)

	factoryCalled := false
	oldFactory := newB2MetadataClient
	newB2MetadataClient = func(policy *model.Policy) (metadataClient, error) {
		factoryCalled = true
		return nil, nil
	}
	t.Cleanup(func() { newB2MetadataClient = oldFactory })

	res := (&Service{}).Metadata(newMetadataContext(&model.Share{UserID: user.ID, SourceID: file.ID}))

	assert.Equal(t, serializer.CodePolicyNotAllowed, res.Code)
	assert.False(t, factoryCalled)
}

func setupMetadataTestDB(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cache.Store = cache.NewMemoStore()

	db, err := gorm.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.LogMode(false)
	model.DB = db
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Policy{}, &model.Folder{}, &model.File{}, &model.Share{}).Error)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
		cache.Store = cache.NewMemoStore()
	})
}

func createMetadataPolicy(t *testing.T, policyType string) model.Policy {
	t.Helper()
	policy := model.Policy{
		Name:       "B2 policy",
		Type:       policyType,
		Server:     "https://s3.us-west-004.backblazeb2.com",
		BucketName: "bucket",
		AccessKey:  "account-id",
		SecretKey:  "application-key",
	}
	require.NoError(t, model.DB.Create(&policy).Error)
	return policy
}

func createMetadataUser(t *testing.T) model.User {
	t.Helper()
	user := model.User{Email: "metadata@example.com", Status: model.Active}
	require.NoError(t, model.DB.Create(&user).Error)
	return user
}

func createMetadataFolder(t *testing.T, ownerID uint, parentID *uint, name string) model.Folder {
	t.Helper()
	folder := model.Folder{Name: name, OwnerID: ownerID, ParentID: parentID}
	require.NoError(t, model.DB.Create(&folder).Error)
	return folder
}

func createMetadataFile(t *testing.T, userID, folderID, policyID uint, name, sourceName string, size uint64) model.File {
	t.Helper()
	file := model.File{
		Name:       name,
		SourceName: sourceName,
		UserID:     userID,
		Size:       size,
		FolderID:   folderID,
		PolicyID:   policyID,
	}
	require.NoError(t, model.DB.Create(&file).Error)
	return file
}

func newMetadataContext(share *model.Share) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/api/v3/share/metadata/test", nil)
	c.Request = req
	c.Set("share", share)
	return c
}

func useMetadataClientFactory(t *testing.T, expectedPolicyID uint, client metadataClient) *int {
	t.Helper()
	oldFactory := newB2MetadataClient
	calls := 0
	newB2MetadataClient = func(policy *model.Policy) (metadataClient, error) {
		calls++
		assert.Equal(t, expectedPolicyID, policy.ID)
		return client, nil
	}
	t.Cleanup(func() { newB2MetadataClient = oldFactory })
	return &calls
}

func requireShareMetadataResponse(t *testing.T, res serializer.Response) serializer.ShareMetadataResponse {
	t.Helper()
	data, ok := res.Data.(serializer.ShareMetadataResponse)
	require.True(t, ok)
	return data
}
