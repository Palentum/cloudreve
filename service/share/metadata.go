package share

import (
	"context"
	"net/url"
	"sort"
	"strings"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/filesystem/driver/b2"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type metadataClient interface {
	GetMetadata(ctx context.Context, objectPath string) (*b2.Metadata, error)
}

type metadataClientFactory func(policy *model.Policy) (metadataClient, error)

var newB2MetadataClient metadataClientFactory = func(policy *model.Policy) (metadataClient, error) {
	return b2.NewMetadataClient(policy)
}

// Metadata returns database and Backblaze B2 metadata for every file in a share.
func (service *Service) Metadata(c *gin.Context) serializer.Response {
	shareCtx, ok := c.Get("share")
	if !ok {
		return serializer.Err(serializer.CodeShareLinkNotFound, "", nil)
	}

	files, err := collectShareFiles(shareCtx.(*model.Share))
	if err != nil {
		return serializer.Err(serializer.CodeNotSet, "", err)
	}

	ctx := context.Background()
	if c.Request != nil {
		ctx = c.Request.Context()
	}

	items, err := buildShareMetadataItems(ctx, files)
	if err != nil {
		return serializer.Err(serializer.CodeNotSet, "", err)
	}

	return serializer.Response{
		Code: 0,
		Data: serializer.ShareMetadataResponse{Items: items},
	}
}

func collectShareFiles(share *model.Share) ([]model.File, error) {
	if !share.IsDir {
		file := share.SourceFile()
		if file.ID == 0 {
			return nil, serializer.NewError(serializer.CodeFileNotFound, "", nil)
		}
		return []model.File{*file}, nil
	}

	folders, err := model.GetRecursiveChildFolder([]uint{share.SourceID}, share.UserID, true)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "Database operation failed.", err)
	}
	if len(folders) == 0 {
		return nil, serializer.NewError(serializer.CodeFileNotFound, "", nil)
	}

	files, err := model.GetChildFilesOfFolders(&folders)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "Database operation failed.", err)
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].ID < files[j].ID
	})
	return files, nil
}

func buildShareMetadataItems(ctx context.Context, files []model.File) ([]serializer.ShareMetadataItem, error) {
	items := make([]serializer.ShareMetadataItem, 0, len(files))
	clients := make(map[uint]metadataClient)

	for i := range files {
		file := &files[i]
		client, ok := clients[file.PolicyID]
		if !ok {
			var err error
			client, err = metadataClientForPolicy(file.PolicyID)
			if err != nil {
				return nil, err
			}
			clients[file.PolicyID] = client
		}

		metadata, err := client.GetMetadata(ctx, file.SourceName)
		if err != nil {
			return nil, serializer.NewError(serializer.CodeQueryMetaFailed, "Failed to query B2 metadata", err)
		}

		items = append(items, serializer.ShareMetadataItem{
			ObjectPath:  file.SourceName,
			Name:        file.Name,
			Size:        file.Size,
			ContentType: metadata.ContentType,
			Hash:        metadata.Hash,
			HashType:    metadata.HashType,
		})
	}

	return items, nil
}

func metadataClientForPolicy(policyID uint) (metadataClient, error) {
	policy, err := model.GetPolicyByID(policyID)
	if err != nil {
		return nil, serializer.NewError(serializer.CodePolicyNotExist, "", err)
	}
	if !isB2MetadataPolicy(&policy) {
		return nil, serializer.NewError(serializer.CodePolicyNotAllowed, "B2 metadata is only supported for Backblaze B2 storage policies", nil)
	}

	client, err := newB2MetadataClient(&policy)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeQueryMetaFailed, "Failed to initialize B2 metadata client", err)
	}
	return client, nil
}

func isB2MetadataPolicy(policy *model.Policy) bool {
	if policy.Type == "b2" {
		return true
	}
	return policy.Type == "s3" && isBackblazeB2Endpoint(policy.Server)
}

func isBackblazeB2Endpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	parsed, err := url.Parse(endpoint)
	host := endpoint
	if err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "backblazeb2.com" || strings.HasSuffix(host, ".backblazeb2.com")
}
