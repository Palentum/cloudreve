package b2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	model "github.com/cloudreve/Cloudreve/v3/models"
)

const (
	apiVersion          = "v4"
	defaultAuthorizeURL = "https://api.backblazeb2.com/b2api/" + apiVersion + "/b2_authorize_account"

	// HashTypeMD5 identifies a Backblaze B2 contentMd5 hash.
	HashTypeMD5 = "MD5"
	// HashTypeSHA1 identifies a Backblaze B2 contentSha1 hash.
	HashTypeSHA1 = "SHA1"
)

// Metadata is the subset of Backblaze B2 file metadata exposed by share APIs.
type Metadata struct {
	ContentType string
	Hash        *string
	HashType    *string
}

// Client queries Backblaze B2 Native API file metadata for one storage policy.
type Client struct {
	policy       *model.Policy
	httpClient   *http.Client
	authorizeURL string
	authMu       sync.Mutex
	auth         *authorization
}

// NewMetadataClient creates a Backblaze B2 metadata client for policy.
func NewMetadataClient(policy *model.Policy) (*Client, error) {
	return NewMetadataClientWithOptions(policy, nil, "")
}

// NewMetadataClientWithOptions creates a Backblaze B2 metadata client with testable HTTP options.
func NewMetadataClientWithOptions(policy *model.Policy, httpClient *http.Client, authorizeURL string) (*Client, error) {
	if policy == nil {
		return nil, errors.New("b2 metadata: empty policy")
	}
	if policy.AccessKey == "" || policy.SecretKey == "" {
		return nil, errors.New("b2 metadata: access key and secret key are required")
	}
	if policy.BucketName == "" {
		return nil, errors.New("b2 metadata: bucket name is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if authorizeURL == "" {
		authorizeURL = defaultAuthorizeURL
	}

	return &Client{
		policy:       policy,
		httpClient:   httpClient,
		authorizeURL: authorizeURL,
	}, nil
}

// GetMetadata returns B2 Native API metadata for objectPath.
func (c *Client) GetMetadata(ctx context.Context, objectPath string) (*Metadata, error) {
	if objectPath == "" {
		return nil, errors.New("b2 metadata: object path is required")
	}

	auth, err := c.getAuthorization(ctx)
	if err != nil {
		return nil, err
	}

	listed, err := c.listFileName(ctx, auth, auth.bucketID, objectPath)
	if err != nil {
		return nil, err
	}

	if listed.ContentType == "" {
		info, err := c.getFileInfo(ctx, auth, listed.FileID)
		if err != nil {
			return nil, err
		}
		fillMissingFileInfo(info, listed)
		return buildMetadata(info), nil
	}

	return buildMetadata(listed), nil
}

type authorization struct {
	accountID string
	token     string
	apiURL    string
	bucketID  string
}

type authorizeResponse struct {
	AccountID          string      `json:"accountId"`
	AuthorizationToken string      `json:"authorizationToken"`
	APIURL             string      `json:"apiUrl"`
	Allowed            allowedInfo `json:"allowed"`
	APIInfo            apiInfo     `json:"apiInfo"`
}

type apiInfo struct {
	StorageAPI storageAPIInfo `json:"storageApi"`
}

type storageAPIInfo struct {
	APIURL     string      `json:"apiUrl"`
	BucketID   string      `json:"bucketId"`
	BucketName string      `json:"bucketName"`
	Allowed    allowedInfo `json:"allowed"`
}

type allowedInfo struct {
	BucketID   string        `json:"bucketId"`
	BucketName string        `json:"bucketName"`
	Buckets    []bucketEntry `json:"buckets"`
}

type bucketEntry struct {
	BucketID   string `json:"bucketId"`
	BucketName string `json:"bucketName"`
	ID         string `json:"id"`
	Name       string `json:"name"`
}

func (c *Client) getAuthorization(ctx context.Context) (*authorization, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	if c.auth != nil {
		return c.auth, nil
	}

	auth, err := c.authorize(ctx)
	if err != nil {
		return nil, err
	}
	auth.bucketID, err = c.resolveBucketID(ctx, auth)
	if err != nil {
		return nil, err
	}
	c.auth = auth
	return c.auth, nil
}

func (c *Client) authorize(ctx context.Context) (*authorization, error) {
	var out authorizeResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authorizeURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.policy.AccessKey, c.policy.SecretKey)

	if err := c.do(req, &out); err != nil {
		return nil, fmt.Errorf("b2 authorize account failed: %w", err)
	}
	if out.AuthorizationToken == "" {
		return nil, errors.New("b2 authorize account failed: empty authorization token")
	}

	apiURL := out.APIInfo.StorageAPI.APIURL
	if apiURL == "" {
		apiURL = out.APIURL
	}
	if apiURL == "" {
		return nil, errors.New("b2 authorize account failed: empty API URL")
	}

	return &authorization{
		accountID: out.AccountID,
		token:     out.AuthorizationToken,
		apiURL:    apiURL,
		bucketID:  out.bucketID(c.policy.BucketName),
	}, nil
}

func (r *authorizeResponse) bucketID(bucketName string) string {
	storageAPI := r.APIInfo.StorageAPI
	if storageAPI.BucketID != "" && (storageAPI.BucketName == "" || storageAPI.BucketName == bucketName) {
		return storageAPI.BucketID
	}
	if bucketID := storageAPI.Allowed.bucketID(bucketName); bucketID != "" {
		return bucketID
	}
	if r.Allowed.BucketID != "" && (r.Allowed.BucketName == "" || r.Allowed.BucketName == bucketName) {
		return r.Allowed.BucketID
	}
	return r.Allowed.bucketID(bucketName)
}

func (info *allowedInfo) bucketID(bucketName string) string {
	for _, bucket := range info.Buckets {
		if bucket.name() == bucketName && bucket.id() != "" {
			return bucket.id()
		}
	}
	return ""
}

func (bucket bucketEntry) id() string {
	if bucket.BucketID != "" {
		return bucket.BucketID
	}
	return bucket.ID
}

func (bucket bucketEntry) name() string {
	if bucket.BucketName != "" {
		return bucket.BucketName
	}
	return bucket.Name
}

func (c *Client) resolveBucketID(ctx context.Context, auth *authorization) (string, error) {
	if auth.bucketID != "" {
		return auth.bucketID, nil
	}
	if auth.accountID == "" {
		return "", errors.New("b2 metadata: unable to resolve bucket id: empty account id")
	}

	var out listBucketsResponse
	err := c.postJSON(ctx, auth, "b2_list_buckets", listBucketsRequest{
		AccountID: auth.accountID,
	}, &out)
	if err != nil {
		return "", fmt.Errorf("b2 metadata: unable to resolve bucket id for %q: %w", c.policy.BucketName, err)
	}
	for _, bucket := range out.Buckets {
		if bucket.name() == c.policy.BucketName && bucket.id() != "" {
			return bucket.id(), nil
		}
	}
	return "", fmt.Errorf("b2 metadata: unable to resolve bucket id for %q", c.policy.BucketName)
}

type listBucketsRequest struct {
	AccountID string `json:"accountId"`
}

type listBucketsResponse struct {
	Buckets []bucketEntry `json:"buckets"`
}

func (c *Client) listFileName(ctx context.Context, auth *authorization, bucketID, objectPath string) (*fileInfo, error) {
	var out listFileNamesResponse
	err := c.postJSON(ctx, auth, "b2_list_file_names", listFileNamesRequest{
		BucketID:     bucketID,
		Prefix:       objectPath,
		MaxFileCount: 1,
	}, &out)
	if err != nil {
		return nil, fmt.Errorf("b2 list file names failed for %q: %w", objectPath, err)
	}
	if len(out.Files) == 0 || out.Files[0].FileName != objectPath {
		return nil, fmt.Errorf("b2 metadata: object %q not found", objectPath)
	}
	if out.Files[0].FileID == "" {
		return nil, fmt.Errorf("b2 metadata: object %q has empty file id", objectPath)
	}
	return &out.Files[0], nil
}

type listFileNamesRequest struct {
	BucketID     string `json:"bucketId"`
	Prefix       string `json:"prefix"`
	MaxFileCount int    `json:"maxFileCount"`
}

type listFileNamesResponse struct {
	Files []fileInfo `json:"files"`
}

func (c *Client) getFileInfo(ctx context.Context, auth *authorization, fileID string) (*fileInfo, error) {
	var out fileInfo
	err := c.postJSON(ctx, auth, "b2_get_file_info", getFileInfoRequest{FileID: fileID}, &out)
	if err != nil {
		return nil, fmt.Errorf("b2 get file info failed for %q: %w", fileID, err)
	}
	return &out, nil
}

type getFileInfoRequest struct {
	FileID string `json:"fileId"`
}

type fileInfo struct {
	FileID      string  `json:"fileId"`
	FileName    string  `json:"fileName"`
	ContentType string  `json:"contentType"`
	ContentMD5  *string `json:"contentMd5"`
	ContentSHA1 *string `json:"contentSha1"`
}

func fillMissingFileInfo(dst, src *fileInfo) {
	if dst.ContentType == "" {
		dst.ContentType = src.ContentType
	}
	if dst.ContentMD5 == nil {
		dst.ContentMD5 = src.ContentMD5
	}
	if dst.ContentSHA1 == nil {
		dst.ContentSHA1 = src.ContentSHA1
	}
}

func buildMetadata(info *fileInfo) *Metadata {
	hash, hashType := selectHash(info.ContentMD5, info.ContentSHA1)
	return &Metadata{
		ContentType: info.ContentType,
		Hash:        hash,
		HashType:    hashType,
	}
}

func selectHash(contentMD5, contentSHA1 *string) (*string, *string) {
	if hash := normalizeHash(contentMD5); hash != "" {
		hashType := HashTypeMD5
		return &hash, &hashType
	}
	if hash := normalizeHash(contentSHA1); hash != "" {
		hashType := HashTypeSHA1
		return &hash, &hashType
	}
	return nil, nil
}

func normalizeHash(value *string) string {
	if value == nil {
		return ""
	}
	hash := strings.TrimSpace(*value)
	if hash == "" || strings.EqualFold(hash, "none") {
		return ""
	}
	return hash
}

func (c *Client) postJSON(ctx context.Context, auth *authorization, apiName string, body interface{}, out interface{}) error {
	rawBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiEndpoint(auth.apiURL, apiName), bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth.token)
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return decodeB2Error(resp)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type b2ErrorResponse struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func decodeB2Error(resp *http.Response) error {
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	var b2Err b2ErrorResponse
	if err := json.Unmarshal(body, &b2Err); err == nil && b2Err.Message != "" {
		if b2Err.Code != "" {
			return fmt.Errorf("%s: %s", b2Err.Code, b2Err.Message)
		}
		return errors.New(b2Err.Message)
	}
	if len(body) > 0 {
		return fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, string(body))
	}
	return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
}

func apiEndpoint(apiURL, apiName string) string {
	return strings.TrimRight(apiURL, "/") + "/b2api/" + apiVersion + "/" + apiName
}
