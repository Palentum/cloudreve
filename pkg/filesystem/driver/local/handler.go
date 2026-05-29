package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/auth"
	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/filesystem/driver"
	"github.com/cloudreve/Cloudreve/v3/pkg/filesystem/fsctx"
	"github.com/cloudreve/Cloudreve/v3/pkg/filesystem/response"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
)

const (
	Perm = 0744
)

// Driver 本地策略适配器
type Driver struct {
	Policy *model.Policy
}

// validatePath 校验路径是否在存储根目录内，防止路径穿越，返回解析后的绝对路径。
// 本地策略的 DirNameRule 可以包含前导 "/"（如 "/{uid}/{path}"），
// 由 GeneratePath 产生的 SavePath 会以 "/" 开头。此类路径需去掉前导
// "/" 后作为相对于可执行文件目录的路径处理。
func (handler Driver) validatePath(p string) (string, error) {
	cleaned := filepath.Clean(filepath.FromSlash(p))
	root := handler.root()

	if filepath.IsAbs(cleaned) {
		// 去掉前导 "/"，使其作为相对于 root 的路径处理。
		// GeneratePath 的 DirNameRule 可能产生 "/1/filename" 这样的路径，
		// util.RelativePath 会将其视为绝对路径直接返回，导致不在 root 下。
		cleaned = cleaned[1:]
	}

	// 检查路径是否包含 ".." 穿越组件
	for _, part := range strings.Split(cleaned, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("path %q contains path traversal", p)
		}
	}

	resolved := filepath.Join(root, cleaned)
	if !util.IsPathUnderRoot(resolved, root) {
		return "", fmt.Errorf("path %q is outside storage root", p)
	}
	return resolved, nil
}

// root 返回本地存储的根目录（可执行文件所在目录）
func (handler Driver) root() string {
	e, _ := os.Executable()
	return filepath.Dir(e)
}

// List 递归列取给定物理路径下所有文件
func (handler Driver) List(ctx context.Context, path string, recursive bool) ([]response.Object, error) {
	var res []response.Object

	root, err := handler.validatePath(path)
	if err != nil {
		return nil, err
	}

	// 开始遍历路径下的文件、目录
	err = filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			// 跳过根目录
			if path == root {
				return nil
			}

			if err != nil {
				util.Log().Warning("Failed to walk folder %q: %s", path, err)
				return filepath.SkipDir
			}

			// 将遍历对象的绝对路径转换为相对路径
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}

			res = append(res, response.Object{
				Name:         info.Name(),
				RelativePath: filepath.ToSlash(rel),
				Source:       path,
				Size:         uint64(info.Size()),
				IsDir:        info.IsDir(),
				LastModify:   info.ModTime(),
			})

			// 如果非递归，则不步入目录
			if !recursive && info.IsDir() {
				return filepath.SkipDir
			}

			return nil
		})

	return res, err
}

// Get 获取文件内容
func (handler Driver) Get(ctx context.Context, path string) (response.RSCloser, error) {
	resolved, err := handler.validatePath(path)
	if err != nil {
		return nil, err
	}

	// 打开文件
	file, err := os.Open(resolved)
	if err != nil {
		util.Log().Debug("Failed to open file: %s", err)
		return nil, err
	}

	return file, nil
}

// Put 将文件流保存到指定目录
func (handler Driver) Put(ctx context.Context, file fsctx.FileHeader) error {
	defer file.Close()
	fileInfo := file.Info()

	dst, err := handler.validatePath(fileInfo.SavePath)
	if err != nil {
		return err
	}

	// 如果非 Overwrite，则检查是否有重名冲突
	if fileInfo.Mode&fsctx.Overwrite != fsctx.Overwrite {
		if util.Exists(dst) {
			util.Log().Warning("File with the same name existed or unavailable: %s", dst)
			return errors.New("file with the same name existed or unavailable")
		}
	}

	// 如果目标目录不存在，创建
	basePath := filepath.Dir(dst)
	if !util.Exists(basePath) {
		mkdirErr := os.MkdirAll(basePath, Perm)
		if mkdirErr != nil {
			util.Log().Warning("Failed to create directory: %s", mkdirErr)
			return mkdirErr
		}
	}

	var out *os.File

 	openMode := os.O_CREATE | os.O_RDWR
 	if fileInfo.Mode&fsctx.Append == fsctx.Append {
 		openMode |= os.O_APPEND
 	} else {
 		openMode |= os.O_TRUNC
		// 非 Overwrite 模式使用 O_EXCL 避免 TOCTOU 竞态
		if fileInfo.Mode&fsctx.Overwrite != fsctx.Overwrite {
			openMode |= os.O_EXCL
		}
 	}

	out, err = os.OpenFile(dst, openMode, Perm)
	if err != nil {
		util.Log().Warning("Failed to open or create file: %s", err)
		return err
	}
	defer out.Close()

	if fileInfo.Mode&fsctx.Append == fsctx.Append {
		stat, err := out.Stat()
		if err != nil {
			util.Log().Warning("Failed to read file info: %s", err)
			return err
		}

		if uint64(stat.Size()) < fileInfo.AppendStart {
			return errors.New("size of unfinished uploaded chunks is not as expected")
		} else if uint64(stat.Size()) > fileInfo.AppendStart {
			out.Close()
			if err := handler.Truncate(ctx, fileInfo.SavePath, fileInfo.AppendStart); err != nil {
				return fmt.Errorf("failed to overwrite chunk: %w", err)
			}

			out, err = os.OpenFile(dst, openMode, Perm)
			defer out.Close()
			if err != nil {
				util.Log().Warning("Failed to create or open file: %s", err)
				return err
			}
		}
	}

	// 写入文件内容
	_, err = io.Copy(out, file)
	return err
}

// Truncate 截断文件。src 为原始路径（与 validatePath 输入一致），非解析后路径。
func (handler Driver) Truncate(ctx context.Context, src string, size uint64) error {
	resolved, err := handler.validatePath(src)
	if err != nil {
		return err
	}

	util.Log().Warning("Truncate file %q to [%d].", src, size)
	out, err := os.OpenFile(resolved, os.O_WRONLY, Perm)
	if err != nil {
		util.Log().Warning("Failed to open file: %s", err)
		return err
	}

	defer out.Close()
	return out.Truncate(int64(size))
}

// Delete 删除一个或多个文件，
// 返回未删除的文件，及遇到的最后一个错误
func (handler Driver) Delete(ctx context.Context, files []string) ([]string, error) {
	deleteFailed := make([]string, 0, len(files))
	var retErr error

	for _, value := range files {
		filePath, err := handler.validatePath(value)
		if err != nil {
			deleteFailed = append(deleteFailed, value)
			retErr = err
			continue
		}

		if util.Exists(filePath) {
			err := os.Remove(filePath)
			if err != nil {
				util.Log().Warning("Failed to delete file: %s", err)
				retErr = err
				deleteFailed = append(deleteFailed, value)
			}
		}

		// 尝试删除文件的缩略图（如果有）
		thumbPath := filePath + model.GetSettingByNameWithDefault("thumb_file_suffix", "._thumb")
		_ = os.Remove(thumbPath)
	}

	return deleteFailed, retErr
}

// Thumb 获取文件缩略图
func (handler Driver) Thumb(ctx context.Context, file *model.File) (*response.ContentResponse, error) {
	// Quick check thumb existence on master.
	if conf.SystemConfig.Mode == "master" && file.MetadataSerialized[model.ThumbStatusMetadataKey] == model.ThumbStatusNotExist {
		// Tell invoker to generate a thumb
		return nil, driver.ErrorThumbNotExist
	}

	thumbFile, err := handler.Get(ctx, file.ThumbFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("thumb not exist: %w (%w)", err, driver.ErrorThumbNotExist)
		}

		return nil, err
	}

	return &response.ContentResponse{
		Redirect: false,
		Content:  thumbFile,
	}, nil
}

// Source 获取外链URL
func (handler Driver) Source(ctx context.Context, path string, ttl int64, isDownload bool, speed int) (string, error) {
	file, ok := ctx.Value(fsctx.FileModelCtx).(model.File)
	if !ok {
		return "", errors.New("failed to read file model context")
	}

	var baseURL *url.URL
	// 是否启用了CDN
	if handler.Policy.BaseURL != "" {
		cdnURL, err := url.Parse(handler.Policy.BaseURL)
		if err != nil {
			return "", err
		}
		baseURL = cdnURL
	}

	var (
		signedURI *url.URL
		err       error
	)
	if isDownload {
		// 创建下载会话，将文件信息写入缓存
		downloadSessionID := util.RandStringRunes(16)
		err = cache.Set("download_"+downloadSessionID, file, int(ttl))
		if err != nil {
			return "", serializer.NewError(serializer.CodeCacheOperation, "Failed to create download session", err)
		}

		// 签名生成文件记录
		signedURI, err = auth.SignURI(
			auth.General,
			fmt.Sprintf("/api/v3/file/download/%s", downloadSessionID),
			ttl,
		)
	} else {
		// 签名生成文件记录
		signedURI, err = auth.SignURI(
			auth.General,
			fmt.Sprintf("/api/v3/file/get/%d/%s", file.ID, file.Name),
			ttl,
		)
	}

	if err != nil {
		return "", serializer.NewError(serializer.CodeEncryptError, "Failed to sign url", err)
	}

	finalURL := signedURI.String()
	if baseURL != nil {
		finalURL = baseURL.ResolveReference(signedURI).String()
	}

	return finalURL, nil
}

// Token 获取上传策略和认证Token，本地策略直接返回空值
func (handler Driver) Token(ctx context.Context, ttl int64, uploadSession *serializer.UploadSession, file fsctx.FileHeader) (*serializer.UploadCredential, error) {
	resolved, err := handler.validatePath(uploadSession.SavePath)
	if err != nil {
		return nil, err
	}

	if util.Exists(resolved) {
		return nil, errors.New("placeholder file already exist")
	}

	return &serializer.UploadCredential{
		SessionID: uploadSession.Key,
		ChunkSize: handler.Policy.OptionsSerialized.ChunkSize,
	}, nil
}

// 取消上传凭证
func (handler Driver) CancelToken(ctx context.Context, uploadSession *serializer.UploadSession) error {
	return nil
}
