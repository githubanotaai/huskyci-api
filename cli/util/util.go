package util

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"

	"github.com/githubanotaai/huskyci-api/cli/config"
	"github.com/githubanotaai/huskyci-api/cli/errorcli"
)

// GetAllAllowedFilesAndDirsFromPath returns a list of all files and dirs allowed to be zipped
func GetAllAllowedFilesAndDirsFromPath(path string) ([]string, error) {

	var allFilesAndDirNames []string

	filesAndDirs, err := os.ReadDir(path)
	if err != nil {
		return allFilesAndDirNames, err
	}
	for _, file := range filesAndDirs {
		fileName := file.Name()
		if err := checkFileExtension(fileName); err != nil {
			continue
		} else {
			allFilesAndDirNames = append(allFilesAndDirNames, fileName)
		}
	}

	return allFilesAndDirNames, nil
}

// CompressFiles compress all files into a zip and return its full path and an error
func CompressFiles(allFilesAndDirNames []string) (string, error) {

	var fullFilePath string

	fullFilePath, err := config.GetHuskyZipFilePath()
	if err != nil {
		return fullFilePath, err
	}

	zipFile, err := os.Create(fullFilePath)
	if err != nil {
		return fullFilePath, err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer func() {
		if closeErr := zipWriter.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	cwd, err := os.Getwd()
	if err != nil {
		return fullFilePath, err
	}

	for _, name := range allFilesAndDirNames {
		absName, absErr := filepath.Abs(name)
		if absErr != nil {
			return fullFilePath, absErr
		}

		info, statErr := os.Stat(absName)
		if statErr != nil {
			return fullFilePath, statErr
		}

		if info.IsDir() {
			walkErr := filepath.Walk(absName, func(path string, fi os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if fi.IsDir() {
					return nil
				}
				relPath, relErr := filepath.Rel(cwd, path)
				if relErr != nil {
					return relErr
				}
				return addFileToZip(zipWriter, path, relPath)
			})
			if walkErr != nil {
				return fullFilePath, walkErr
			}
		} else {
			relPath, relErr := filepath.Rel(cwd, absName)
			if relErr != nil {
				return fullFilePath, relErr
			}
			if addErr := addFileToZip(zipWriter, absName, relPath); addErr != nil {
				return fullFilePath, addErr
			}
		}
	}

	return fullFilePath, nil
}

// addFileToZip adds a single file to the zip archive.
func addFileToZip(zipWriter *zip.Writer, filePath, zipName string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(zipName)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// GetZipFriendlySize returns the size of a friendly zip file size based on its destination
func GetZipFriendlySize(destination string) (string, error) {

	var friendlySize string

	file, err := os.Open(destination) // #nosec -> this destination is always "$HOME/.huskyci/compressed-code.zip"
	if err != nil {
		return friendlySize, err
	}

	fi, err := file.Stat()
	if err != nil {
		return friendlySize, err
	}

	if err := file.Close(); err != nil {
		return friendlySize, err
	}

	friendlySize = byteCountSI(fi.Size())
	return friendlySize, nil
}

// DeleteHuskyFile will delete the huskyCI file present at "$HOME/.huskyci/compressed-code.zip"
func DeleteHuskyFile(destination string) error {
	return os.Remove(destination)
}

func checkFileExtension(file string) error {
	extensionFound := filepath.Ext(file)
	switch extensionFound {
	case "":
		return nil
	case ".jpg", ".png", ".gif", ".webp", ".tiff", ".psd", ".raw", ".bmp", ".heif", ".indd", ".jpeg", ".svg", ".ai", ".eps", ".pdf":
		return errorcli.ErrInvalidExtension
	case ".webm", ".mpg", ".mp2", ".mpeg", ".mpe", ".mpv", ".ogg", ".mp4", ".m4p", ".m4v", ".avi", ".wmv", ".mov", ".qt", ".flv", ".swf", ".avchd":
		return errorcli.ErrInvalidExtension
	default:
		return nil
	}
}

func byteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// AppendIfMissing will append an item in a slice if it is missing
func AppendIfMissing(slice []string, s string) []string {
	for _, ele := range slice {
		if ele == s {
			return slice
		}
	}
	return append(slice, s)
}
