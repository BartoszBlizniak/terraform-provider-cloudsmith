package cloudsmith

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

type Checksums struct {
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
}

func checksumMismatchError(localChecksum string, remoteChecksum string, checksumType string) string {
	formatString := fmt.Sprintf("Checksum mismatch (%s): expected=%s, got=%s", localChecksum, remoteChecksum, checksumType)
	return formatString
}

func dataSourcePackageRead(d *schema.ResourceData, m interface{}) error {
	pc := m.(*providerConfig)
	namespace := requiredString(d, "namespace")
	repository := requiredString(d, "repository")
	identifier := requiredString(d, "identifier")
	download := requiredBool(d, "download")
	downloadDir := requiredString(d, "download_dir")
	ignoreChecksum := requiredBool(d, "ignore_checksums")

	req := pc.APIClient.PackagesApi.PackagesRead(pc.Auth, namespace, repository, identifier)
	pkg, _, err := pc.APIClient.PackagesApi.PackagesReadExecute(req)
	if err != nil {
		return err
	}

	d.Set("cdn_url", pkg.GetCdnUrl())
	d.Set("format", pkg.GetFormat())
	d.Set("is_sync_awaiting", pkg.GetIsSyncAwaiting())
	d.Set("is_sync_completed", pkg.GetIsSyncCompleted())
	d.Set("is_sync_failed", pkg.GetIsSyncFailed())
	d.Set("is_sync_in_flight", pkg.GetIsSyncInFlight())
	d.Set("is_sync_in_progress", pkg.GetIsSyncInProgress())
	d.Set("name", pkg.GetName())
	d.Set("slug", pkg.GetSlug())
	d.Set("slug_perm", pkg.GetSlugPerm())
	d.Set("version", pkg.GetVersion())
	// Grab the checksum from API in case they don't want to download the file directly via terraform (when returning just the cdn_url)
	d.Set("checksum_md5", pkg.GetChecksumMd5())
	d.Set("checksum_sha1", pkg.GetChecksumSha1())
	d.Set("checksum_sha256", pkg.GetChecksumSha256())
	d.Set("checksum_sha512", pkg.GetChecksumSha512())

	d.SetId(fmt.Sprintf("%s_%s_%s", namespace, repository, pkg.GetSlugPerm()))

	if download {
		outputPath, err := downloadPackage(pkg.GetCdnUrl(), downloadDir, pc, false)
		if err != nil {
			return err
		}
		d.Set("output_path", outputPath)
		d.Set("output_directory", downloadDir)

		// Calculate checksums for the downloaded file
		localChecksums, err := calculateChecksums(outputPath)
		if err != nil {
			return err
		}

		localMD5 := localChecksums.MD5
		localSHA1 := localChecksums.SHA1
		localSHA256 := localChecksums.SHA256
		localSHA512 := localChecksums.SHA512

		// Check against API checksums
		if localMD5 != pkg.GetChecksumMd5() || localSHA1 != pkg.GetChecksumSha1() || localSHA256 != pkg.GetChecksumSha256() || localSHA512 != pkg.GetChecksumSha512() {
			// Checksum doesn't match, try to download again with bustCache set to true
			outputPath, err := downloadPackage(pkg.GetCdnUrl(), downloadDir, pc, true)
			if err != nil {
				return err
			}
			fmt.Println("Package pulled again with bustCache due to checksum mismatch.")

			// Calculate checksums for the downloaded file again
			localChecksums, err := calculateChecksums(outputPath)
			if err != nil {
				return err
			}

			localMD5 = localChecksums.MD5
			localSHA1 = localChecksums.SHA1
			localSHA256 = localChecksums.SHA256
			localSHA512 = localChecksums.SHA512

			// Check again after the retry
			if localMD5 != pkg.GetChecksumMd5() || localSHA1 != pkg.GetChecksumSha1() || localSHA256 != pkg.GetChecksumSha256() || localSHA512 != pkg.GetChecksumSha512() {
				if ignoreChecksum {
					fmt.Println("Warning: ignore_checksums set to true, downloading mismatched checksum file.")
					d.Set("checksum_md5", localMD5)
					d.Set("checksum_sha1", localSHA1)
					d.Set("checksum_sha256", localSHA256)
					d.Set("checksum_sha512", localSHA512)
				} else {
					if localMD5 != pkg.GetChecksumMd5() || localSHA1 != pkg.GetChecksumSha1() || localSHA256 != pkg.GetChecksumSha256() || localSHA512 != pkg.GetChecksumSha512() {
						errMsg := ""
						if localMD5 != pkg.GetChecksumMd5() {
							errMsg += checksumMismatchError(localMD5, pkg.GetChecksumMd5(), "MD5") + "\n"
						}
						if localSHA1 != pkg.GetChecksumSha1() {
							errMsg += checksumMismatchError(localSHA1, pkg.GetChecksumSha1(), "SHA1") + "\n"
						}
						if localSHA256 != pkg.GetChecksumSha256() {
							errMsg += checksumMismatchError(localSHA256, pkg.GetChecksumSha256(), "SHA256") + "\n"
						}
						if localSHA512 != pkg.GetChecksumSha512() {
							errMsg += checksumMismatchError(localSHA512, pkg.GetChecksumSha512(), "SHA512") + "\n"
						}
						return errors.New(errMsg)
					}
				}
			}
		}

		d.Set("checksum_md5", localMD5)
		d.Set("checksum_sha1", localSHA1)
		d.Set("checksum_sha256", localSHA256)
		d.Set("checksum_sha512", localSHA512)
	} else {
		d.Set("output_path", pkg.GetCdnUrl())
		d.Set("output_directory", "")
	}

	return nil
}

func downloadPackage(downloadUrl string, downloadDir string, pc *providerConfig, bustCache bool) (string, error) {
	req, err := http.NewRequest(http.MethodGet, downloadUrl, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Token %s", pc.GetAPIKey()))

	client := pc.APIClient.GetConfig().HTTPClient
	if bustCache {
		timestamp := time.Now().Unix()
		parsedURL, err := url.Parse(downloadUrl)
		if err != nil {
			return "", err
		}

		queryValues := parsedURL.Query()
		queryValues.Set("time", strconv.FormatInt(timestamp, 10))
		parsedURL.RawQuery = queryValues.Encode()

		req.URL = parsedURL
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download file: %s, status code: %d", downloadUrl, resp.StatusCode)
	}

	// Extract filename from CDN URL
	filename := path.Base(downloadUrl)
	outputPath := path.Join(downloadDir, filename)

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, resp.Body)
	if err != nil {
		return "", err
	}

	return outputPath, nil
}

func calculateChecksums(filePath string) (Checksums, error) {
	var checksums Checksums

	file, err := os.Open(filePath)
	if err != nil {
		return checksums, err
	}
	defer file.Close()

	md5hash := md5.New()
	sha1hash := sha1.New()
	sha256hash := sha256.New()
	sha512hash := sha512.New()

	if _, err := io.Copy(io.MultiWriter(md5hash, sha1hash, sha256hash, sha512hash), file); err != nil {
		return checksums, err
	}

	checksums.MD5 = hex.EncodeToString(md5hash.Sum(nil))
	checksums.SHA1 = hex.EncodeToString(sha1hash.Sum(nil))
	checksums.SHA256 = hex.EncodeToString(sha256hash.Sum(nil))
	checksums.SHA512 = hex.EncodeToString(sha512hash.Sum(nil))

	return checksums, nil
}

func dataSourcePackage() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePackageRead,

		Schema: map[string]*schema.Schema{
			"cdn_url": {
				Type:        schema.TypeString,
				Description: "The URL of the package to download.",
				Computed:    true,
			},
			"checksum_md5": {
				Type:        schema.TypeString,
				Description: "MD5 hash of the package",
				Computed:    true,
			},
			"checksum_sha1": {
				Type:        schema.TypeString,
				Description: "SHA1 hash of the package",
				Computed:    true,
			},
			"checksum_sha256": {
				Type:        schema.TypeString,
				Description: "SHA256 hash of the package",
				Computed:    true,
			},
			"checksum_sha512": {
				Type:        schema.TypeString,
				Description: "SHA512 hash of the package",
				Computed:    true,
			},
			"download": {
				Type:        schema.TypeBool,
				Description: "If set to true, download the package",
				Optional:    true,
				Default:     false,
			},
			"download_dir": {
				Type:        schema.TypeString,
				Description: "The directory where the file will be downloaded if download is set to true",
				Optional:    true,
				Default:     os.TempDir(),
			},
			"format": {
				Type:        schema.TypeString,
				Description: "The format of the package",
				Computed:    true,
			},
			"ignore_checksums": {
				Type:        schema.TypeBool,
				Description: "Ignore checksums for the package",
				Optional:    true,
				Default:     false,
			},
			"identifier": {
				Type:         schema.TypeString,
				Description:  "The identifier for this repository.",
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"is_sync_awaiting": {
				Type:        schema.TypeBool,
				Description: "Is the package awaiting synchronization",
				Computed:    true,
			},
			"is_sync_completed": {
				Type:        schema.TypeBool,
				Description: "Has the package synchronization completed",
				Computed:    true,
			},
			"is_sync_failed": {
				Type:        schema.TypeBool,
				Description: "Has the package synchronization failed",
				Computed:    true,
			},
			"is_sync_in_flight": {
				Type:        schema.TypeBool,
				Description: "Is the package synchronization currently in-flight",
				Computed:    true,
			},
			"is_sync_in_progress": {
				Type:        schema.TypeBool,
				Description: "Is the package synchronization currently in-progress",
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "A descriptive name for the package.",
				Computed:    true,
			},
			"namespace": {
				Type:         schema.TypeString,
				Description:  "The namespace of the package",
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"output_directory": {
				Type:        schema.TypeString,
				Description: "The directory where the file is downloaded",
				Computed:    true,
			},
			"output_path": {
				Type:        schema.TypeString,
				Description: "The location of the package",
				Computed:    true,
			},
			"repository": {
				Type:         schema.TypeString,
				Description:  "The repository of the package",
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"slug": {
				Type:        schema.TypeString,
				Description: "The slug identifies the package in URIs.",
				Computed:    true,
			},
			"slug_perm": {
				Type: schema.TypeString,
				Description: "The slug_perm immutably identifies the package. " +
					"It will never change once a package has been created.",
				Computed: true,
			},
			"version": {
				Type:        schema.TypeString,
				Description: "The version of the package",
				Computed:    true,
			},
		},
	}
}
