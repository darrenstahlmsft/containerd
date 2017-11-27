package windowsdiffer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/archive/tar"
	"github.com/Microsoft/go-winio/backuptar"
	"github.com/Microsoft/hcsshim"
	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/plugin"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.DiffPlugin,
		ID:   "windows",
		Requires: []plugin.Type{
			plugin.ContentPlugin,
			plugin.MetadataPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			md, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}
			return NewWindowsDiff(md.(*metadata.DB).ContentStore())
		},
	})
}

var (
	emptyDesc = ocispec.Descriptor{}
)

type windowsDiff struct {
	store content.Store
}

// NewWindowsDiff is the Windows container implementation of diff.Differ.
func NewWindowsDiff(store content.Store) (diff.Differ, error) {
	return &windowsDiff{
		store: store,
	}, nil
}

// Apply applies the content associated with the provided digests onto the
// provided mounts. Archive content will be extracted and decompressed if
// necessary.
func (s *windowsDiff) Apply(ctx context.Context, desc ocispec.Descriptor, mounts []mount.Mount) (ocispec.Descriptor, error) {
	var isCompressed bool
	switch desc.MediaType {
	case ocispec.MediaTypeImageLayer, images.MediaTypeDockerSchema2Layer:
	case ocispec.MediaTypeImageLayerGzip, images.MediaTypeDockerSchema2LayerGzip:
		isCompressed = true
	default:
		// Still apply all generic media types *.tar[.+]gzip and *.tar
		if strings.HasSuffix(desc.MediaType, ".tar.gzip") || strings.HasSuffix(desc.MediaType, ".tar+gzip") {
			isCompressed = true
		} else if !strings.HasSuffix(desc.MediaType, ".tar") {
			return emptyDesc, errors.Wrapf(errdefs.ErrNotImplemented, "unsupported diff media type: %v", desc.MediaType)
		}
	}

	ra, err := s.store.ReaderAt(ctx, desc.Digest)
	if err != nil {
		return emptyDesc, errors.Wrap(err, "failed to get reader from content store")
	}
	defer ra.Close()

	r := content.NewReader(ra)
	if isCompressed {
		ds, err := compression.DecompressStream(r)
		if err != nil {
			return emptyDesc, err
		}
		defer ds.Close()
		r = ds
	}

	digester := digest.Canonical.Digester()
	rc := &readCounter{
		r: io.TeeReader(r, digester.Hash()),
	}

	layer, parentLayerPaths, err := mountsToLayerAndParents(mounts)
	if err != nil {
		return emptyDesc, err
	}

	layerWriter, err := archive.NewWindowsLayerWriter(filepath.Dir(layer), filepath.Base(layer), false, parentLayerPaths...)
	if err != nil {
		return emptyDesc, err
	}
	defer layerWriter.Close()

	if _, err := archive.Apply(ctx, layerWriter, rc); err != nil {
		return emptyDesc, err
	}

	// Read any trailing data
	if _, err := io.Copy(ioutil.Discard, rc); err != nil {
		return emptyDesc, err
	}

	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer,
		Size:      rc.c,
		Digest:    digester.Digest(),
	}, nil
}

// DiffMounts creates a diff between the given mounts and uploads the result
// to the content store.
func (s *windowsDiff) DiffMounts(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (ocispec.Descriptor, error) {
	var config diff.Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return emptyDesc, err
		}
	}

	if config.MediaType == "" {
		config.MediaType = ocispec.MediaTypeImageLayerGzip
	}

	var isCompressed bool
	switch config.MediaType {
	case ocispec.MediaTypeImageLayer:
	case ocispec.MediaTypeImageLayerGzip:
		isCompressed = true
	default:
		return emptyDesc, errors.Wrapf(errdefs.ErrNotImplemented, "unsupported diff media type: %v", config.MediaType)
	}

	var newReference bool
	if config.Reference == "" {
		newReference = true
		config.Reference = uniqueRef()
	}

	cw, err := s.store.Writer(ctx, config.Reference, 0, "")
	if err != nil {
		return emptyDesc, errors.Wrap(err, "failed to open writer")
	}
	defer func() {
		if err != nil {
			cw.Close()
			if newReference {
				if err := s.store.Abort(ctx, config.Reference); err != nil {
					log.G(ctx).WithField("ref", config.Reference).Warnf("failed to delete diff upload")
				}
			}
		}
	}()
	if !newReference {
		if err := cw.Truncate(0); err != nil {
			return emptyDesc, err
		}
	}

	layer, parentLayerPaths, err := mountsToLayerAndParents(upper)
	if err != nil {
		return emptyDesc, errors.Wrap(err, "failed to get layer and parent paths from mounts")
	}
	if lower[0].Source != parentLayerPaths[0] {
		return emptyDesc, errors.Wrapf(errdefs.ErrInvalidArgument, "lower mounts must be the direct child of the upper mounts %v != %v", lower[0].Source, parentLayerPaths[0])
	}

	if isCompressed {
		dgstr := digest.SHA256.Digester()
		compressed, err := compression.CompressStream(cw, compression.Gzip)
		if err != nil {
			return emptyDesc, errors.Wrap(err, "failed to get compressed stream")
		}
		err = s.writeDiff(ctx, io.MultiWriter(compressed, dgstr.Hash()), layer, parentLayerPaths)
		compressed.Close()
		if err != nil {
			return emptyDesc, errors.Wrap(err, "failed to write compressed diff")
		}

		if config.Labels == nil {
			config.Labels = map[string]string{}
		}
		config.Labels["containerd.io/uncompressed"] = dgstr.Digest().String()
	} else {
		if err = s.writeDiff(ctx, cw, layer, parentLayerPaths); err != nil {
			return emptyDesc, errors.Wrap(err, "failed to write diff")
		}
	}

	var commitopts []content.Opt
	if config.Labels != nil {
		commitopts = append(commitopts, content.WithLabels(config.Labels))
	}

	dgst := cw.Digest()
	if err := cw.Commit(ctx, 0, dgst, commitopts...); err != nil {
		return emptyDesc, errors.Wrap(err, "failed to commit")
	}

	info, err := s.store.Info(ctx, dgst)
	if err != nil {
		return emptyDesc, errors.Wrap(err, "failed to get info from content store")
	}

	return ocispec.Descriptor{
		MediaType: config.MediaType,
		Size:      info.Size,
		Digest:    info.Digest,
	}, nil
}

func mountsToLayerAndParents(mounts []mount.Mount) (string, []string, error) {
	if len(mounts) == 0 {
		return "", nil, errors.Wrap(errdefs.ErrInvalidArgument, "number of mounts should not be 0")
	}
	layer := mounts[0].Source

	var parents []string
	for _, mount := range mounts[1:] {
		parents = append(parents, mount.Source)
	}

	return layer, parents, nil
}

// WriteDiff writes a tar stream of the computed difference between the
// provided directories.
//
// Produces a tar using OCI style file markers for deletions. Deleted
// files will be prepended with the prefix ".wh.". This style is
// based off AUFS whiteouts.
// See https://github.com/opencontainers/image-spec/blob/master/layer.md
func (s *windowsDiff) writeDiff(ctx context.Context, w io.Writer, layer string, parentLayerPaths []string) error {
	info := hcsshim.DriverInfo{
		Flavour: 1,
		HomeDir: filepath.Dir(layer),
	}
	id := filepath.Base(layer)
	err := winio.RunWithPrivilege(winio.SeBackupPrivilege, func() error {
		r, err := hcsshim.NewLayerReader(info, id, parentLayerPaths)
		if err != nil {
			return err
		}

		err = writeTarFromLayer(r, w)
		cerr := r.Close()
		if err == nil {
			err = cerr
		}
		return err
	})
	return err
}

const (
	// whiteoutPrefix prefix means file is a whiteout. If this is followed by a
	// filename this means that file has been removed from the base layer.
	// See https://github.com/opencontainers/image-spec/blob/master/layer.md#whiteouts
	whiteoutPrefix = ".wh."
)

func writeTarFromLayer(r hcsshim.LayerReader, w io.Writer) error {
	t := tar.NewWriter(w)
	for {
		name, size, fileInfo, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if fileInfo == nil {
			// Write a whiteout file.
			hdr := &tar.Header{
				Name: filepath.ToSlash(filepath.Join(filepath.Dir(name), whiteoutPrefix+filepath.Base(name))),
			}
			err := t.WriteHeader(hdr)
			if err != nil {
				return err
			}
		} else {
			err = backuptar.WriteTarFileFromBackupStream(t, r, name, size, fileInfo)
			if err != nil {
				return err
			}
		}
	}
	return t.Close()
}

type readCounter struct {
	r io.Reader
	c int64
}

func (rc *readCounter) Read(p []byte) (n int, err error) {
	n, err = rc.r.Read(p)
	rc.c += int64(n)
	return
}

func uniqueRef() string {
	t := time.Now()
	var b [3]byte
	// Ignore read failures, just decreases uniqueness
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", t.UnixNano(), base64.URLEncoding.EncodeToString(b[:]))
}
