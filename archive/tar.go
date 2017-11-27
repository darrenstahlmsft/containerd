package archive

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/fs"
	"github.com/containerd/containerd/log"
	"github.com/dmcgowan/go-tar"
	"github.com/pkg/errors"
)

var (
	bufferPool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

// TarToLayerWriter defines the interface for layer writers to implement.
//
// Allows for layer writers to have extra context specific to the implementation
// such as on Windows where all parent layers must be known in order to build the
// filesystem to apply the diff to.
type TarToLayerWriter interface {
	// PrepareApply must be called prior to applying the diff. It sets up the
	// system or destination for the layer apply.
	PrepareApply() error

	// PostApply must be called if PrepareLayer succeeded. It must be called
	// prior to Close. If the layer apply failed, err should be the error
	// that caused the layer apply to fail. It does any post processing of the
	// layer such as re-applying directory times to directories which had files
	// modified inside, resetting the last modified time to an incorrect value.
	PostApply(err error) error

	// AddTarFile adds the file referenced by srcHdr to the layer being written.
	// It may require multiple tar entries to get all the data for the written
	// file, so it returns the next tar header to process as well as an error,
	// which will be io.EOF if there are no more headers to process.
	AddTarFile(ctx context.Context, t *tar.Reader, srcHdr *tar.Header) (*tar.Header, error)

	// HandleWhiteoutFile removes the whiteout file referenced by srcHdr from the
	// layer being written.
	HandleWhiteoutFile(srcHdr *tar.Header) error

	// Close closes the writer.
	Close() error
}

// Diff returns a tar stream of the computed filesystem
// difference between the provided directories.
//
// Produces a tar using OCI style file markers for deletions. Deleted
// files will be prepended with the prefix ".wh.". This style is
// based off AUFS whiteouts.
// See https://github.com/opencontainers/image-spec/blob/master/layer.md
func Diff(ctx context.Context, a, b string) io.ReadCloser {
	r, w := io.Pipe()

	go func() {
		err := WriteDiff(ctx, w, a, b)
		if err = w.CloseWithError(err); err != nil {
			log.G(ctx).WithError(err).Debugf("closing tar pipe failed")
		}
	}()

	return r
}

// WriteDiff writes a tar stream of the computed difference between the
// provided directories.
//
// Produces a tar using OCI style file markers for deletions. Deleted
// files will be prepended with the prefix ".wh.". This style is
// based off AUFS whiteouts.
// See https://github.com/opencontainers/image-spec/blob/master/layer.md
func WriteDiff(ctx context.Context, w io.Writer, a, b string) error {
	cw := newChangeWriter(w, b)
	err := fs.Changes(ctx, a, b, cw.HandleChange)
	if err != nil {
		return errors.Wrap(err, "failed to create diff tar stream")
	}
	return cw.Close()
}

const (
	// whiteoutPrefix prefix means file is a whiteout. If this is followed by a
	// filename this means that file has been removed from the base layer.
	// See https://github.com/opencontainers/image-spec/blob/master/layer.md#whiteouts
	whiteoutPrefix = ".wh."

	// whiteoutMetaPrefix prefix means whiteout has a special meaning and is not
	// for removing an actual file. Normally these files are excluded from exported
	// archives.
	whiteoutMetaPrefix = whiteoutPrefix + whiteoutPrefix

	// whiteoutLinkDir is a directory AUFS uses for storing hardlink links to other
	// layers. Normally these should not go into exported archives and all changed
	// hardlinks should be copied to the top layer.
	whiteoutLinkDir = whiteoutMetaPrefix + "plnk"

	// whiteoutOpaqueDir file means directory has been made opaque - meaning
	// readdir calls to this directory do not follow to lower layers.
	whiteoutOpaqueDir = whiteoutMetaPrefix + ".opq"
)

// Apply applies a tar stream of an OCI style diff tar.
// See https://github.com/opencontainers/image-spec/blob/master/layer.md#applying-changesets
func Apply(ctx context.Context, w TarToLayerWriter, r io.Reader) (size int64, err error) {
	tr := tar.NewReader(r)

	if err := w.PrepareApply(); err != nil {
		return 0, err
	}
	defer w.PostApply(err)

	// Iterate through the files in the archive.
	hdr, nextErr := tr.Next()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		if nextErr == io.EOF {
			// end of tar archive
			break
		}
		if nextErr != nil {
			return 0, nextErr
		}

		size += hdr.Size

		if skipFile(hdr) {
			log.G(ctx).Warnf("file %q ignored: archive may not be supported on system", hdr.Name)
			hdr, nextErr = tr.Next()
			continue
		}

		base := filepath.Base(hdr.Name)
		if strings.HasPrefix(base, whiteoutPrefix) {
			if err := w.HandleWhiteoutFile(hdr); err != nil {
				return 0, err
			}

			hdr, nextErr = tr.Next()
			continue
		}

		hdr, nextErr = w.AddTarFile(ctx, tr, hdr)
	}

	return size, nil
}

type changeWriter struct {
	tw        *tar.Writer
	source    string
	whiteoutT time.Time
	inodeSrc  map[uint64]string
	inodeRefs map[uint64][]string
}

func newChangeWriter(w io.Writer, source string) *changeWriter {
	return &changeWriter{
		tw:        tar.NewWriter(w),
		source:    source,
		whiteoutT: time.Now(),
		inodeSrc:  map[uint64]string{},
		inodeRefs: map[uint64][]string{},
	}
}

func (cw *changeWriter) HandleChange(k fs.ChangeKind, p string, f os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if k == fs.ChangeKindDelete {
		whiteOutDir := filepath.Dir(p)
		whiteOutBase := filepath.Base(p)
		whiteOut := filepath.Join(whiteOutDir, whiteoutPrefix+whiteOutBase)
		hdr := &tar.Header{
			Name:       whiteOut[1:],
			Size:       0,
			ModTime:    cw.whiteoutT,
			AccessTime: cw.whiteoutT,
			ChangeTime: cw.whiteoutT,
		}
		if err := cw.tw.WriteHeader(hdr); err != nil {
			return errors.Wrap(err, "failed to write whiteout header")
		}
	} else {
		var (
			link   string
			err    error
			source = filepath.Join(cw.source, p)
		)

		if f.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(source); err != nil {
				return err
			}
		}

		hdr, err := tar.FileInfoHeader(f, link)
		if err != nil {
			return err
		}

		hdr.Mode = int64(chmodTarEntry(os.FileMode(hdr.Mode)))

		name := p
		if strings.HasPrefix(name, string(filepath.Separator)) {
			name, err = filepath.Rel(string(filepath.Separator), name)
			if err != nil {
				return errors.Wrap(err, "failed to make path relative")
			}
		}
		name, err = tarName(name)
		if err != nil {
			return errors.Wrap(err, "cannot canonicalize path")
		}
		// suffix with '/' for directories
		if f.IsDir() && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		hdr.Name = name

		if err := setHeaderForSpecialDevice(hdr, name, f); err != nil {
			return errors.Wrap(err, "failed to set device headers")
		}

		// additionalLinks stores file names which must be linked to
		// this file when this file is added
		var additionalLinks []string
		inode, isHardlink := fs.GetLinkInfo(f)
		if isHardlink {
			// If the inode has a source, always link to it
			if source, ok := cw.inodeSrc[inode]; ok {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = source
				hdr.Size = 0
			} else {
				if k == fs.ChangeKindUnmodified {
					cw.inodeRefs[inode] = append(cw.inodeRefs[inode], name)
					return nil
				}
				cw.inodeSrc[inode] = name
				additionalLinks = cw.inodeRefs[inode]
				delete(cw.inodeRefs, inode)
			}
		} else if k == fs.ChangeKindUnmodified {
			// Nothing to write to diff
			return nil
		}

		if capability, err := getxattr(source, "security.capability"); err != nil {
			return errors.Wrap(err, "failed to get capabilities xattr")
		} else if capability != nil {
			hdr.Xattrs = map[string]string{
				"security.capability": string(capability),
			}
		}

		if err := cw.tw.WriteHeader(hdr); err != nil {
			return errors.Wrap(err, "failed to write file header")
		}

		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			file, err := open(source)
			if err != nil {
				return errors.Wrapf(err, "failed to open path: %v", source)
			}
			defer file.Close()

			buf := bufferPool.Get().([]byte)
			n, err := io.CopyBuffer(cw.tw, file, buf)
			bufferPool.Put(buf)
			if err != nil {
				return errors.Wrap(err, "failed to copy")
			}
			if n != hdr.Size {
				return errors.New("short write copying file")
			}
		}

		if additionalLinks != nil {
			source = hdr.Name
			for _, extra := range additionalLinks {
				hdr.Name = extra
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = source
				hdr.Size = 0
				if err := cw.tw.WriteHeader(hdr); err != nil {
					return errors.Wrap(err, "failed to write file header")
				}
			}
		}
	}
	return nil
}

func (cw *changeWriter) Close() error {
	if err := cw.tw.Close(); err != nil {
		return errors.Wrap(err, "failed to close tar writer")
	}
	return nil
}

func createTarFile(ctx context.Context, path, extractDir string, hdr *tar.Header, reader io.Reader) error {
	// hdr.Mode is in linux format, which we can use for syscalls,
	// but for os.Foo() calls we need the mode converted to os.FileMode,
	// so use hdrInfo.Mode() (they differ for e.g. setuid bits)
	hdrInfo := hdr.FileInfo()

	switch hdr.Typeflag {
	case tar.TypeDir:
		// Create directory unless it exists as a directory already.
		// In that case we just want to merge the two
		if fi, err := os.Lstat(path); !(err == nil && fi.IsDir()) {
			if err := mkdir(path, hdrInfo.Mode()); err != nil {
				return err
			}
		}

	case tar.TypeReg, tar.TypeRegA:
		file, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, hdrInfo.Mode())
		if err != nil {
			return err
		}

		_, err = copyBuffered(ctx, file, reader)
		if err1 := file.Close(); err == nil {
			err = err1
		}
		if err != nil {
			return err
		}

	case tar.TypeBlock, tar.TypeChar:
		// Handle this is an OS-specific way
		if err := handleTarTypeBlockCharFifo(hdr, path); err != nil {
			return err
		}

	case tar.TypeFifo:
		// Handle this is an OS-specific way
		if err := handleTarTypeBlockCharFifo(hdr, path); err != nil {
			return err
		}

	case tar.TypeLink:
		targetPath, err := fs.RootPath(extractDir, hdr.Linkname)
		if err != nil {
			return err
		}
		if err := os.Link(targetPath, path); err != nil {
			return err
		}

	case tar.TypeSymlink:
		if err := os.Symlink(hdr.Linkname, path); err != nil {
			return err
		}

	case tar.TypeXGlobalHeader:
		log.G(ctx).Debug("PAX Global Extended Headers found and ignored")
		return nil

	default:
		return errors.Errorf("unhandled tar header type %d\n", hdr.Typeflag)
	}

	// Lchown is not supported on Windows.
	if runtime.GOOS != "windows" {
		if err := os.Lchown(path, hdr.Uid, hdr.Gid); err != nil {
			return err
		}
	}

	for key, value := range hdr.Xattrs {
		if err := setxattr(path, key, value); err != nil {
			if errors.Cause(err) == syscall.ENOTSUP {
				log.G(ctx).WithError(err).Warnf("ignored xattr %s in archive", key)
				continue
			}
			return err
		}
	}

	// There is no LChmod, so ignore mode for symlink. Also, this
	// must happen after chown, as that can modify the file mode
	if err := handleLChmod(hdr, path, hdrInfo); err != nil {
		return err
	}

	return chtimes(path, boundTime(latestTime(hdr.AccessTime, hdr.ModTime)), boundTime(hdr.ModTime))
}

func copyBuffered(ctx context.Context, dst io.Writer, src io.Reader) (written int64, err error) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		default:
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err

}
