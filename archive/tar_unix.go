// +build !windows

package archive

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/containerd/containerd/fs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/continuity/sysx"
	"github.com/dmcgowan/go-tar"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func tarName(p string) (string, error) {
	return p, nil
}

func chmodTarEntry(perm os.FileMode) os.FileMode {
	return perm
}

func setHeaderForSpecialDevice(hdr *tar.Header, name string, fi os.FileInfo) error {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unsupported stat type")
	}

	// Currently go does not fill in the major/minors
	if s.Mode&syscall.S_IFBLK != 0 ||
		s.Mode&syscall.S_IFCHR != 0 {
		hdr.Devmajor = int64(unix.Major(uint64(s.Rdev)))
		hdr.Devminor = int64(unix.Minor(uint64(s.Rdev)))
	}

	return nil
}

func open(p string) (*os.File, error) {
	return os.Open(p)
}

func openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	// Call chmod to avoid permission mask
	if err := os.Chmod(name, perm); err != nil {
		return nil, err
	}
	return f, err
}

func mkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func mkdir(path string, perm os.FileMode) error {
	if err := os.Mkdir(path, perm); err != nil {
		return err
	}
	// Only final created directory gets explicit permission
	// call to avoid permission mask
	return os.Chmod(path, perm)
}

func skipFile(*tar.Header) bool {
	return false
}

var (
	inUserNS bool
	nsOnce   sync.Once
)

func setInUserNS() {
	inUserNS = system.RunningInUserNS()
}

// handleTarTypeBlockCharFifo is an OS-specific helper function used by
// createTarFile to handle the following types of header: Block; Char; Fifo
func handleTarTypeBlockCharFifo(hdr *tar.Header, path string) error {
	nsOnce.Do(setInUserNS)
	if inUserNS {
		// cannot create a device if running in user namespace
		return nil
	}

	mode := uint32(hdr.Mode & 07777)
	switch hdr.Typeflag {
	case tar.TypeBlock:
		mode |= unix.S_IFBLK
	case tar.TypeChar:
		mode |= unix.S_IFCHR
	case tar.TypeFifo:
		mode |= unix.S_IFIFO
	}

	return unix.Mknod(path, mode, int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))))
}

func handleLChmod(hdr *tar.Header, path string, hdrInfo os.FileInfo) error {
	if hdr.Typeflag == tar.TypeLink {
		if fi, err := os.Lstat(hdr.Linkname); err == nil && (fi.Mode()&os.ModeSymlink == 0) {
			if err := os.Chmod(path, hdrInfo.Mode()); err != nil {
				return err
			}
		}
	} else if hdr.Typeflag != tar.TypeSymlink {
		if err := os.Chmod(path, hdrInfo.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func getxattr(path, attr string) ([]byte, error) {
	b, err := sysx.LGetxattr(path, attr)
	if err == unix.ENOTSUP || err == sysx.ENODATA {
		return nil, nil
	}
	return b, err
}

func setxattr(path, key, value string) error {
	return sysx.LSetxattr(path, key, []byte(value), 0)
}

type tarToLayerWriter struct {
	root string

	// Used for aufs plink directory
	aufsTempdir   string
	aufsHardlinks map[string]*tar.Header

	// Used for handling opaque directory markers which
	// may occur out of order
	unpackedPaths map[string]struct{}

	oldumask int
}

func newTarToLayerWriter(root string) (TarToLayerWriter, error) {
	return tarToLayerWriter{
		root:          root,
		aufsHardlinks: make(map[string]*tar.Header),
		unpackedPaths: make(map[string]struct{}),
		oldumask:      unix.Umask(0),
	}, nil
}

// AddTarFile may require multiple tar entries to get all the alternate data
// streams, so pass it the reader. It returns the next tar header to process
func (w *tarToLayerWriter) AddTarFile(ctx context.Context, t *tar.Reader, hdr *tar.Header) (*tar.Header, error) {
	reader := io.Reader(tr)
	extractDir := w.Root()

	// Normalize name, for safety and for a simple is-root check
	hdr.Name = filepath.Clean(hdr.Name)

	// Split name and resolve symlinks for root directory.
	ppath, base := filepath.Split(hdr.Name)
	ppath, err = fs.RootPath(root, ppath)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get root path")
	}

	// If file is not directly under root, ensure parent directory
	// exists or is created.
	if ppath != root {
		parentPath := ppath
		if base == "" {
			parentPath = filepath.Dir(path)
		}
		if _, err := os.Lstat(parentPath); err != nil && os.IsNotExist(err) {
			err = mkdirAll(parentPath, 0700)
			if err != nil {
				return 0, err
			}
		}
	}

	// Join to root before joining to parent path to ensure relative links are
	// already resolved based on the root before adding to parent.
	path := filepath.Join(ppath, filepath.Join("/", base))
	if path == root {
		log.G(ctx).Debugf("file %q ignored: resolved to root", hdr.Name)
		return t.Next()
	}

	// If path exits we almost always just want to remove and replace it.
	// The only exception is when it is a directory *and* the file from
	// the layer is also a directory. Then we want to merge them (i.e.
	// just apply the metadata from the layer).
	if fi, err := os.Lstat(path); err == nil {
		if !(fi.IsDir() && hdr.Typeflag == tar.TypeDir) {
			if err := os.RemoveAll(path); err != nil {
				return 0, err
			}
		}
	}

	// Hard links into /.wh..wh.plnk don't work, as we don't extract that directory, so
	// we manually retarget these into the temporary files we extracted them into
	if hdr.Typeflag == tar.TypeLink && strings.HasPrefix(filepath.Clean(hdr.Linkname), whiteoutLinkDir) {
		linkBasename := filepath.Base(hdr.Linkname)
		srcHdr = w.aufsHardlinks[linkBasename]
		if srcHdr == nil {
			return 0, fmt.Errorf("Invalid aufs hardlink")
		}
		p, err := fs.RootPath(aufsTempdir, linkBasename)
		if err != nil {
			return 0, err
		}
		//TODO move to a global context
		tmpFile, err := os.Open(p)
		if err != nil {
			return 0, err
		}
		defer tmpFile.Close()
		srcData = tmpFile
	}

	// hdr.Mode is in linux format, which we can use for syscalls,
	// but for os.Foo() calls we need the mode converted to os.FileMode,
	// so use hdrInfo.Mode() (they differ for e.g. setuid bits)
	hdrInfo := hdr.FileInfo()

	switch hdr.Typeflag {
	case tar.TypeDir:
		// Create directory unless it exists as a directory already.
		// In that case we just want to merge the two
		if fi, err := os.Lstat(path); !(err == nil && fi.IsDir()) {
			if err := os.Mkdir(path, hdrInfo.Mode()); err != nil {
				return nil, err
			}
		}

	case tar.TypeReg, tar.TypeRegA:
		file, err := openFile(path, os.O_CREATE|os.O_WRONLY, hdrInfo.Mode())
		if err != nil {
			return nil, err
		}
		buf := bufferPool.Get().([]byte)
		_, err = io.CopyBuffer(file, reader, buf)
		bufferPool.Put(buf)
		if err1 := file.Close(); err == nil {
			err = err1
		}
		if err != nil {
			return nil, err
		}

	case tar.TypeBlock, tar.TypeChar:
		// Handle this is an OS-specific way
		if err := handleTarTypeBlockCharFifo(hdr, path); err != nil {
			return nil, err
		}

	case tar.TypeFifo:
		// Handle this is an OS-specific way
		if err := handleTarTypeBlockCharFifo(hdr, path); err != nil {
			return nil, err
		}

	case tar.TypeLink:
		targetPath, err := fs.RootPath(extractDir, hdr.Linkname)
		if err != nil {
			return nil, err
		}
		if err := os.Link(targetPath, path); err != nil {
			return nil, err
		}

	case tar.TypeSymlink:
		if err := os.Symlink(hdr.Linkname, path); err != nil {
			return nil, err
		}

	case tar.TypeXGlobalHeader:
		log.G(ctx).Debug("PAX Global Extended Headers found and ignored")
		return t.Next()

	default:
		return errors.Errorf("unhandled tar header type %d\n", hdr.Typeflag)
	}

	// Lchown is not supported on Windows.
	if runtime.GOOS != "windows" {
		if err := os.Lchown(path, hdr.Uid, hdr.Gid); err != nil {
			return nil, err
		}
	}

	for key, value := range hdr.Xattrs {
		if err := setxattr(path, key, value); err != nil {
			if errors.Cause(err) == syscall.ENOTSUP {
				log.G(ctx).WithError(err).Warnf("ignored xattr %s in archive", key)
				continue
			}
			return nil, err
		}
	}

	// There is no LChmod, so ignore mode for symlink. Also, this
	// must happen after chown, as that can modify the file mode
	if err := handleLChmod(hdr, path, hdrInfo); err != nil {
		return nil, err
	}

	if err := chtimes(path, boundTime(latestTime(hdr.AccessTime, hdr.ModTime)), boundTime(hdr.ModTime)); err != nil {
		return nil, err
	}

	w.unpackedPaths[path] = struct{}{}

	return t.Next()
}

func (w *tarToLayerWriter) SetTimeFromTar(hdr *tar.Header) error {
	path, err := fs.RootPath(root, hdr.Name)
	if err != nil {
		return err
	}
	if err := chtimes(path, boundTime(latestTime(hdr.AccessTime, hdr.ModTime)), boundTime(hdr.ModTime)); err != nil {
		return err
	}
	return nil
}

func (w *tarToLayerWriter) HandleWhiteoutFile(srcHdr *tar.Header) error {
	// Normalize name, for safety and for a simple is-root check
	hdr.Name = filepath.Clean(hdr.Name)

	// Split name and resolve symlinks for root directory.
	ppath, base := filepath.Split(relativePath)
	ppath, err = fs.RootPath(w.Root(), ppath)
	if err != nil {
		return errors.Wrap(err, "failed to get root path")
	}

	// Join to root before joining to parent path to ensure relative links are
	// already resolved based on the root before adding to parent.
	path := filepath.Join(ppath, filepath.Join("/", base))
	if path == root {
		log.G(ctx).Debugf("file %q ignored: resolved to root", relativePath)
		return nil
	}

	// Skip AUFS metadata dirs
	if strings.HasPrefix(hdr.Name, whiteoutMetaPrefix) {
		// Regular files inside /.wh..wh.plnk can be used as hardlink targets
		// We don't want this directory, but we need the files in them so that
		// such hardlinks can be resolved.
		if strings.HasPrefix(hdr.Name, whiteoutLinkDir) && hdr.Typeflag == tar.TypeReg {
			basename := filepath.Base(hdr.Name)
			aufsHardlinks[basename] = hdr
			if aufsTempdir == "" {
				if aufsTempdir, err = ioutil.TempDir("", "dockerplnk"); err != nil {
					return 0, err
				}
			}
			p, err := fs.RootPath(aufsTempdir, basename)
			if err != nil {
				return 0, err
			}
			// TODO: What to do here on Windows for plnk?? Ignore? It should never happen..
			if err := createTarFile(ctx, p, root, hdr, tr); err != nil {
				return 0, err
			}
		}

		if hdr.Name != whiteoutOpaqueDir {
			hdr, err = tr.Next()
			continue
		}
	}

	if strings.HasPrefix(base, whiteoutPrefix) {
		dir := filepath.Dir(path)
		if base == whiteoutOpaqueDir {
			// TODO: This should never occur on Windows, refactor as such
			_, err := os.Lstat(dir)
			if err != nil {
				return 0, err
			}
			err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					if os.IsNotExist(err) {
						err = nil // parent was deleted
					}
					return err
				}
				if path == dir {
					return nil
				}
				if _, exists := unpackedPaths[path]; !exists {
					err := os.RemoveAll(path)
					return err
				}
				return nil
			})
			if err != nil {
				return 0, err
			}
			hdr, err = tr.Next()
			continue
		}

		originalBase := base[len(whiteoutPrefix):]
		originalPath := filepath.Join(dir, originalBase)
		if err := os.RemoveAll(originalPath); err != nil {
			return 0, err
		}
		hdr, err = tr.Next()
		continue
	}
}

func (w *tarToLayerWriter) Close() error {
	unix.Umask(w.oldumask)
	if w.aufsTempdir != "" {
		os.RemoveAll(aufsTempdir)
	}
}
