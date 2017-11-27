package archive

import (
	"os"

	"github.com/Microsoft/go-winio"
)

type windowsLayerWriter struct {
	root         string
	backupWriter *winio.BackupFileWriter
	currentFile  *os.File
	isIsolated   bool
	hasUtilityVM bool
	dirs         []dirInfo
}

type dirInfo struct {
	path     string
	fileInfo winio.FileBasicInfo
}

func (w *windowsLayerWriter) PrepareApply() error {
	return winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege})
}

func (w *windowsLayerWriter) PostApply(err error) error {
	if !w.isIsolated {
		if err := winio.DisableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}); err != nil {
			// This should never happen, but just in case when in debugging mode.
			// See https://github.com/docker/docker/pull/28002#discussion_r86259241 for rationale.
			panic("Failed to disable process privileges while in non-isolated apply")
		}
	}
	return nil
}
