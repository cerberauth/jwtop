package crack

import "context"

// ScanMeta carries scan-level context passed to Reporter.Report.
type ScanMeta struct {
	Target         string
	BaselineStatus int
	Offline        bool
	TokenString    string
}

// Reporter outputs the results of a crack scan.
type Reporter interface {
	Report(ctx context.Context, results []ProbeResult, meta ScanMeta) error
}
