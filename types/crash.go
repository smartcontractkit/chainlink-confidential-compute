package types

// DEBUG BUILDS ONLY. The crash channel ships unredacted enclave state
// (tracebacks, kernel log, trace records, core dumps) to the untrusted host.

const (
	// CrashReportPort is the host vsock port the enclave supervisor dials.
	CrashReportPort uint32 = 5002

	// CrashReportAck is what the host writes once a report is fully stored.
	CrashReportAck = "ack\n"

	// CrashStreamLive is a long-lived connection carrying CrashLiveMessage
	// lines while the app runs.
	CrashStreamLive = "live"
	// CrashStreamReport is a one-shot connection carrying a gzip-compressed
	// tar of crash artifacts, answered with CrashReportAck.
	CrashStreamReport = "report"

	// CrashReportFile is the first entry of a report archive.
	CrashReportFile = "report.json"
)

// CrashStreamHeader is the first line of every crash-channel connection.
type CrashStreamHeader struct {
	Kind string `json:"kind"`
	// BootID identifies one enclave boot across its connections.
	BootID   string `json:"boot_id"`
	App      string `json:"app"`
	UnixNano int64  `json:"unix_nano"`
}

// CrashLiveMessage is one line of a live stream.
type CrashLiveMessage struct {
	// Stream names the source: "kmsg", "trace", "sample", "threads",
	// "gocrash", "note".
	Stream   string   `json:"k"`
	UnixNano int64    `json:"t"`
	Lines    []string `json:"l"`
}

// CrashReport is the summary the supervisor writes when the enclave app exits.
type CrashReport struct {
	BootID string   `json:"boot_id"`
	App    string   `json:"app"`
	Args   []string `json:"args,omitempty"`
	Env    []string `json:"env,omitempty"`
	PID    int      `json:"pid"`

	StartedUnixNano int64   `json:"started_unix_nano"`
	ExitedUnixNano  int64   `json:"exited_unix_nano"`
	Exited          string  `json:"exited"`
	UptimeSeconds   float64 `json:"uptime_seconds"`

	// ExitCode is the exit status, or 128+signal when the app was signalled.
	ExitCode int `json:"exit_code"`
	// Status is os.ProcessState's rendering, e.g. "signal: aborted (core dumped)".
	Status     string `json:"status,omitempty"`
	Signal     string `json:"signal,omitempty"`
	CoreDumped bool   `json:"core_dumped"`
	WaitError  string `json:"wait_error,omitempty"`
	// Terminated is set when the supervisor forwarded a termination signal.
	Terminated bool `json:"terminated,omitempty"`

	// OOMKilled is set when the kernel's OOM killer ran during this boot and the
	// app died by SIGKILL. OOMKills is the kernel's own count of kills, and
	// KernelOOMLines are the kernel log lines that name the victim.
	OOMKilled      bool     `json:"oom_killed"`
	OOMKills       uint64   `json:"oom_kills"`
	KernelOOMLines []string `json:"kernel_oom_lines,omitempty"`

	PeakRSSBytes          uint64  `json:"peak_rss_bytes,omitempty"`
	UserCPUSeconds        float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds      float64 `json:"system_cpu_seconds"`
	MinorFaults           int64   `json:"minor_faults"`
	MajorFaults           int64   `json:"major_faults"`
	VoluntaryCtxSwitches  int64   `json:"voluntary_ctx_switches"`
	InvoluntaryCtxSwitch  int64   `json:"involuntary_ctx_switches"`
	LastHeartbeatUnixNano int64   `json:"last_heartbeat_unix_nano,omitempty"`
	// HeartbeatAgeSeconds is how long before exit the app last stamped its
	// heartbeat: a large value means the Go runtime stopped before the process
	// went away.
	HeartbeatAgeSeconds float64 `json:"heartbeat_age_seconds,omitempty"`
	HeartbeatCount      uint64  `json:"heartbeat_count,omitempty"`

	// Notes records what the supervisor could and could not set up or collect.
	Notes []string `json:"notes,omitempty"`
	// Files lists the archive entries that follow, with their sizes.
	Files map[string]int64 `json:"files,omitempty"`
}
