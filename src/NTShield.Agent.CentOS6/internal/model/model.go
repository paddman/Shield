package model

import "time"

// The JSON field names intentionally match NTShield.Shared contracts.
// Keep these structs dependency-free so the legacy agent can be built as a
// static binary for CentOS 6.

type AgentRegistrationRequest struct {
	AgentID               string  `json:"agentId"`
	ComputerName          string  `json:"computerName"`
	AgentVersion          string  `json:"agentVersion"`
	OSVersion             string  `json:"osVersion"`
	CertificateThumbprint *string `json:"certificateThumbprint,omitempty"`
	HostIP                string  `json:"hostIp,omitempty"`
	EnrollmentToken       string  `json:"enrollmentToken,omitempty"`
	RotateAPIKey          bool    `json:"rotateApiKey"`
	BinarySHA256          string  `json:"binarySha256,omitempty"`
	IsBinarySigned        *bool   `json:"isBinarySigned,omitempty"`
	Platform              string  `json:"platform"`
}

type AgentRegistrationResponse struct {
	Accepted    bool   `json:"accepted"`
	Message     string `json:"message"`
	ServerUTC   string `json:"serverUtc"`
	AgentAPIKey string `json:"agentApiKey"`
}

type AgentHeartbeat struct {
	AgentID                 string   `json:"agentId"`
	ComputerName            string   `json:"computerName"`
	AgentVersion            string   `json:"agentVersion"`
	OSVersion               string   `json:"osVersion"`
	TimestampUTC            string   `json:"timestampUtc"`
	LocalQueueDepth         int64    `json:"localQueueDepth"`
	DatabaseSizeBytes       int64    `json:"databaseSizeBytes"`
	Status                  string   `json:"status"`
	WorkingSetBytes         int64    `json:"workingSetBytes"`
	CPUPercentEstimate      *float64 `json:"cpuPercentEstimate,omitempty"`
	ClockSkewSeconds        float64  `json:"clockSkewSeconds"`
	HostIP                  string   `json:"hostIp,omitempty"`
	CentralURL              string   `json:"centralUrl,omitempty"`
	Platform                string   `json:"platform"`
	LastError               string   `json:"lastError,omitempty"`
	BinarySHA256            string   `json:"binarySha256,omitempty"`
	IsBinarySigned          *bool    `json:"isBinarySigned,omitempty"`
	AppliedPolicyVersion    *int     `json:"appliedPolicyVersion,omitempty"`
	MemUsedPercent          *float64 `json:"memUsedPercent,omitempty"`
	DiskUsedPercent         *float64 `json:"diskUsedPercent,omitempty"`
	NetworkRXBytesPerSecond *float64 `json:"networkRxBytesPerSec,omitempty"`
	NetworkTXBytesPerSecond *float64 `json:"networkTxBytesPerSec,omitempty"`
	DiskReadBytesPerSecond  *float64 `json:"diskReadBytesPerSec,omitempty"`
	DiskWriteBytesPerSecond *float64 `json:"diskWriteBytesPerSec,omitempty"`
	LoadAverage1            *float64 `json:"loadAverage1,omitempty"`
	HostMemUsedBytes        *int64   `json:"hostMemUsedBytes,omitempty"`
	HostMemTotalBytes       *int64   `json:"hostMemTotalBytes,omitempty"`
	MetricsSummary          string   `json:"metricsSummary,omitempty"`
}

type HeartbeatResponse struct {
	Accepted         bool    `json:"accepted"`
	ServerUTC        string  `json:"serverUtc"`
	ClockSkewSeconds float64 `json:"clockSkewSeconds"`
}

type AgentIngestBatch struct {
	AgentID            string                    `json:"agentId"`
	ComputerName       string                    `json:"computerName"`
	AgentVersion       string                    `json:"agentVersion"`
	SentAtUTC          string                    `json:"sentAtUtc"`
	IdempotencyKey     string                    `json:"idempotencyKey"`
	SecurityEvents     []SecurityEventRecord     `json:"securityEvents"`
	NetworkConnections []NetworkConnectionRecord `json:"networkConnections"`
	Processes          []any                     `json:"processes"`
	Services           []any                     `json:"services"`
	ScheduledTasks     []any                     `json:"scheduledTasks"`
	Alerts             []DetectionAlert          `json:"alerts"`
}

type IngestResponse struct {
	Accepted           bool     `json:"accepted"`
	Message            string   `json:"message"`
	ReceivedCount      int      `json:"receivedCount"`
	CreatedIncidentIDs []string `json:"createdIncidentIds"`
	Duplicate          bool     `json:"duplicate"`
}

type SecurityEventRecord struct {
	ID                    int64  `json:"id"`
	TimestampUTC          string `json:"timestampUtc"`
	ComputerName          string `json:"computerName"`
	AgentID               string `json:"agentId"`
	EventID               int    `json:"eventId"`
	Channel               string `json:"channel"`
	ProviderName          string `json:"providerName,omitempty"`
	Username              string `json:"username,omitempty"`
	Domain                string `json:"domain,omitempty"`
	SourceIP              string `json:"sourceIp,omitempty"`
	SourcePort            *int   `json:"sourcePort,omitempty"`
	DestinationIP         string `json:"destinationIp,omitempty"`
	DestinationPort       *int   `json:"destinationPort,omitempty"`
	LogonType             *int   `json:"logonType,omitempty"`
	AuthenticationPackage string `json:"authenticationPackage,omitempty"`
	ProcessID             *int   `json:"processId,omitempty"`
	ProcessPath           string `json:"processPath,omitempty"`
	LogonProcess          string `json:"logonProcess,omitempty"`
	Status                string `json:"status,omitempty"`
	SubStatus             string `json:"subStatus,omitempty"`
	TargetUserName        string `json:"targetUserName,omitempty"`
	TargetDomainName      string `json:"targetDomainName,omitempty"`
	WorkstationName       string `json:"workstationName,omitempty"`
	ServiceName           string `json:"serviceName,omitempty"`
	TaskName              string `json:"taskName,omitempty"`
	RawXML                string `json:"rawXml"`
	EventRecordID         int64  `json:"eventRecordId"`
	CollectedAtUTC        string `json:"collectedAtUtc"`
}

type NetworkConnectionRecord struct {
	ID                     int64  `json:"id"`
	TimestampUTC           string `json:"timestampUtc"`
	ComputerName           string `json:"computerName"`
	AgentID                string `json:"agentId"`
	Protocol               string `json:"protocol"`
	LocalAddress           string `json:"localAddress"`
	LocalPort              int    `json:"localPort"`
	RemoteAddress          string `json:"remoteAddress"`
	RemotePort             int    `json:"remotePort"`
	TCPState               *int   `json:"tcpState,omitempty"`
	ProcessID              int    `json:"processId"`
	ProcessName            string `json:"processName,omitempty"`
	ProcessPath            string `json:"processPath,omitempty"`
	ProcessCommandLine     string `json:"processCommandLine,omitempty"`
	ProcessOwner           string `json:"processOwner,omitempty"`
	ParentProcessID        *int   `json:"parentProcessId,omitempty"`
	DigitalSignatureStatus string `json:"digitalSignatureStatus,omitempty"`
	SignerName             string `json:"signerName,omitempty"`
	ExecutableSHA256       string `json:"executableSha256,omitempty"`
	ServiceNames           string `json:"serviceNames,omitempty"`
	ServiceDisplayNames    string `json:"serviceDisplayNames,omitempty"`
	IsNew                  bool   `json:"isNew"`
	IsClosed               bool   `json:"isClosed"`
	ConnectionKey          string `json:"connectionKey"`
}

type DetectionAlert struct {
	ID                       int64  `json:"id"`
	AlertID                  string `json:"alertId"`
	TimestampUTC             string `json:"timestampUtc"`
	ComputerName             string `json:"computerName"`
	AgentID                  string `json:"agentId"`
	RuleID                   string `json:"ruleId"`
	RuleName                 string `json:"ruleName"`
	Severity                 int    `json:"severity"`
	Title                    string `json:"title"`
	Description              string `json:"description"`
	SourceIP                 string `json:"sourceIp,omitempty"`
	DestinationIP            string `json:"destinationIp,omitempty"`
	Username                 string `json:"username,omitempty"`
	EventCount               int    `json:"eventCount"`
	DistinctUserCount        int    `json:"distinctUserCount"`
	DistinctDestinationCount int    `json:"distinctDestinationCount"`
	EvidenceJSON             string `json:"evidenceJson"`
	Suppressed               bool   `json:"suppressed"`
	CooldownUntilUTC         string `json:"cooldownUntilUtc,omitempty"`
}

func NewBatch(agentID, computerName, version, key string) AgentIngestBatch {
	return AgentIngestBatch{
		AgentID:            agentID,
		ComputerName:       computerName,
		AgentVersion:       version,
		SentAtUTC:          time.Now().UTC().Format(time.RFC3339Nano),
		IdempotencyKey:     key,
		SecurityEvents:     make([]SecurityEventRecord, 0),
		NetworkConnections: make([]NetworkConnectionRecord, 0),
		Processes:          make([]any, 0),
		Services:           make([]any, 0),
		ScheduledTasks:     make([]any, 0),
		Alerts:             make([]DetectionAlert, 0),
	}
}
