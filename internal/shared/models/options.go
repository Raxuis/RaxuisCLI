package models

// ScanOptions holds common scanning configuration
type ScanOptions struct {
	URL          string
	Method       string
	Headers      map[string]string
	Cookie       string
	UserAgent    string
	Timeout      int
	Threads      int
	Insecure     bool
	FollowRedir  bool
	Verbose      bool
	PayloadLevel int // 1=basic, 2=normal, 3=aggressive
}

// CORSOptions holds CORS testing configuration
type CORSOptions struct {
	ScanOptions
	TestOrigin string
	Full       bool
}

// NoSQLiOptions holds NoSQL injection testing configuration
type NoSQLiOptions struct {
	ScanOptions
	Data   string
	DBType string // mongodb, couchdb, etc.
	IsJSON bool
}

// XXEOptions holds XXE testing configuration
type XXEOptions struct {
	ScanOptions
	OOBCallback string
	PayloadType string // file, oob, error
}

// GraphQLOptions holds GraphQL testing configuration
type GraphQLOptions struct {
	ScanOptions
	Introspect bool
	DoS        bool
}

// HostHeaderOptions holds host header testing configuration
type HostHeaderOptions struct {
	ScanOptions
	Poison bool // password reset poisoning
	Cache  bool // web cache poisoning
}

// RaceOptions holds race condition testing configuration
type RaceOptions struct {
	ScanOptions
	Data       string
	Requests   int
	Concurrent bool
}

// RequestOptions holds HTTP request configuration
type RequestOptions struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Cookie      string
	UserAgent   string
	Timeout     int
	Insecure    bool
	FollowRedir bool
}
