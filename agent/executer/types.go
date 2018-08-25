package executer

// EncRequest describes encrypted JSON request from Management server.
type EncRequest struct {
	HostID  string `json:"hostid"`
	Request string `json:"request"`
}

// Request is a encapsulation for RequestOptions required by the Management server.
type Request struct {
	ID      string         `json:"id"`
	Request RequestOptions `json:"request"`
}

// RequestOptions describes parameters of the request for command execution.
type RequestOptions struct {
	Type        string            `json:"type"`
	ID          string            `json:"id"`
	CommandID   string            `json:"commandId"`
	WorkingDir  string            `json:"workingDirectory"`
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Environment map[string]string `json:"environment"`
	StdOut      string            `json:"stdOut"`
	StdErr      string            `json:"stdErr"`
	RunAs       string            `json:"runAs"`
	Timeout     int               `json:"timeout"`
	IsDaemon    int               `json:"isDaemon"`
}

// Response is a encapsulation for ResponseOptions required by the Management server.
type Response struct {
	ResponseOpts ResponseOptions `json:"response"`
	ID           string          `json:"id"`
}

// ResponseOptions describes parameters of the response for command execution.
type ResponseOptions struct {
	Type           string `json:"type"`
	ID             string `json:"id"`
	CommandID      string `json:"commandId"`
	Pid            int    `json:"pid"`
	ResponseNumber int    `json:"responseNumber,omitempty"`
	StdOut         string `json:"stdOut,omitempty"`
	StdErr         string `json:"stdErr,omitempty"`
	ExitCode       string `json:"exitCode,omitempty"`
}
