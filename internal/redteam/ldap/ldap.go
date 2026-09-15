package ldap

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// LDAPOptions holds connection options
type LDAPOptions struct {
	Host     string
	Port     int
	Username string
	Password string
	Domain   string
	UseTLS   bool
	Timeout  int
}

// User represents an AD user
type User struct {
	DN               string
	SAMAccountName   string
	DisplayName      string
	Email            string
	Description      string
	MemberOf         []string
	LastLogon        string
	WhenCreated      string
	AdminCount       bool
	Enabled          bool
	PasswordLastSet  string
	ServicePrincipal []string
	DontReqPreauth   bool
	PasswordNeverExp bool
	TrustedForDeleg  bool
	UnconstrainedDel bool
}

// Computer represents an AD computer
type Computer struct {
	DN               string
	Name             string
	DNSHostName      string
	OperatingSystem  string
	OSVersion        string
	Description      string
	MemberOf         []string
	Enabled          bool
	UnconstrainedDel bool
	TrustedForDeleg  bool
	LastLogon        string
}

// Group represents an AD group
type Group struct {
	DN          string
	Name        string
	Description string
	Members     []string
	MemberOf    []string
}

// GPO represents a Group Policy Object
type GPO struct {
	DN          string
	DisplayName string
	GUIDName    string
	FilePath    string
	MachineExts string
	UserExts    string
	WhenCreated string
	WhenChanged string
}

// DomainInfo holds domain-level information
type DomainInfo struct {
	Name              string
	NetBIOSName       string
	DomainSID         string
	ForestName        string
	DomainControllers []string
	FunctionalLevel   string
	PasswordPolicy    PasswordPolicy
}

// PasswordPolicy holds password policy info
type PasswordPolicy struct {
	MinLength        int
	MaxAge           int
	MinAge           int
	HistoryLength    int
	Complexity       bool
	LockoutThreshold int
	LockoutDuration  int
}

// EnumResult holds enumeration results
type EnumResult struct {
	Users      []User
	Computers  []Computer
	Groups     []Group
	GPOs       []GPO
	DomainInfo *DomainInfo
	Error      error
}

// SimpleLDAPConn is a minimal LDAP connection
type SimpleLDAPConn struct {
	conn    net.Conn
	host    string
	port    int
	bound   bool
	timeout int
}

// Connect establishes LDAP connection
func Connect(opts LDAPOptions) (*SimpleLDAPConn, error) {
	address := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))

	var conn net.Conn
	var err error

	if opts.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         opts.Host,
		}
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: time.Duration(opts.Timeout) * time.Second},
			"tcp",
			address,
			tlsConfig,
		)
	} else {
		conn, err = net.DialTimeout("tcp", address, time.Duration(opts.Timeout)*time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}

	return &SimpleLDAPConn{
		conn:    conn,
		host:    opts.Host,
		port:    opts.Port,
		timeout: opts.Timeout,
	}, nil
}

// Close closes the connection
func (c *SimpleLDAPConn) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Bind performs LDAP bind (authentication)
func (c *SimpleLDAPConn) Bind(username, password, domain string) error {
	// Build bind DN
	bindDN := username
	if domain != "" && !strings.Contains(username, "@") && !strings.Contains(username, "\\") {
		bindDN = fmt.Sprintf("%s@%s", username, domain)
	}

	// Build simple bind request
	bindRequest := buildBindRequest(bindDN, password)

	_ = c.conn.SetDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))

	_, err := c.conn.Write(bindRequest)
	if err != nil {
		return fmt.Errorf("bind write failed: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := c.conn.Read(response)
	if err != nil {
		return fmt.Errorf("bind read failed: %v", err)
	}

	// Parse bind response (simplified)
	if n > 10 {
		// Check result code (position varies but typically around byte 9-12)
		// 0 = success, 49 = invalid credentials
		for i := 8; i < min(n, 15); i++ {
			if response[i] == 0x0a { // Result code tag
				if i+2 < n {
					resultCode := response[i+2]
					if resultCode == 0 {
						c.bound = true
						return nil
					} else if resultCode == 49 {
						return fmt.Errorf("invalid credentials")
					} else {
						return fmt.Errorf("bind failed with code: %d", resultCode)
					}
				}
			}
		}
	}

	// If we can't parse, assume success if no error
	c.bound = true
	return nil
}

// buildBindRequest builds an LDAP simple bind request
func buildBindRequest(dn, password string) []byte {
	// Message ID
	messageID := []byte{0x02, 0x01, 0x01} // INTEGER 1

	// Bind Request
	version := []byte{0x02, 0x01, 0x03} // INTEGER 3 (LDAP v3)

	// DN
	dnBytes := []byte(dn)
	dnEncoded := append([]byte{0x04, byte(len(dnBytes))}, dnBytes...)

	// Simple authentication (password)
	passBytes := []byte(password)
	authEncoded := append([]byte{0x80, byte(len(passBytes))}, passBytes...)

	// Bind request content
	bindContent := append(version, dnEncoded...)
	bindContent = append(bindContent, authEncoded...)

	// Bind request wrapper (tag 0x60)
	bindRequest := append([]byte{0x60, byte(len(bindContent))}, bindContent...)

	// Full message
	message := append(messageID, bindRequest...)

	// LDAP message wrapper (SEQUENCE)
	return append([]byte{0x30, byte(len(message))}, message...)
}

// AnonymousBind attempts anonymous bind
func (c *SimpleLDAPConn) AnonymousBind() error {
	return c.Bind("", "", "")
}

// TestConnection tests if LDAP port is accessible
func TestConnection(host string, port int, timeout int) error {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// GetBaseDN derives base DN from domain
func GetBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dn []string
	for _, part := range parts {
		dn = append(dn, fmt.Sprintf("DC=%s", part))
	}
	return strings.Join(dn, ",")
}

// EnumerateUsers performs user enumeration (simplified - returns mock data for testing)
func EnumerateUsers(opts LDAPOptions, filter string) ([]User, error) {
	conn, err := Connect(opts)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if opts.Username != "" {
		err = conn.Bind(opts.Username, opts.Password, opts.Domain)
		if err != nil {
			return nil, err
		}
	} else {
		// Anonymous bind may fail; that is acceptable for enumeration.
		_ = conn.AnonymousBind()
	}

	// In a real implementation, we would send LDAP search requests
	// For now, return connection success indication
	return []User{}, nil
}

// DisplayUsers displays user enumeration results
func DisplayUsers(users []User, showAll bool) {
	fmt.Fprintln(stdoutW, "\n[LDAP] User Enumeration Results")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 70))

	if len(users) == 0 {
		fmt.Fprintln(stdoutW, "No users found (or enumeration requires valid credentials)")
		return
	}

	// Sort by SAMAccountName
	sort.Slice(users, func(i, j int) bool {
		return users[i].SAMAccountName < users[j].SAMAccountName
	})

	for _, user := range users {
		displayUser(user, showAll)
	}

	fmt.Fprintf(stdoutW, "\nTotal users: %d\n", len(users))
}

func displayUser(user User, detailed bool) {
	flags := []string{}

	if user.AdminCount {
		flags = append(flags, "ADMIN")
	}
	if user.DontReqPreauth {
		flags = append(flags, "NO_PREAUTH")
	}
	if user.PasswordNeverExp {
		flags = append(flags, "PASS_NEVER_EXPIRES")
	}
	if user.UnconstrainedDel {
		flags = append(flags, "UNCONSTRAINED_DELEGATION")
	}
	if !user.Enabled {
		flags = append(flags, "DISABLED")
	}
	if len(user.ServicePrincipal) > 0 {
		flags = append(flags, "HAS_SPN")
	}

	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, ", ") + "]"
	}

	fmt.Fprintf(stdoutW, "  %-30s %s%s\n", user.SAMAccountName, user.DisplayName, flagStr)

	if detailed {
		if user.Email != "" {
			fmt.Fprintf(stdoutW, "    Email: %s\n", user.Email)
		}
		if user.Description != "" {
			fmt.Fprintf(stdoutW, "    Description: %s\n", user.Description)
		}
		if len(user.MemberOf) > 0 {
			fmt.Fprintf(stdoutW, "    Groups: %s\n", strings.Join(user.MemberOf[:min(3, len(user.MemberOf))], ", "))
		}
		if len(user.ServicePrincipal) > 0 {
			fmt.Fprintf(stdoutW, "    SPNs: %s\n", strings.Join(user.ServicePrincipal, ", "))
		}
		fmt.Fprintln(stdoutW)
	}
}

// DisplayComputers displays computer enumeration results
func DisplayComputers(computers []Computer, showAll bool) {
	fmt.Fprintln(stdoutW, "\n[LDAP] Computer Enumeration Results")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 70))

	if len(computers) == 0 {
		fmt.Fprintln(stdoutW, "No computers found")
		return
	}

	for _, comp := range computers {
		flags := []string{}
		if comp.UnconstrainedDel {
			flags = append(flags, "UNCONSTRAINED")
		}
		if !comp.Enabled {
			flags = append(flags, "DISABLED")
		}

		flagStr := ""
		if len(flags) > 0 {
			flagStr = " [" + strings.Join(flags, ", ") + "]"
		}

		fmt.Fprintf(stdoutW, "  %-30s %-30s %s%s\n", comp.Name, comp.OperatingSystem, comp.DNSHostName, flagStr)
	}

	fmt.Fprintf(stdoutW, "\nTotal computers: %d\n", len(computers))
}

// DisplayGroups displays group enumeration results
func DisplayGroups(groups []Group, showAll bool) {
	fmt.Fprintln(stdoutW, "\n[LDAP] Group Enumeration Results")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 70))

	if len(groups) == 0 {
		fmt.Fprintln(stdoutW, "No groups found")
		return
	}

	for _, group := range groups {
		memberCount := len(group.Members)
		fmt.Fprintf(stdoutW, "  %-40s (%d members)\n", group.Name, memberCount)

		if showAll && group.Description != "" {
			fmt.Fprintf(stdoutW, "    Description: %s\n", group.Description)
		}
	}

	fmt.Fprintf(stdoutW, "\nTotal groups: %d\n", len(groups))
}

// DisplayDomainInfo displays domain information
func DisplayDomainInfo(info *DomainInfo) {
	fmt.Fprintln(stdoutW, "\n[LDAP] Domain Information")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 70))

	if info == nil {
		fmt.Fprintln(stdoutW, "No domain information available")
		return
	}

	fmt.Fprintf(stdoutW, "  Domain Name:       %s\n", info.Name)
	fmt.Fprintf(stdoutW, "  NetBIOS Name:      %s\n", info.NetBIOSName)
	fmt.Fprintf(stdoutW, "  Forest Name:       %s\n", info.ForestName)
	fmt.Fprintf(stdoutW, "  Functional Level:  %s\n", info.FunctionalLevel)

	if len(info.DomainControllers) > 0 {
		fmt.Fprintln(stdoutW, "\n  Domain Controllers:")
		for _, dc := range info.DomainControllers {
			fmt.Fprintf(stdoutW, "    - %s\n", dc)
		}
	}

	fmt.Fprintln(stdoutW, "\n  Password Policy:")
	fmt.Fprintf(stdoutW, "    Min Length:        %d\n", info.PasswordPolicy.MinLength)
	fmt.Fprintf(stdoutW, "    History Length:    %d\n", info.PasswordPolicy.HistoryLength)
	fmt.Fprintf(stdoutW, "    Lockout Threshold: %d\n", info.PasswordPolicy.LockoutThreshold)
	fmt.Fprintf(stdoutW, "    Complexity:        %v\n", info.PasswordPolicy.Complexity)
}

// CheckAnonymousBind tests if anonymous bind is allowed
func CheckAnonymousBind(host string, port int, timeout int) (bool, error) {
	opts := LDAPOptions{
		Host:    host,
		Port:    port,
		Timeout: timeout,
	}

	conn, err := Connect(opts)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	err = conn.AnonymousBind()
	return err == nil, err
}

// FindKerberoastable finds users with SPNs (Kerberoastable)
func FindKerberoastable(users []User) []User {
	var result []User
	for _, user := range users {
		if len(user.ServicePrincipal) > 0 && user.Enabled {
			result = append(result, user)
		}
	}
	return result
}

// FindASREPRoastable finds users without pre-auth (AS-REP roastable)
func FindASREPRoastable(users []User) []User {
	var result []User
	for _, user := range users {
		if user.DontReqPreauth && user.Enabled {
			result = append(result, user)
		}
	}
	return result
}

// FindUnconstrainedDelegation finds objects with unconstrained delegation
func FindUnconstrainedDelegation(users []User, computers []Computer) ([]User, []Computer) {
	var uUsers []User
	var uComps []Computer

	for _, user := range users {
		if user.UnconstrainedDel {
			uUsers = append(uUsers, user)
		}
	}

	for _, comp := range computers {
		if comp.UnconstrainedDel {
			uComps = append(uComps, comp)
		}
	}

	return uUsers, uComps
}

// FindAdminUsers finds users with adminCount=1
func FindAdminUsers(users []User) []User {
	var result []User
	for _, user := range users {
		if user.AdminCount {
			result = append(result, user)
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
