package payloads

// GraphQLQueries contains GraphQL introspection and enumeration queries
var GraphQLQueries = map[string]string{
	"introspection_full":   `{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}`,
	"introspection_simple": `{"query":"{__schema{types{name fields{name}}}}"}`,
	"type_query":           `{"query":"{__type(name:\"User\"){fields{name type{name}}}}"}`,
	"query_type":           `{"query":"{__schema{queryType{fields{name}}}}"}`,
	"mutation_type":        `{"query":"{__schema{mutationType{fields{name}}}}"}`,
}

// GraphQLDoSQueries contains queries for testing GraphQL DoS vulnerabilities
var GraphQLDoSQueries = []string{
	`{"query":"query{__typename ".repeat(100)+"}"}`, // Placeholder for actual nested query
	`{"query":"{a]}}"}`,                             // Field suggestion exploitation
}

// GraphQLSuggestionQuery is used to test for field suggestions (typo-based enumeration)
var GraphQLSuggestionQuery = `{"query":"{user{__badfield}}"}`

// GraphQLBatchQuery is used to test for query batching support
var GraphQLBatchQuery = `[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]`

// GraphQLNestedQuery is used to test for deeply nested query DoS
var GraphQLNestedQuery = `{"query":"{__schema{types{name fields{name type{name fields{name type{name}}}}}}}"}`

// SensitiveTypeNames contains field/type names that may indicate sensitive data exposure
var SensitiveTypeNames = []string{
	"password",
	"secret",
	"token",
	"key",
	"admin",
	"credential",
	"private",
	"internal",
	"debug",
}

// GetGraphQLQuery returns a GraphQL query by name
func GetGraphQLQuery(name string) string {
	if q, ok := GraphQLQueries[name]; ok {
		return q
	}
	return ""
}
