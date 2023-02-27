package main

import "testing"

func expectGood(t *testing.T, expr string) {
	err := Validate(expr)
	t.Log(err)
	if err != nil {
		t.Fatal(err)
	}
}

func expectError(t *testing.T, expr string, e string) {
	err := Validate(expr)
	t.Log(err)
	if err == nil {
		t.Fatal(e)
	}
}

func TestConcat(t *testing.T) {
	t.Parallel()
	// Concat does not support numbers
	expectError(t, "concat(10,\"test\")==\"test\"", "Concat shouldn't be able to take integers")
	// Concat requires multiple variables
	expectError(t, "concat(\"test\")==\"test\"", "Concat doesn't support single variables")
	// Concat
	expectGood(t, "concat(\"test\",\"test\")==\"test\"")
	// Array inputs
	expectGood(t, "concat(http.request.headers[\"test\"][0],http.request.headers[\"test\"][0])==\"test\"")
	//Array expansion
	expectGood(t, "concat(http.request.headers[\"test\"][*],\"test\")[0]==\"test\"")
	//map
	expectGood(t, "concat(http.request.headers[*][*],\"test\")[0]==\"test\"")
}

func TestUuidFunc(t *testing.T) {
	t.Parallel()
	expectGood(t, "uuidv4(http.request.headers[\"test\"][0]) == \"test\"")
}

func TestRegexFunc(t *testing.T) {
	t.Parallel()
	expectError(t, "regex_replace(\"test\",/test/,\"1\") == \"test\"", "Regex does not support literals in first slot")
}

func TestLen(t *testing.T) {
	t.Parallel()
	// Takes bytes field
	expectGood(t, "len(cf.random_seed) == 10")
	//Doesn't take raw value
	expectError(t, "len(\"ten\") == 3", "Values shouldn't be supported")
}

func TestBool(t *testing.T) {
	t.Parallel()
	//Not
	expectGood(t, "not ssl")
	//Not supported in standard expression format
	expectError(t, "ssl == false", "Bool should not be supported in standard expression")
	//function not supported in standard format
	expectError(t, "ends_with(http.host,\"test\") == false", "Bool should not be supported in standard expression")
	// Function
	expectGood(t, "ends_with(http.host,\"test\")")
	//raw
	expectGood(t, "true")
}

func TestArrayFieldInFunc(t *testing.T) {
	t.Parallel()
	//Number in simple expression
	expectGood(t, "len(http.request.headers[\"test\"][*])[0] == 3")
	// boolean expansion/access
	expectGood(t, "ends_with(http.request.headers[\"test\"][*],\"test\")[0]")
	//Boolean with any expansion
	expectGood(t, "not any(not ends_with(http.request.headers[*][*],\"test\"))")
}

func TestAny(t *testing.T) {
	t.Parallel()
	//In expression works
	expectGood(t, "any(http.request.headers[\"test\"][*] in { \"16\" \"test2\" })")
	//Literal works
	expectGood(t, "any(http.request.headers[\"test\"][*] == \"test\")")
	//No compound on rhs
	expectError(t, "any(starts_with(http.request.headers[\"test\"][*],\"test\")[*] == (http.host == \"test\"))", "Only supports literals on rhs")
	//No functions on rhs of any
	expectError(t, "any(starts_with(http.request.headers[\"test\"][*],\"test\")[*] == concat(http.host,\"test\"))", "RHS doesn't support functions")
	//multi level
	expectGood(t, "any(to_string(starts_with(http.request.headers[\"test\"][*],\"test\")[*])[*] == \"false\")")
	//corpus
	expectGood(t, "any(len(http.request.headers[\"test\"][*])[*] eq 3)")
}

func TestGroupInComp(t *testing.T) {
	t.Parallel()
	//Paren with string check
	expectError(t, "(http.cookie == \"test\") == true", "parens not supported in expressions")
	//bool paren
	expectError(t, "(ssl) == true", "parens not supported in expressions")
}

func TestMagicFirewall(t *testing.T) {
	t.Parallel()
	expectGood(t, "icmp == \"testing\"")
}
