package main

import "testing"

func TestConcat(t *testing.T) {
	t.Parallel()
	expr := "concat(10,\"test\")==\"test\""
	err := Validate(expr)
	t.Log(err)
	if err == nil {
		t.Fatal("Concat shouldn't be able to take integers")
	}

	expr = "concat(\"test\")==\"test\""
	err = Validate(expr)
	t.Log(err)
	if err == nil {
		t.Fatal("Concat doesn't support single variables")
	}

	expr = "concat(\"test\",\"test\")==\"test\""
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	//Array inputs
	expr = "concat(http.request.headers[\"test\"][0],http.request.headers[\"test\"][0])==\"test\""
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	//Array expansion
	expr = "concat(http.request.headers[\"test\"][*],\"test\")[0]==\"test\""
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	//map
	expr = "concat(http.request.headers[*][*],\"test\")[0]==\"test\""
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegexFunc(t *testing.T) {
	t.Parallel()
	expr := "regex_replace(\"test\",/test/,\"1\") == \"test\""
	err := Validate(expr)
	if err == nil {
		t.Fatal("Can't replace string ")
	}
}

func TestLen(t *testing.T) {
	t.Parallel()
	// Takes bytes field
	expr := "len(cf.random_seed) == 10"
	err := Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	//Doesn't take raw value

	expr = "len(\"ten\") == 3"
	err = Validate(expr)
	if err == nil {
		t.Fatal("Values shouldn't be supported")
	}
}

func TestBool(t *testing.T) {
	t.Parallel()
	expr := "not ssl"
	err := Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	expr = "ssl == false"
	err = Validate(expr)
	if err == nil {
		t.Fatal("Should be error")
	}

	//bool function
	expr = "ends_with(http.host,\"test\") == false"
	err = Validate(expr)
	if err == nil {
		t.Fatal("Should be error")
	}

	expr = "ends_with(http.host,\"test\")"
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	//raw
	expr = "true"
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

}

func TestArrayFieldInFunc(t *testing.T) {
	t.Parallel()
	expr := "len(http.request.headers[\"test\"][*])[0] == 3"
	err := Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	expr = "ends_with(http.request.headers[\"test\"][*],\"test\")[0]"
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}

	expr = "not any(not ends_with(http.request.headers[*][*],\"test\"))"
	err = Validate(expr)
	if err != nil {
		t.Fatal(err)
	}
}
