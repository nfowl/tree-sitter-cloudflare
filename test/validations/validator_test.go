package main

import "testing"

func TestConcat(t *testing.T) {
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
}

func TestLen(t *testing.T) {
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
