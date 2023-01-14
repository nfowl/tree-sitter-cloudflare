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
