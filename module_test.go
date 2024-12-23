package gomoduletemplate_test

import (
	"testing"

	gomoduletemplate "github.com/YOURUSER/YOURREPONAME"
)

func TestWorkingGoInstall(t *testing.T) {
	t.Log("Your go installation works!")
}

func TestFibonacci(t *testing.T) {
	var sequence = []int{0, 1, 1, 2, 3, 5, 8, 13, 21, 34}
	for nth, expected := range sequence {
		got := gomoduletemplate.Fibonacci(nth)
		if got != expected {
			t.Errorf("Fibonacci(%d) = %d, expected %d", nth, got, expected)
		}
	}
}
