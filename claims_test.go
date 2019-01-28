package jwtauth

import (
	"testing"

	"github.com/go-test/deep"
)

func TestGetClaim(t *testing.T) {
	tests := []struct {
		allClaims map[string]interface{}
		claim     string
		expected  interface{}
	}{
		{nil, "data", nil},
		{map[string]interface{}{"data": "foo"}, "data", "foo"},
		{map[string]interface{}{"data": "foo"}, "data2", nil},
		{map[string]interface{}{"data": "foo"}, "/data", "foo"},
		{
			map[string]interface{}{"data": map[string]interface{}{
				"foo": "bar",
			}}, "/data/foo", "bar",
		},
		{
			map[string]interface{}{"data": map[string]interface{}{
				"foo": "bar",
			}}, "/data/foo2", nil,
		},

		{map[string]interface{}{"data": "foo"}, `\`, nil},
	}

	for _, test := range tests {
		actual := getClaim(test.allClaims, test.claim)
		if diff := deep.Equal(actual, test.expected); diff != nil {
			t.Fatalf("invalid results for claim '%s': %v", test.claim, diff)
		}
	}
}

func TestExtractMetadata(t *testing.T) {
	emptyMap := make(map[string]string)

	tests := []struct {
		testCase      string
		allClaims     map[string]interface{}
		claimMappings map[string]string
		expected      map[string]string
		errExpected   bool
	}{
		{"empty", nil, nil, emptyMap, false},
		{
			"full match",
			map[string]interface{}{
				"data1": "foo",
				"data2": "bar",
			},
			map[string]string{
				"data1": "val1",
				"data2": "val2",
			},
			map[string]string{
				"val1": "foo",
				"val2": "bar",
			},
			false,
		},
		{
			"partial match",
			map[string]interface{}{
				"data1": "foo",
				"data2": "bar",
			},
			map[string]string{
				"data1": "val1",
				"data3": "val2",
			},
			map[string]string{
				"val1": "foo",
			},
			false,
		},
		{
			"no match",
			map[string]interface{}{
				"data1": "foo",
				"data2": "bar",
			},
			map[string]string{
				"data8": "val1",
				"data9": "val2",
			},
			emptyMap,
			false,
		},
		{
			"nested data",
			map[string]interface{}{
				"data1": "foo",
				"data2": map[string]interface{}{
					"child": "bar",
				},
			},
			map[string]string{
				"data1":        "val1",
				"/data2/child": "val2",
			},
			map[string]string{
				"val1": "foo",
				"val2": "bar",
			},
			false,
		},
		{
			"error: non-string data",
			map[string]interface{}{
				"data1": 42,
			},
			map[string]string{
				"data1": "val1",
			},
			nil,
			true,
		},
	}

	for _, test := range tests {
		actual, err := extractMetadata(test.allClaims, test.claimMappings)
		if (err != nil) != test.errExpected {
			t.Fatalf("case '%s': expected error: %t, actual: %v", test.testCase, test.errExpected, err)
		}
		if diff := deep.Equal(actual, test.expected); diff != nil {
			t.Fatalf("case '%s': expected results: %v", test.testCase, diff)
		}
	}
}
