package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

// IMP: https://dave.cheney.net/2019/05/07/prefer-table-driven-tests

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - missing token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey mysecretkey"},
			},
			wantKey: "mysecretkey",
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		gotKey, gotErr := GetAPIKey(tc.headers)

		if !reflect.DeepEqual(gotKey, tc.wantKey) {
			t.Errorf("expected: %v, got: %v", tc.wantKey, gotKey)
		}

		if (gotErr == nil && tc.wantErr != nil) ||
			(gotErr != nil && tc.wantErr == nil) ||
			(gotErr != nil && tc.wantErr != nil && gotErr.Error() != tc.wantErr.Error()) {
			t.Errorf("expected err %v, got %v", tc.wantErr, gotErr)
		}

	}
}
