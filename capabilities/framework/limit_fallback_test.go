package framework

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/settings"
)

type getterFunc func(ctx context.Context, scope settings.Scope, key string) (string, error)

func (f getterFunc) GetScoped(ctx context.Context, scope settings.Scope, key string) (string, error) {
	return f(ctx, scope, key)
}

func TestResolveWithFallback(t *testing.T) {
	var s struct {
		Shared   settings.Setting[int]
		Specific settings.Setting[int]
	}
	s.Shared = settings.Int(1)
	s.Specific = settings.Int(2)
	require.NoError(t, settings.InitConfig(&s))

	getter := func(t *testing.T, json string) settings.Getter {
		g, err := settings.NewJSONGetter([]byte(json))
		require.NoError(t, err)
		return g
	}

	for _, tt := range []struct {
		name     string
		specific settings.Setting[int]
		getter   settings.Getter
		want     int
	}{
		{"specific unset uses the shared value", s.Specific, getter(t, `{"global":{"Shared":"4"}}`), 4},
		{"specific set wins", s.Specific, getter(t, `{"global":{"Shared":"4","Specific":"7"}}`), 7},
		{"neither set uses the shared default", s.Specific, getter(t, `{}`), 1},
		{"nil getter uses the shared default", s.Specific, nil, 1},
		{"zero specific is unset", settings.Setting[int]{}, getter(t, `{"global":{"Shared":"4","Specific":"7"}}`), 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveWithFallback(t.Context(), tt.getter, tt.specific, s.Shared)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("lookup error returns the shared default", func(t *testing.T) {
		wantErr := errors.New("lookup failed")
		g := getterFunc(func(context.Context, settings.Scope, string) (string, error) { return "", wantErr })
		got, err := resolveWithFallback(t.Context(), g, s.Specific, s.Shared)
		require.ErrorIs(t, err, wantErr)
		assert.Equal(t, 1, got)
	})

	t.Run("parse error returns the shared default", func(t *testing.T) {
		got, err := resolveWithFallback(t.Context(), getter(t, `{"global":{"Specific":"nope"}}`), s.Specific, s.Shared)
		require.Error(t, err)
		assert.Equal(t, 1, got)
	})
}
