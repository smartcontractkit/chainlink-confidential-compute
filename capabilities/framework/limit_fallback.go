package framework

import (
	"context"

	"github.com/smartcontractkit/chainlink-common/pkg/settings"
)

// resolveWithFallback returns specific when it is set in g, otherwise shared.
// When neither is set it returns shared's default. A specific setting without a
// Key counts as unset. On a lookup or parse error it returns shared's default
// and the error.
func resolveWithFallback[T any](ctx context.Context, g settings.Getter, specific, shared settings.Setting[T]) (T, error) {
	if g != nil && specific.Key != "" {
		str, err := g.GetScoped(ctx, specific.Scope, specific.Key)
		if err != nil {
			return shared.DefaultValue, err
		}
		if str != "" {
			value, err := specific.Parse(str)
			if err != nil {
				return shared.DefaultValue, err
			}
			return value, nil
		}
	}
	return shared.GetOrDefault(ctx, g)
}
