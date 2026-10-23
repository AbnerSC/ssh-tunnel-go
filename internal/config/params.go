package config

import (
	"fmt"
	"strconv"
)

// ParamFormat 复刻 Java 版参数解析语义：
//   - 以 "-" 开头的 token 视为参数名，其后首个 token 视为该参数的取值；
//   - 同名参数重复出现时取值累积（单值读取取第一个）；
//   - 参数名后没有取值也是合法的（仅表示该开关被打开）。
//
// 与 Java 版唯一的差异：多余的无归属 token 会被忽略，而不是抛空指针异常。
type ParamFormat struct {
	values map[string][]string
}

// ParseParams 解析命令行参数。
func ParseParams(args []string) *ParamFormat {
	p := &ParamFormat{values: make(map[string][]string)}
	var last string
	pending := false
	for _, arg := range args {
		if len(arg) > 0 && arg[0] == '-' {
			if pending {
				p.values[last] = nil
			}
			last = arg
			pending = true
			continue
		}
		if pending {
			p.values[last] = append(p.values[last], arg)
			pending = false
		}
	}
	if pending {
		p.values[last] = nil
	}
	return p
}

// Contains 参数是否出现过（即使没有取值）。
func (p *ParamFormat) Contains(key string) bool {
	_, ok := p.values[key]
	return ok
}

// Value 返回参数的第一个取值；参数未出现或没有取值时返回 false。
func (p *ParamFormat) Value(key string) (string, bool) {
	list := p.values[key]
	if len(list) == 0 {
		return "", false
	}
	return list[0], true
}

// ValueOr 返回参数的第一个取值，缺省时返回 def。
func (p *ParamFormat) ValueOr(key, def string) string {
	if v, ok := p.Value(key); ok {
		return v
	}
	return def
}

// Values 返回参数的全部取值。
func (p *ParamFormat) Values(key string) []string {
	list := p.values[key]
	if len(list) == 0 {
		return nil
	}
	out := make([]string, len(list))
	copy(out, list)
	return out
}

// Resolver 统一处理配置来源：环境变量优先，命令行参数补充。
//
// 与 Java 版容器入口脚本的实际效果保持一致：脚本把环境变量放在命令行参数之前，
// 而单值参数取第一个出现的值，因此环境变量优先；列表参数（直连规则）两者合并。
type Resolver struct {
	params *ParamFormat
	env    func(string) (string, bool)
}

// NewResolver 创建配置解析器。
func NewResolver(args []string) *Resolver {
	return &Resolver{
		params: ParseParams(args),
		env:    lookupEnv,
	}
}

func lookupEnv(key string) (string, bool) {
	v, ok := envLookup(key)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// Has 参数或对应环境变量是否配置。
func (r *Resolver) Has(flag, env string) bool {
	if _, ok := r.env(env); ok {
		return true
	}
	return r.params.Contains(flag)
}

// Value 返回单值配置：环境变量优先，其次命令行，均未配置时返回 def。
func (r *Resolver) Value(flag, env, def string) string {
	if v, ok := r.env(env); ok {
		return v
	}
	if v, ok := r.params.Value(flag); ok {
		return v
	}
	return def
}

// Values 返回列表配置：环境变量值在前，命令行取值依次追加。
func (r *Resolver) Values(flag, env string) []string {
	var out []string
	if v, ok := r.env(env); ok {
		out = append(out, v)
	}
	return append(out, r.params.Values(flag)...)
}

// Int 解析整型配置。
func (r *Resolver) Int(flag, env string, def int) (int, error) {
	if !r.Has(flag, env) {
		return def, nil
	}
	v := r.Value(flag, env, "")
	if v == "" {
		return 0, fmt.Errorf("参数 %s 缺少取值", flag)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("参数 %s 取值非法: %q", flag, v)
	}
	return n, nil
}
