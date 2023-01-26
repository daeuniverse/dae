package config

import (
	"fmt"
	"github.com/spf13/viper"
	"reflect"
	"strconv"
	"strings"
)

var (
	ErrRequired               = fmt.Errorf("required")
	ErrMutualReference        = fmt.Errorf("mutual reference or invalid value")
	ErrOverlayHierarchicalKey = fmt.Errorf("overlay hierarchical key")
)

type Binder struct {
	viper     *viper.Viper
	toResolve map[string]string
	resolved  map[string]interface{}
}

func MustGetMapKeys(m interface{}) (keys []string) {
	v := reflect.ValueOf(m)
	vKeys := v.MapKeys()
	for _, k := range vKeys {
		keys = append(keys, k.String())
	}
	return keys
}

func NewBinder(viper *viper.Viper) *Binder {
	return &Binder{
		viper:     viper,
		toResolve: make(map[string]string),
		resolved:  make(map[string]interface{}),
	}
}

func (b *Binder) Bind(iface interface{}) error {
	if err := b.bind(iface); err != nil {
		return err
	}
	for len(b.toResolve) > 0 {
		var changed bool
		for key, expr := range b.toResolve {
			ok, err := b.bindKey(key, expr)
			if err != nil {
				return err
			}
			if ok {
				changed = true
				if err := SetValueHierarchicalMap(b.resolved, key, b.viper.Get(key)); err != nil {
					return fmt.Errorf("%w: %v", err, key)
				}
				delete(b.toResolve, key)
			}
		}
		if !changed {
			return fmt.Errorf("%v: %w", strings.Join(MustGetMapKeys(b.toResolve), ", "), ErrMutualReference)
		}
	}
	return nil
}

func (b *Binder) bind(iface interface{}, parts ...string) error {
	// https://github.com/spf13/viper/issues/188
	ifv := reflect.ValueOf(iface)
	ift := reflect.TypeOf(iface)
nextField:
	for i := 0; i < ift.NumField(); i++ {
		v := ifv.Field(i)
		t := ift.Field(i)
		tv, ok := t.Tag.Lookup("mapstructure")
		if !ok {
			continue
		}
		fields := strings.Split(tv, ",")
		tv = fields[0]
		switch v.Kind() {
		case reflect.Struct:
			if err := b.bind(v.Interface(), append(parts, tv)...); err != nil {
				return err
			}
		default:
			key := strings.Join(append(parts, tv), ".")
			if b.viper.Get(key) == nil {
				if defaultValue, ok := t.Tag.Lookup("default"); ok {
					ok, err := b.bindKey(key, defaultValue)
					if err != nil {
						return err
					}
					if !ok {
						b.toResolve[key] = defaultValue
						continue nextField
					}
				} else if _, ok := t.Tag.Lookup("required"); ok {
					if desc, ok := t.Tag.Lookup("desc"); ok {
						key += " (" + desc + ")"
					}
					return fmt.Errorf("%w: %v", ErrRequired, key)
				} else if len(fields) == 1 || fields[1] != "omitempty" {
					// write an empty value
					b.viper.Set(key, "")
				}
			}
			if err := SetValueHierarchicalMap(b.resolved, key, b.viper.Get(key)); err != nil {
				return fmt.Errorf("%w: %v", err, key)
			}
		}
	}
	return nil
}

func (b *Binder) bindKey(key string, expr string) (ok bool, err error) {
	b.viper.Set(key, expr)
	return true, nil
}

func SetValueHierarchicalMap(m map[string]interface{}, key string, val interface{}) error {
	keys := strings.Split(key, ".")
	lastKey := keys[len(keys)-1]
	keys = keys[:len(keys)-1]
	p := &m
	for _, key := range keys {
		if v, ok := (*p)[key]; ok {
			vv, ok := v.(map[string]interface{})
			if !ok {
				return ErrOverlayHierarchicalKey
			}
			p = &vv
		} else {
			(*p)[key] = make(map[string]interface{})
			vv := (*p)[key].(map[string]interface{})
			p = &vv
		}
	}
	(*p)[lastKey] = val
	return nil
}

func SetValueHierarchicalStruct(m interface{}, key string, val string) error {
	ifv, err := GetValueHierarchicalStruct(m, key)
	if err != nil {
		return err
	}
	if !FuzzyDecode(ifv.Addr().Interface(), val) {
		return fmt.Errorf("type does not match: type \"%v\" and value \"%v\"", ifv.Kind(), val)
	}
	return nil
}

func GetValueHierarchicalStruct(m interface{}, key string) (reflect.Value, error) {
	keys := strings.Split(key, ".")
	ifv := reflect.Indirect(reflect.ValueOf(m))
	ift := ifv.Type()
	lastK := ""
	for _, k := range keys {
		found := false
		if ift.Kind() == reflect.Struct {
			for i := 0; i < ifv.NumField(); i++ {
				name, ok := ift.Field(i).Tag.Lookup("mapstructure")
				if ok && name == k {
					found = true
					ifv = ifv.Field(i)
					ift = ifv.Type()
					lastK = k
					break
				}
			}
		}
		if !found {
			return reflect.Value{}, fmt.Errorf(`unexpected key "%v": "%v" (%v type) has no member "%v"`, key, lastK, ift.Kind().String(), k)
		}
	}
	return ifv, nil
}

func FuzzyDecode(to interface{}, val string) bool {
	v := reflect.Indirect(reflect.ValueOf(to))
	switch v.Kind() {
	case reflect.Int:
		i, err := strconv.ParseInt(val, 10, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int8:
		i, err := strconv.ParseInt(val, 10, 8)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int16:
		i, err := strconv.ParseInt(val, 10, 16)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int32:
		i, err := strconv.ParseInt(val, 10, 32)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int64:
		i, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Uint:
		i, err := strconv.ParseUint(val, 10, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint8:
		i, err := strconv.ParseUint(val, 10, 8)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint16:
		i, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint32:
		i, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint64:
		i, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Bool:
		if val == "true" || val == "1" {
			v.SetBool(true)
		} else if val == "false" || val == "0" {
			v.SetBool(false)
		} else {
			return false
		}
	case reflect.String:
		v.SetString(val)
	}
	return true
}
