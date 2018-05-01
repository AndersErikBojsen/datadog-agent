// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

// +build !windows

package encryptedsecret

import (
	"fmt"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

var secretCache map[string]string

func init() {
	secretCache = make(map[string]string)
}

type walkerCallback func(string) (string, error)

func walkSlice(data []interface{}, callback walkerCallback) error {
	for idx, k := range data {
		if v, ok := k.(string); ok {
			if newValue, err := callback(v); err != nil {
				return err
			} else {
				data[idx] = newValue
			}
		}
		if v, ok := k.(map[interface{}]interface{}); ok {
			if err := walkHash(v, callback); err != nil {
				return err
			}
		}
		if v, ok := k.([]interface{}); ok {
			if err := walkSlice(v, callback); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkHash(data map[interface{}]interface{}, callback walkerCallback) error {
	for k := range data {
		if v, ok := data[k].(string); ok {
			if newValue, err := callback(v); err != nil {
				return err
			} else {
				data[k] = newValue
			}
		}
		if v, ok := data[k].(map[interface{}]interface{}); ok {
			if err := walkHash(v, callback); err != nil {
				return err
			}
		}
		if v, ok := data[k].([]interface{}); ok {
			if err := walkSlice(v, callback); err != nil {
				return err
			}
		}
	}
	return nil
}

// walk will go through loaded yaml and call callback on every strings allowing
// the callback to overwrite the string value
func walk(data *interface{}, callback walkerCallback) error {
	if v, ok := (*data).(string); ok {
		if newValue, err := callback(v); err != nil {
			return err
		} else {
			*data = newValue
		}
	}
	if v, ok := (*data).(map[interface{}]interface{}); ok {
		return walkHash(v, callback)
	}
	if v, ok := (*data).([]interface{}); ok {
		return walkSlice(v, callback)
	}
	return nil
}

func isEnc(str string) (bool, string) {
	str = strings.Trim(str, " 	")
	if strings.HasPrefix(str, "ENC[") && strings.HasSuffix(str, "]") {
		return true, str[4 : len(str)-1]
	}
	return false, ""
}

// testing purpose
var secretFetcher = fetchSecret

func DecryptSecret(data []byte) ([]byte, error) {
	var config interface{}
	err := yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("Could not Unmarshal config: %s", err)
	}

	// First we collect all passwords in the config
	handles := []string{}
	err = walk(&config, func(str string) (string, error) {
		if ok, handle := isEnc(str); ok {
			// We already know this secret
			if secret, ok := secretCache[handle]; ok {
				return secret, nil
			}
			handles = append(handles, handle)
		}
		return str, nil
	})
	if err != nil {
		return nil, err
	}

	if len(handles) != 0 {
		passwords, err := secretFetcher(handles)
		if err != nil {
			return nil, err
		}

		// Replace all encrypted passwords in the config
		err = walk(&config, func(str string) (string, error) {
			if ok, handle := isEnc(str); ok {
				if secret, ok := passwords[handle]; ok {
					return secret, nil
				}
			}
			return str, nil
		})
		if err != nil {
			return nil, err
		}
	}

	finalConfig, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("Could not Marshal config after replace encrypted secrets: %s", err)
	}
	return finalConfig, nil
}
