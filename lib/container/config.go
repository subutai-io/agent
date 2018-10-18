package container

import (
	"io/ioutil"
	"strings"
)

type LxcConfig struct {
	params []string
	path   string
}

func SetConfig(path string, params [][]string) error {
	cfg := LxcConfig{}
	err := cfg.Load(path)
	if err != nil {
		return err
	}

	cfg.SetParams(params)

	return cfg.Save()
}

func GetConfig(path string) (LxcConfig, error) {
	cfg := LxcConfig{}

	err := cfg.Load(path)

	return cfg, err
}

func (c *LxcConfig) Load(path string) error {
	c.path = path

	bytes, err := ioutil.ReadFile(path)

	if err != nil {
		return err
	}

	c.params = strings.Split(string(bytes), "\n")

	return nil
}

func (c *LxcConfig) GetParam(paramName string) string {
	paramName = strings.TrimSpace(paramName)

	if paramName == "" {
		return ""
	}

	for _, param := range c.params {
		kv := strings.Split(param, "=")
		if len(kv) > 0 && strings.EqualFold(strings.TrimSpace(kv[0]), paramName) {
			return strings.TrimSpace(kv[1])
		}
	}

	return ""
}

func (c *LxcConfig) SetParams(params [][]string) {

	//remove old parameters with matching names
	skip := make(map[string]bool)
	for i := len(params) - 1; i >= 0; i-- {
		newParam := params[i]

		if len(newParam) > 0 {
			newKey := strings.TrimSpace(newParam[0])
			if skip[newKey] {
				continue
			}
			skip[newKey] = true

			for j := len(c.params) - 1; j >= 0; j-- {
				oldParam := strings.Split(c.params[j], "=")

				if len(oldParam) > 0 {
					oldKey := strings.TrimSpace(oldParam[0])

					if strings.EqualFold(newKey, oldKey) {
						//remove value
						c.params = append(c.params[:j], c.params[j+1:]...)
					}
				}
			}
		}
	}

	//add new parameters with non-empty values
	for i := len(params) - 1; i >= 0; i-- {
		newParam := params[i]

		if len(newParam) > 1 {
			newKey := strings.TrimSpace(newParam[0])
			newValue := strings.TrimSpace(newParam[1])

			if newKey != "" && newValue != "" {
				c.params = append(c.params, newKey+"="+newValue)
			}
		}
	}

}

func (c *LxcConfig) Save() error {

	//remove comments and empty lines
	for i := len(c.params) - 1; i >= 0; i-- {
		param := strings.Split(c.params[i], "=")

		if len(param) < 2 {
			c.params = append(c.params[:i], c.params[i+1:]...)
		}

	}

	return ioutil.WriteFile(c.path,
		[]byte(strings.Join(c.params, "\n")), 0644)
}
