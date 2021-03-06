/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metadata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"git.openstack.org/openstack/openstack-cloud-controller-manager/pkg/flexvolume/knownflags"
)

// MapToJson converts the specified map object to indented JSON.
// It panics in case if the map connot be converted.
func MapToJson(m map[string]interface{}) string {
	bs, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Panicf("error marshalling json: %v", err)
	}
	return string(bs)
}

// MapToJson converts the specified map object to unindented JSON.
// It panics in case if the map connot be converted.
func MapToJsonUnindented(m map[string]interface{}) string {
	bs, err := json.Marshal(m)
	if err != nil {
		log.Panicf("error marshalling json: %v", err)
	}
	return string(bs)
}

func ReadJson(filename string, v interface{}) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading json file %q: %v", filename, err)
	}

	if err := json.Unmarshal(content, v); err != nil {
		return fmt.Errorf("failed to parse json file %q: %v", filename, err)
	}

	return nil
}

func WriteJson(filename string, v interface{}, perm os.FileMode) error {
	content, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("couldn't marshal the data to JSON for %q: %v", filename, err)
	}
	if err := ioutil.WriteFile(filename, content, perm); err != nil {
		return fmt.Errorf("error writing JSON data file %q: %v", filename, err)
	}
	return nil
}

func WriteJsonOptsFile(targetDir string, opts map[string]interface{}) error {
	return WriteJson(filepath.Join(targetDir, knownflags.FlexvolumeDataFile), opts, 0700)
}

func ReadJsonOptsFile(targetDir string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := ReadJson(filepath.Join(targetDir, knownflags.FlexvolumeDataFile), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func CleanUpMetadataFile(targetDir string) error {
	metadataFile := filepath.Join(targetDir, knownflags.FlexvolumeDataFile)
	if err := os.Remove(metadataFile); err != nil {
		return fmt.Errorf("removing metadata file: %v failed: %v", metadataFile, err)
	}
	return nil
}
