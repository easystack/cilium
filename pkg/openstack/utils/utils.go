// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

const eniIndexTagKey = "cilium-eni-index"

func IsExcludedByTags(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, eniIndexTagKey) {
			return false
		}
	}
	logrus.Errorf("Unable to retrieve index tag from ENI")
	return true
}

// GetENIIndexFromTags get ENI index from tags
func GetENIIndexFromTags(tags []string) int {
	logrus.Errorf("############# tags is %s", tags)
	for _, str := range tags {
		if strings.HasPrefix(str, eniIndexTagKey) {
			result := strings.Split(str, ":")
			if len(result) == 2 {
				index, err := strconv.Atoi(result[1])
				if err != nil {
					logrus.WithError(err).Warning("Unable to retrieve index from ENI")
					return 0
				}
				return index
			}
			break
		}
	}
	logrus.Errorf("Unable to retrieve index from ENI")
	return 0
}

// FillTagWithENIIndex set the index to tags
func FillTagWithENIIndex(index int) string {
	return fmt.Sprintf("%s:%d", eniIndexTagKey, index)
}

func GetMaxIpsFromCIDR(cidr string) (int, error) {
	splits := strings.Split(cidr, "/")
	if len(splits) != 2 {
		return 0, errors.New("bad cidr string")
	}
	maskBit, err := strconv.Atoi(splits[1])
	if err != nil {
		return 0, errors.New("bad cidr string")
	}

	return 1<<(32-maskBit) - 2, nil
}
