/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

// Modified from https://github.com/v2fly/v2ray-core/blob/42b166760b2ba8d984e514b830fcd44e23728e43/infra/conf/geodata/memconservative

package geodata

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"os"
	"strings"
)

func UnmarshalGeoIp(log *logrus.Logger, filepath, code string) (*GeoIP, error) {
	geoipBytes, err := Decode(filepath, code)
	switch err {
	case nil:
		var geoip GeoIP
		if err := proto.Unmarshal(geoipBytes, &geoip); err != nil {
			return nil, err
		}
		return &geoip, nil

	case errCodeNotFound:
		return nil, fmt.Errorf("country code %v not found in %v", code, filepath)

	case errFailedToReadBytes, errFailedToReadExpectedLenBytes,
		errInvalidGeodataFile, errInvalidGeodataVarintLength:
		log.Warnln("failed to decode geoip file: ", filepath, ", fallback to the original ReadFile method")
		geoipBytes, err = os.ReadFile(filepath)
		if err != nil {
			return nil, err
		}
		var geoipList GeoIPList
		if err := proto.Unmarshal(geoipBytes, &geoipList); err != nil {
			return nil, err
		}
		for _, geoip := range geoipList.GetEntry() {
			if strings.EqualFold(code, geoip.GetCountryCode()) {
				return geoip, nil
			}
		}

	default:
		return nil, err
	}

	return nil, fmt.Errorf("country code %v not found in %v", code, filepath)
}

func UnmarshalGeoSite(log *logrus.Logger, filepath, code string) (*GeoSite, error) {
	geositeBytes, err := Decode(filepath, code)
	switch err {
	case nil:
		var geosite GeoSite
		if err := proto.Unmarshal(geositeBytes, &geosite); err != nil {
			return nil, err
		}
		return &geosite, nil

	case errCodeNotFound:
		return nil, fmt.Errorf("list %V not found in %v", code, filepath)

	case errFailedToReadBytes, errFailedToReadExpectedLenBytes,
		errInvalidGeodataFile, errInvalidGeodataVarintLength:
		log.Warnln("failed to decode geoip file: ", filepath, ", fallback to the original ReadFile method")
		geositeBytes, err = os.ReadFile(filepath)
		if err != nil {
			return nil, err
		}
		var geositeList GeoSiteList
		if err := proto.Unmarshal(geositeBytes, &geositeList); err != nil {
			return nil, err
		}
		for _, geosite := range geositeList.GetEntry() {
			if strings.EqualFold(code, geosite.GetCountryCode()) {
				return geosite, nil
			}
		}

	default:
		return nil, err
	}

	return nil, fmt.Errorf("list %v not found in %v", code, filepath)
}
