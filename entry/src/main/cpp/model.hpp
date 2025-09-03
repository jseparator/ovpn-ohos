//
// Created on 2024/11/23.
//
// OpenHarmonyOS VpnConfig

#ifndef VPNCLI_MODEL_H
#define VPNCLI_MODEL_H

#include <string>
#include <json/json.h>

struct NetAddress {
    std::string address;
    int family = 1; // Address family identifier. The value is 1 for IPv4 and 2 for IPv6. The default value is 1.
    int port = 0;   // Port number. The value ranges from 0 to 65535.
};

struct LinkAddress {
    NetAddress address;
    int prefixLength;
};

struct RouteInfo {
//     std::string interface; // Network card name.
    LinkAddress destination;
    NetAddress gateway;
    bool hasGateway;
    bool isDefaultRoute;
};

struct VpnConfig {
    std::vector<LinkAddress> addresses;     // {Array<LinkAddress>}
    std::vector<RouteInfo> routes;          // {?Array<RouteInfo>}
    std::vector<std::string> dnsAddresses;  // {?Array<string>}
    std::vector<std::string> searchDomains; // {?Array<string>}
    int mtu = 1500; // 1400
};

// Function to convert a LinkAddress to Json
Json::Value linkAddressToJson(const LinkAddress &linkAddress) {
    Json::Value json;
    json["address"]["address"] = linkAddress.address.address;
    json["address"]["family"] = linkAddress.address.family;
//     json["address"]["port"] = linkAddress.address.port;
    json["prefixLength"] = linkAddress.prefixLength;
    return json;
}

// Function to convert a RouteInfo to Json
Json::Value routeInfoToJson(const RouteInfo &routeInfo) {
    Json::Value json;
//     json["interface"] = routeInfo.interface;
    json["destination"] = linkAddressToJson(routeInfo.destination);
    json["gateway"]["address"] = routeInfo.gateway.address;
    json["gateway"]["family"] = routeInfo.gateway.family;
//     json["gateway"]["port"] = routeInfo.gateway.port;
//     json["hasGateway"] = routeInfo.hasGateway;
//     json["isDefaultRoute"] = routeInfo.isDefaultRoute;
    return json;
}

// Function to convert a VpnConfig to Json
Json::Value vpnConfigToJson(const VpnConfig &vpnConfig) {
    Json::Value json;
    // Convert addresses
    for (const auto &address : vpnConfig.addresses) {
        json["addresses"].append(linkAddressToJson(address));
    }
    // Convert routes
    for (const auto &route : vpnConfig.routes) {
        json["routes"].append(routeInfoToJson(route));
    }
    // Convert DNS addresses
    for (const auto &dns : vpnConfig.dnsAddresses) {
        json["dnsAddresses"].append(dns);
    }
    // Convert search domains
    for (const auto &searchDomain : vpnConfig.searchDomains) {
        json["searchDomains"].append(searchDomain);
    }
    // Set mtu
    json["mtu"] = vpnConfig.mtu;
    return json;
}

#endif
