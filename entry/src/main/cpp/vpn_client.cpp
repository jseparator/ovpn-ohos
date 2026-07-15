/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <napi/native_api.h>
#include <hilog/log.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <js_native_api.h>
#include <js_native_api_types.h>
#include <client/ovpncli.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include "model.hpp"
#include <json/json.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') + 1)

#define NETMANAGER_VPN_LOGE(fmt, ...)                                                                                  \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b0, "NetMgrVpn", "vpn [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,          \
                 __LINE__, ##__VA_ARGS__)

#define NETMANAGER_VPN_LOGI(fmt, ...)                                                                                  \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b0, "NetMgrVpn", "vpn [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, \
                 ##__VA_ARGS__)

#define NETMANAGER_VPN_LOGD(fmt, ...)                                                                                  \
    OH_LOG_Print(LOG_APP, LOG_DEBUG, 0x15b0, "NetMgrVpn", "vpn [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,          \
                 __LINE__, ##__VA_ARGS__)

napi_ref cb_protect_ref = nullptr;
napi_ref cb_tun_ref = nullptr;
napi_ref cb_connected_ref = nullptr;
napi_ref cb_stats_ref = nullptr;
napi_ref cb_exit_ref = nullptr;
napi_threadsafe_function tsfn_protect = nullptr;
napi_threadsafe_function tsfn_tun = nullptr;
napi_threadsafe_function tsfn_connected = nullptr;
napi_threadsafe_function tsfn_stats = nullptr;
napi_threadsafe_function tsfn_exit = nullptr;

int tun_fd = -1;
bool tun_done = false;
std::mutex tun_mtx;
std::condition_variable tun_cv;
int established_tun_fd = -1; // reuse across OpenVPN reconnect (tunPersist)

bool protect_done = false;
bool protect_ok = false;
std::mutex protect_mtx;
std::condition_variable protect_cv;
std::mutex protect_call_mtx; // serialize socket_protect end-to-end

std::string files_dir;
std::atomic<bool> vpn_running{false};

static void NotifyTunDone(int fd) {
    std::unique_lock<std::mutex> lock(tun_mtx);
    tun_fd = fd;
    tun_done = true;
    tun_cv.notify_all();
}

static void NotifyProtectDone(bool ok) {
    std::unique_lock<std::mutex> lock(protect_mtx);
    protect_ok = ok;
    protect_done = true;
    protect_cv.notify_all();
}

napi_value ArkTsTunCallBack(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value v;
    napi_get_cb_info(env, info, &argc, &v, nullptr, nullptr);

    int32_t fd = -1;
    if (argc >= 1 && v != nullptr) {
        napi_get_value_int32(env, v, &fd);
    }
    NETMANAGER_VPN_LOGI("TunThenFinished, %{public}d", fd);
    NotifyTunDone(fd);
    return nullptr;
}

napi_value ArkTsProtectCallBack(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    // then() with no useful value => success; catch passes error
    NotifyProtectDone(true);
    return nullptr;
}

void call_js_tun(napi_env env, napi_value js_cb, void *context, void *data) {
    napi_get_reference_value(env, cb_tun_ref, &js_cb);
    auto v = static_cast<std::string *>(data);

    napi_value cfg, promise;
    napi_create_string_utf8(env, v->c_str(), v->length(), &cfg);
    napi_status st = napi_call_function(env, nullptr, js_cb, 1, &cfg, &promise);
    if (st != napi_ok || promise == nullptr) {
        NETMANAGER_VPN_LOGE("tun callback invoke failed: %{public}d", static_cast<int>(st));
        NotifyTunDone(-1);
        return;
    }

    napi_valuetype ptype = napi_undefined;
    napi_typeof(env, promise, &ptype);
    if (ptype != napi_object) {
        // Sync number return
        int32_t fd = -1;
        napi_get_value_int32(env, promise, &fd);
        NotifyTunDone(fd);
        return;
    }

    napi_value thenProperty = nullptr;
    napi_get_named_property(env, promise, "then", &thenProperty);
    napi_value thenCallback = nullptr;
    napi_create_function(env, "thenCallback", NAPI_AUTO_LENGTH, ArkTsTunCallBack, nullptr, &thenCallback);

    napi_value catchProperty = nullptr;
    napi_get_named_property(env, promise, "catch", &catchProperty);
    napi_value catchCallback = nullptr;
    napi_create_function(
        env, "catchCallback", NAPI_AUTO_LENGTH,
        [](napi_env env, napi_callback_info info) -> napi_value {
            size_t argc = 1;
            napi_value args[1] = {nullptr};
            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            size_t strLen = 0;
            if (argc >= 1 && args[0] != nullptr) {
                napi_get_value_string_utf8(env, args[0], nullptr, 0, &strLen);
                if (strLen > 0 && strLen < 4096) {
                    char *strBuffer = new char[strLen + 1];
                    napi_get_value_string_utf8(env, args[0], strBuffer, strLen + 1, &strLen);
                    NETMANAGER_VPN_LOGE("ArkTS Tun Exception: %{public}s", strBuffer);
                    delete[] strBuffer;
                }
            }
            // Must unblock tun_builder_establish — previously this path deadlocked.
            NotifyTunDone(-1);
            return nullptr;
        },
        nullptr, &catchCallback);

    napi_call_function(env, promise, thenProperty, 1, &thenCallback, nullptr);
    napi_call_function(env, promise, catchProperty, 1, &catchCallback, nullptr);
}

void call_js_protect(napi_env env, napi_value js_cb, void *context, void *data) {
    napi_get_reference_value(env, cb_protect_ref, &js_cb);
    auto socket = static_cast<openvpn_io::detail::socket_type *>(data);
    napi_value argv;
    napi_create_int32(env, static_cast<int32_t>(*socket), &argv);
    delete socket;

    napi_value result = nullptr;
    napi_status st = napi_call_function(env, nullptr, js_cb, 1, &argv, &result);
    if (st != napi_ok) {
        NETMANAGER_VPN_LOGE("protect callback invoke failed: %{public}d", static_cast<int>(st));
        NotifyProtectDone(false);
        return;
    }

    if (result == nullptr) {
        // Fire-and-forget void callback — treat as started; wait briefly via done flag set in then if promise
        NotifyProtectDone(true);
        return;
    }

    napi_valuetype rtype = napi_undefined;
    napi_typeof(env, result, &rtype);
    if (rtype != napi_object) {
        NotifyProtectDone(true);
        return;
    }

    napi_value thenProperty = nullptr;
    napi_get_named_property(env, result, "then", &thenProperty);
    napi_value thenCallback = nullptr;
    napi_create_function(env, "protectThen", NAPI_AUTO_LENGTH, ArkTsProtectCallBack, nullptr, &thenCallback);

    napi_value catchProperty = nullptr;
    napi_get_named_property(env, result, "catch", &catchProperty);
    napi_value catchCallback = nullptr;
    napi_create_function(
        env, "protectCatch", NAPI_AUTO_LENGTH,
        [](napi_env env, napi_callback_info info) -> napi_value {
            NETMANAGER_VPN_LOGE("ArkTS Protect Exception");
            NotifyProtectDone(false);
            return nullptr;
        },
        nullptr, &catchCallback);

    napi_call_function(env, result, thenProperty, 1, &thenCallback, nullptr);
    napi_call_function(env, result, catchProperty, 1, &catchCallback, nullptr);
}

static int g_vpnNetId;

class Client : public openvpn::ClientAPI::OpenVPNClient {
private:
    VpnConfig tun;
    NetAddress tun_gw; // gateway
    std::vector<std::string> tun_proxy_bypasses;
//     NetConn_HttpProxy tun_proxy_http;
    std::string tun_proxy_auto_config_url;
    std::string tun_proxy_host;
    int tun_proxy_port;
    std::ofstream logFd;

public:
    ~Client() {
        if (logFd.is_open()) {
            logFd.close();
        }
        this->stop();
    }

    virtual bool pause_on_connection_timeout() override { return false; }

    virtual void event(const openvpn::ClientAPI::Event &e) override { // events delivered here
        NETMANAGER_VPN_LOGI("ovpn event, name: %{public}s, info: %{public}s", e.name.c_str(), e.info.c_str());
        if (e.name == "CONNECTED") {
            /*
            if (this->tun_proxy_http.port > 0) {
                std::vector<std::string> exs;
                exs.push_back("192.168");
                exs.push_back("10.");
                exs.push_back("adt-");
                exs.push_back("oks-");
                for (int i = 0, j = exs.size(); i < j; i++) {
                    auto ex = exs.at(i);
                    ex.copy(this->tun_proxy_http.exclusionList[i], ex.size());
                    this->tun_proxy_http.exclusionListSize++;
                }
                auto err = OH_NetConn_SetAppHttpProxy(&this->tun_proxy_http);
                if (err != 0) {
                    NETMANAGER_VPN_LOGE("ovpn SetAppHttpProxyErr: %{public}d, %{public}s:%{public}d", err,
                                        this->tun_proxy_http.host, this->tun_proxy_http.port);
                }
            }
            NetConn_NetHandleList ns;
            OH_NetConn_GetAllNets(&ns);
            for (int i = 0; i < ns.netHandleListSize; i++) {
                auto n = &ns.netHandles[i];
                NetConn_NetCapabilities nc;
                OH_NetConn_GetNetCapabilities(n, &nc);
                bool is_vpn;
                for (int j = 0; j < nc.bearerTypesSize; j++) {
                    if (nc.bearerTypes[j] == NetConn_NetBearerType::NETCONN_BEARER_VPN) {
                        is_vpn = true;
                        break;
                    }
                }
                if (!is_vpn) {
                    continue;
                }
                g_vpnNetId = n->netId;
//                 NETMANAGER_VPN_LOGE("VpnNetHandle: %{public}d", g_vpnNetId);
//                 auto err = OHOS_NetConn_RegisterDnsResolver(CustomDnsResolver);
//                 if (err != 0) {
//                     NETMANAGER_VPN_LOGE("OHOS_NetConn_RegisterDnsResolverErr: %{public}d", err);
//                 }
//                 addrinfo *res, *cur;
//                 auto hint = addrinfo{.ai_family = AF_INET, .ai_flags = AI_PASSIVE, .ai_socktype = SOCK_DGRAM};
//                 auto err = OH_NetConn_GetAddrInfo("adt-admin", "", &hint, &res, n->netId);
//                 if (err != 0) {
//                     NETMANAGER_VPN_LOGE("OH_NetConn_GetAddrInfo failed with error: %d", err);
//                 } else {
//                     sockaddr_in *addr;
//                     char ipbuf[16];
//                     for (cur = res; cur != NULL; cur = cur->ai_next) {
//                         addr = (struct sockaddr_in *)cur->ai_addr;
//                         NETMANAGER_VPN_LOGE("OH_NetConn_GetAddrInfo: %{public}s", inet_ntop(AF_INET, &addr->sin_addr, ipbuf, 16));
//                     }
//                     OH_NetConn_FreeDnsResult(res);
//                 }
                break;
            }*/

            Json::Value json;
            json["info"] = e.info;
            json["pac"] = this->tun_proxy_auto_config_url;
            json["proxy"]["host"] = this->tun_proxy_host;
            json["proxy"]["port"] = this->tun_proxy_port;
            Json::StreamWriterBuilder writer;
            writer["indentation"] = ""; // Set the indentation to an empty string
            std::string v = Json::writeString(writer, json);
            auto info = new char[v.length() + 1];
            v.copy(info, v.length());
            info[v.length()] = '\0';

            if (!tsfn_connected || !vpn_running.load()) {
                delete[] info;
                return;
            }
            napi_status acq = napi_acquire_threadsafe_function(tsfn_connected);
            if (acq != napi_ok) {
                delete[] info;
                return;
            }
            napi_call_threadsafe_function(tsfn_connected, info, napi_tsfn_blocking);
        }
    }

    virtual void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &e) override {}

    virtual void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &) override {}

    virtual void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &) override {}

    virtual void clock_tick() override {
        if (!vpn_running.load()) {
            return;
        }
        if (!tsfn_stats && files_dir.empty()) {
            return;
        }
        openvpn::ClientAPI::TransportStats ts = this->transport_stats();
        openvpn::ClientAPI::InterfaceStats tun = this->tun_stats();
        long long bytesIn = std::max(ts.bytesIn, tun.bytesIn);
        long long bytesOut = std::max(ts.bytesOut, tun.bytesOut);
        char buf[128];
        std::snprintf(buf, sizeof(buf), "{\"bytesIn\":%lld,\"bytesOut\":%lld}", bytesIn, bytesOut);

        if (!tsfn_stats || !vpn_running.load()) {
            return;
        }
        char *heap = new char[strlen(buf) + 1];
        std::memcpy(heap, buf, strlen(buf) + 1);
        napi_status acq = napi_acquire_threadsafe_function(tsfn_stats);
        if (acq != napi_ok) {
            delete[] heap;
            return;
        }
        napi_status st = napi_call_threadsafe_function(tsfn_stats, heap, napi_tsfn_nonblocking);
        if (st != napi_ok) {
            delete[] heap;
            NETMANAGER_VPN_LOGD("stats tsfn call failed: %{public}d", static_cast<int>(st));
        }
    }

    virtual void log(const openvpn::ClientAPI::LogInfo &l) override { // logging delivered here
        NETMANAGER_VPN_LOGI("%{public}s", l.text.c_str());
        if (!logFd.is_open()) {
            logFd.open(files_dir + "/ovpn.log", std::ios::app);
            NETMANAGER_VPN_LOGI("%{public}s", "open ovpn.log");
        }

        auto now = std::time(nullptr);
        char buf[80];
        std::strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S] ", std::localtime(&now));
        logFd << buf << l.text;
        logFd.flush();
    }

    virtual bool socket_protect(openvpn_io::detail::socket_type socket, std::string remote, bool ipv6) override {
        NETMANAGER_VPN_LOGI("socket_protect: %{public}d %{public}s", socket, remote.c_str());
        if (!tsfn_protect || !vpn_running.load()) {
            return false;
        }
        // Browser / multi-socket reconnect can overlap protect calls — serialize fully.
        std::lock_guard<std::mutex> call_lock(protect_call_mtx);
        {
            std::unique_lock<std::mutex> lock(protect_mtx);
            protect_done = false;
            protect_ok = false;
        }
        auto fd = new openvpn_io::detail::socket_type(socket);
        napi_status acq = napi_acquire_threadsafe_function(tsfn_protect);
        if (acq != napi_ok) {
            delete fd;
            return false;
        }
        napi_status st = napi_call_threadsafe_function(tsfn_protect, fd, napi_tsfn_blocking);
        if (st != napi_ok) {
            delete fd;
            NETMANAGER_VPN_LOGE("protect tsfn call failed: %{public}d", static_cast<int>(st));
            return false;
        }
        std::unique_lock<std::mutex> lock(protect_mtx);
        if (!protect_cv.wait_for(lock, std::chrono::seconds(10), []() { return protect_done; })) {
            NETMANAGER_VPN_LOGE("socket_protect timeout");
            return false;
        }
        return protect_ok;
    }

    virtual bool tun_builder_new() override {
        // Reconnect rebuilds routes; must clear previous session state.
        this->tun = VpnConfig{};
        this->tun_gw = {};
        this->tun_proxy_bypasses.clear();
        this->tun_proxy_auto_config_url.clear();
        this->tun_proxy_host.clear();
        this->tun_proxy_port = 0;
        return true;
    }

    virtual bool tun_builder_set_layer(int layer) override { return true; }

    virtual bool tun_builder_set_remote_address(const std::string &address, bool ipv6) override {
        NETMANAGER_VPN_LOGI("tun_builder_set_remote_address: %{public}s", address.c_str());
        return true;
    }

    virtual bool tun_builder_add_address(const std::string &address, int prefix_length,
                                         const std::string &gateway, // optional
                                         bool ipv6, bool net30) override {
        NETMANAGER_VPN_LOGI("tun_builder_add_address: %{public}s, gateway: %{public}s", address.c_str(),
                            gateway.c_str());
        this->tun.addresses.push_back({
            .address = {.address = address, .family = ipv6 ? 2 : 1},
            .prefixLength = prefix_length,
        });
        this->tun_gw = {.address = gateway};

        this->tun.routes.push_back({
            .destination = {.address = {.address = gateway, .family = ipv6 ? 2 : 1}, .prefixLength = 24},
            .gateway = this->tun_gw,
            .hasGateway = true,
            .isDefaultRoute = true,
        });
        return true;
    }

    virtual bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override {
//          this->tun.routes.push_back(RouteInfo{
//             .destination = {.address = {.address = "1.0.0.0", .family = ipv4 ? 1 : 2}, .prefixLength = 24},
//             .gateway = this->tun_gw,
//             .hasGateway = true,
//             .isDefaultRoute = true,
//         });
        return true;
    }

    virtual bool tun_builder_add_route(const std::string &address, int prefix_length, int metric, bool ipv6) override {
        this->tun.routes.push_back(RouteInfo{
            .destination = {.address = {.address = address, .family = ipv6 ? 2 : 1}, .prefixLength = prefix_length},
            .gateway = this->tun_gw,
            .hasGateway = true,
            .isDefaultRoute = true,
        });
        return true;
    }
    
    virtual bool tun_builder_set_dns_options(const openvpn::DnsOptions &dns) override {
        for (const auto& v : dns.search_domains) {
            this->tun.searchDomains.push_back(v.domain);
        }
        for (const auto& pair : dns.servers) {
            for (const auto& v : pair.second.addresses) {
                this->tun.dnsAddresses.push_back(v.address);
            }
        }
        return true;
    }

//    virtual bool tun_builder_add_dns_server(const std::string &address, bool ipv6) override {
//        this->tun.dnsAddresses.push_back(address);
//        return true;
//    }

//    virtual bool tun_builder_add_dns_options(const openvpn::DnsOptions &dns) override { return true; }

//    virtual bool tun_builder_add_search_domain(const std::string &domain) override {
//        this->tun.searchDomains.push_back(domain);
//        return true;
//    }

    virtual bool tun_builder_set_mtu(int mtu) override {
        this->tun.mtu = mtu;
        return true;
    }

    virtual bool tun_builder_set_session_name(const std::string &name) override { return true; }

    // Callback to add a host which should bypass the proxy
    // May be called more than once per tun_builder session
    virtual bool tun_builder_add_proxy_bypass(const std::string &bypass_host) override {
//         this->tun_proxy_bypasses.push_back(bypass_host);
        return true;
    }

    // Callback to set the proxy "Auto Config URL"
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_auto_config_url(const std::string &url) override {
        this->tun_proxy_auto_config_url = url;
        return true;
    }

    // Callback to set the HTTP proxy
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_http(const std::string &host, int port) override {
        return tun_builder_set_proxy_https(host, port);
    }

    // Callback to set the HTTPS proxy
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_https(const std::string &host, int port) override {
//         host.copy(this->tun_proxy_http.host, host.length());
//         this->tun_proxy_http.host[host.length()] = 0;
//         this->tun_proxy_http.port = port;
        this->tun_proxy_host = host;
        this->tun_proxy_port = port;
        return true;
    }

    // Callback to establish the VPN tunnel, returning a file descriptor
    // to the tunnel, which the caller will henceforth own.  Returns -1
    // if the tunnel could not be established.
    // Always called last after tun_builder session has been configured.
    virtual int tun_builder_establish() override {
        // Reuse TUN across reconnects. Calling VpnConnection.create again would
        // tear down the system VPN session (status-bar icon disappears).
        if (established_tun_fd >= 0) {
            NETMANAGER_VPN_LOGI("tun_builder_establish reuse fd=%{public}d", established_tun_fd);
            return established_tun_fd;
        }

        Json::Value json = vpnConfigToJson(this->tun);
        Json::StreamWriterBuilder writer;
        writer["indentation"] = ""; // Set the indentation to an empty string
        std::string v = Json::writeString(writer, json);
        NETMANAGER_VPN_LOGI("tun_builder_establish: %{public}s", v.c_str());

        if (!tsfn_tun || !vpn_running.load()) {
            return -1;
        }

        {
            std::unique_lock<std::mutex> lock(tun_mtx);
            tun_fd = -1;
            tun_done = false;
        }

        napi_status acq = napi_acquire_threadsafe_function(tsfn_tun);
        if (acq != napi_ok) {
            return -1;
        }
        napi_status st = napi_call_threadsafe_function(tsfn_tun, &v, napi_tsfn_blocking);
        if (st != napi_ok) {
            NETMANAGER_VPN_LOGE("tun tsfn call failed: %{public}d", static_cast<int>(st));
            return -1;
        }

        std::unique_lock<std::mutex> lock(tun_mtx);
        NETMANAGER_VPN_LOGI("TunMainWait");
        if (!tun_cv.wait_for(lock, std::chrono::seconds(30), []() { return tun_done; })) {
            NETMANAGER_VPN_LOGE("TunMain timeout");
            tun_fd = -1;
        }
        NETMANAGER_VPN_LOGI("TunMainFinished, fd=%{public}d", tun_fd);
        if (tun_fd >= 0) {
            established_tun_fd = tun_fd;
        }
        return tun_fd;
    }
};

static std::shared_ptr<Client> client = std::make_shared<Client>();
static std::mutex client_mtx;
static std::atomic<bool> is_connecting{false};
static std::thread connect_thread;
static std::atomic<bool> exit_notified{false};
static std::atomic<bool> intentional_stop{false};

static void SafeReleaseTsfn(napi_env env, napi_threadsafe_function &tsfn) {
    if (!tsfn) {
        return;
    }
    napi_release_threadsafe_function(tsfn, napi_tsfn_release);
    if (env) {
        napi_unref_threadsafe_function(env, tsfn);
    }
    tsfn = nullptr;
}

static void SafeDeleteRef(napi_env env, napi_ref &ref) {
    if (ref && env) {
        napi_delete_reference(env, ref);
    }
    ref = nullptr;
}

static void NotifyExit(const std::string &reason) {
    if (exit_notified.exchange(true)) {
        return;
    }
    if (!tsfn_exit) {
        return;
    }
    char *heap = new char[reason.size() + 1];
    std::memcpy(heap, reason.c_str(), reason.size() + 1);
    napi_status acq = napi_acquire_threadsafe_function(tsfn_exit);
    if (acq != napi_ok) {
        delete[] heap;
        return;
    }
    napi_status st = napi_call_threadsafe_function(tsfn_exit, heap, napi_tsfn_nonblocking);
    if (st != napi_ok) {
        delete[] heap;
        NETMANAGER_VPN_LOGE("exit tsfn call failed: %{public}d", static_cast<int>(st));
    }
}

static std::string GetStringFromValueUtf8(napi_env env, napi_value value, size_t buf_size) {
    std::string result;
    std::vector<char> buffer(buf_size, 0); // 动态分配缓冲区
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, value, buffer.data(), buf_size, &length);
    if (status == napi_ok && length > 0) {
        result.append(buffer.data(), length);
    }
    return result;
}

static napi_value StartVpn(napi_env env, napi_callback_info info) {
    // 检查是否已在运行
    if (is_connecting.exchange(true)) {
        napi_value error;
        napi_create_string_utf8(env, "VPN is already connecting", NAPI_AUTO_LENGTH, &error);
        return error;
    }

    const size_t numArgs = 7;
    size_t argc = numArgs;
    napi_value args[numArgs] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    std::string content = GetStringFromValueUtf8(env, args[0], 1024 * 255);
    napi_value cb_protect_fn = args[1];
    napi_value cb_tun_fn = args[2];
    napi_value cb_connected_fn = args[3];
    files_dir = GetStringFromValueUtf8(env, args[4], 256);
    napi_value cb_stats_fn = args[5];
    napi_value cb_exit_fn = argc >= 7 ? args[6] : nullptr;

    exit_notified = false;
    intentional_stop = false;
    vpn_running = true;

    napi_value protect_name;
    napi_create_string_utf8(env, "ProtectSocket", NAPI_AUTO_LENGTH, &protect_name);
    napi_create_reference(env, cb_protect_fn, 1, &cb_protect_ref);
    napi_create_threadsafe_function(env, cb_protect_fn, NULL, protect_name, 0, 1, NULL, NULL, NULL, call_js_protect,
                                    &tsfn_protect);

    napi_value tun_name;
    napi_create_string_utf8(env, "TunSetup", NAPI_AUTO_LENGTH, &tun_name);
    napi_create_reference(env, cb_tun_fn, 1, &cb_tun_ref);
    napi_create_threadsafe_function(env, cb_tun_fn, NULL, tun_name, 0, 1, NULL, NULL, NULL, call_js_tun, &tsfn_tun);

    napi_value connect_name;
    napi_create_string_utf8(env, "Connected", NAPI_AUTO_LENGTH, &connect_name);
    napi_create_reference(env, cb_connected_fn, 1, &cb_connected_ref);
    napi_create_threadsafe_function(
        env, cb_connected_fn, NULL, connect_name, 0, 1, NULL, NULL, NULL,
        [](napi_env env, napi_value js_cb, void *context, void *data) {
            napi_get_reference_value(env, cb_connected_ref, &js_cb);
            auto v = static_cast<char *>(data);
            napi_value info, rv;
            napi_create_string_utf8(env, v, strlen(v), &info);
            delete[] v;
            napi_call_function(env, nullptr, js_cb, 1, &info, &rv);
        },
        &tsfn_connected);

    napi_value stats_name;
    napi_create_string_utf8(env, "Stats", NAPI_AUTO_LENGTH, &stats_name);
    napi_create_reference(env, cb_stats_fn, 1, &cb_stats_ref);
    napi_create_threadsafe_function(
        env, cb_stats_fn, NULL, stats_name, 8, 1, NULL, NULL, NULL,
        [](napi_env env, napi_value js_cb, void *context, void *data) {
            napi_get_reference_value(env, cb_stats_ref, &js_cb);
            auto v = static_cast<char *>(data);
            napi_value json, rv;
            napi_create_string_utf8(env, v, strlen(v), &json);
            delete[] v;
            napi_call_function(env, nullptr, js_cb, 1, &json, &rv);
        },
        &tsfn_stats);

    if (cb_exit_fn != nullptr) {
        napi_value exit_name;
        napi_create_string_utf8(env, "Exit", NAPI_AUTO_LENGTH, &exit_name);
        napi_create_reference(env, cb_exit_fn, 1, &cb_exit_ref);
        napi_create_threadsafe_function(
            env, cb_exit_fn, NULL, exit_name, 0, 1, NULL, NULL, NULL,
            [](napi_env env, napi_value js_cb, void *context, void *data) {
                napi_get_reference_value(env, cb_exit_ref, &js_cb);
                auto v = static_cast<char *>(data);
                napi_value reason, rv;
                napi_create_string_utf8(env, v, strlen(v), &reason);
                delete[] v;
                napi_call_function(env, nullptr, js_cb, 1, &reason, &rv);
            },
            &tsfn_exit);
    }

    napi_value rv;
    openvpn::ClientAPI::Config config;
    config.content = content;
    config.echo = true;
    config.info = true;
    config.allowLocalLanAccess = true;
    config.tunPersist = true;
    config.clockTickMS = 1000; // enable Client::clock_tick for live stats

    openvpn::ClientAPI::EvalConfig evCfg = client->eval_config(config);
    if (evCfg.error) {
        NETMANAGER_VPN_LOGE("解析配置错误: %{public}s", evCfg.message.c_str());
        vpn_running = false;
        SafeDeleteRef(env, cb_protect_ref);
        SafeDeleteRef(env, cb_tun_ref);
        SafeDeleteRef(env, cb_connected_ref);
        SafeDeleteRef(env, cb_stats_ref);
        SafeDeleteRef(env, cb_exit_ref);
        SafeReleaseTsfn(env, tsfn_protect);
        SafeReleaseTsfn(env, tsfn_tun);
        SafeReleaseTsfn(env, tsfn_connected);
        SafeReleaseTsfn(env, tsfn_stats);
        SafeReleaseTsfn(env, tsfn_exit);
        is_connecting = false;
        napi_create_string_utf8(env, evCfg.message.c_str(), evCfg.message.length(), &rv);
        return rv;
    }

    // Do not detach — StopVpn joins so teardown is race-free.
    if (connect_thread.joinable()) {
        connect_thread.join();
    }
    connect_thread = std::thread([](std::shared_ptr<Client> cli) {
        // Browser load / brief network blips often end a session; reconnect instead of
        // tearing down VpnExtensionAbility (which removes the system VPN icon).
        int failStreak = 0;
        while (!intentional_stop.load()) {
            vpn_running = true;
            auto status = cli->connect();
            if (intentional_stop.load()) {
                break;
            }
            std::string reason;
            if (status.error) {
                reason = status.status + ": " + status.message;
                NETMANAGER_VPN_LOGE("连接失败, status: %{public}s, msg: %{public}s", status.status.c_str(),
                                    status.message.c_str());
                failStreak++;
            } else {
                reason = "disconnected";
                NETMANAGER_VPN_LOGI("OpenVPN 连接断开, will reconnect\n");
                failStreak = 0; // clean disconnect still retry unless user stopped
            }

            // Give up after repeated hard failures (e.g. auth / bad config).
            const bool fatalAuth = reason.find("AUTH") != std::string::npos ||
                                   reason.find("auth") != std::string::npos ||
                                   reason.find("PASSWORD") != std::string::npos;
            if (fatalAuth || failStreak >= 5) {
                vpn_running = false;
                NotifyExit(reason);
                break;
            }

            NETMANAGER_VPN_LOGI("auto-reconnect in 2s (streak=%{public}d)", failStreak);
            for (int i = 0; i < 20 && !intentional_stop.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        vpn_running = false;
    }, client);
    return nullptr;
}

static napi_value StopVpn(napi_env env, napi_callback_info info) {
    std::lock_guard<std::mutex> lock(client_mtx);
    intentional_stop = true;
    vpn_running = false;

    // Unblock any waiters before stop.
    NotifyTunDone(-1);
    NotifyProtectDone(false);

    if (client) {
        client->stop(); // 先停止连接
    }
    // 等待线程结束
    if (connect_thread.joinable()) {
        connect_thread.join();
    }

    SafeDeleteRef(env, cb_protect_ref);
    SafeDeleteRef(env, cb_tun_ref);
    SafeDeleteRef(env, cb_connected_ref);
    SafeDeleteRef(env, cb_stats_ref);
    SafeDeleteRef(env, cb_exit_ref);
    SafeReleaseTsfn(env, tsfn_protect);
    SafeReleaseTsfn(env, tsfn_tun);
    SafeReleaseTsfn(env, tsfn_connected);
    SafeReleaseTsfn(env, tsfn_stats);
    SafeReleaseTsfn(env, tsfn_exit);

    // 重置状态
    {
        std::lock_guard<std::mutex> tun_lock(tun_mtx);
        tun_fd = -1;
        tun_done = false;
        established_tun_fd = -1;
    }
    {
        std::lock_guard<std::mutex> protect_lock(protect_mtx);
        protect_done = false;
        protect_ok = false;
    }

    // 重新创建 client
    client = std::make_shared<Client>();
    is_connecting = false;
    exit_notified = false;
    intentional_stop = false;

    NETMANAGER_VPN_LOGI("StopVpn successful\n");

    napi_value retValue;
    napi_create_int32(env, 0, &retValue);
    return retValue;
}

static napi_value GetTransportStats(napi_env env, napi_callback_info info) {
    long long bytesIn = 0;
    long long bytesOut = 0;
    {
        std::lock_guard<std::mutex> lock(client_mtx);
        if (client && is_connecting.load()) {
            openvpn::ClientAPI::TransportStats ts = client->transport_stats();
            openvpn::ClientAPI::InterfaceStats tun = client->tun_stats();
            // Prefer whichever side has traffic; UI "usage" is closer to TUN bytes.
            bytesIn = std::max(ts.bytesIn, tun.bytesIn);
            bytesOut = std::max(ts.bytesOut, tun.bytesOut);
        }
    }

    // Return JSON string so ArkTS JSON.stringify on NAPI objects is not needed.
    char buf[128];
    std::snprintf(buf, sizeof(buf), "{\"bytesIn\":%lld,\"bytesOut\":%lld}", bytesIn, bytesOut);
    napi_value result;
    napi_create_string_utf8(env, buf, NAPI_AUTO_LENGTH, &result);
    return result;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"startVpn", nullptr, StartVpn, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stopVpn", nullptr, StopVpn, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getTransportStats", nullptr, GetTransportStats, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "vpn_client",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void) { napi_module_register(&demoModule); }
