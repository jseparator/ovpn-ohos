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

#include "napi/native_api.h"
#include "hilog/log.h"

#include <cstring>
#include <js_native_api.h>
#include <js_native_api_types.h>
#include <network/netmanager/net_connection.h>
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

napi_ref cb_log_ref = nullptr;
napi_ref cb_protect_ref = nullptr;
napi_ref cb_tun_ref = nullptr;
napi_ref cb_connected_ref = nullptr;
napi_threadsafe_function tsfn_log, tsfn_protect, tsfn_tun, tsfn_connected; // 线程安全函数

int tun_fd = -1;
bool tun_done = false;
std::mutex tun_mtx;
std::condition_variable tun_cv;

napi_value ArkTsTunCallBack(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value v;
    napi_get_cb_info(env, info, &argc, &v, nullptr, nullptr);

    NETMANAGER_VPN_LOGI("TunThenLock, %{public}d", tun_fd);
    std::unique_lock<std::mutex> lock(tun_mtx);
    napi_get_value_int32(env, v, &tun_fd);
    tun_done = true;
    tun_cv.notify_all(); // 通知主线程继续执行
    NETMANAGER_VPN_LOGI("TunThenFinished, %{public}d", tun_fd);
    return nullptr;
}

void call_js_tun(napi_env env, napi_value js_cb, void *context, void *data) {
    napi_get_reference_value(env, cb_tun_ref, &js_cb);
    auto v = static_cast<std::string *>(data);

    napi_value cfg, promise;
    napi_create_string_utf8(env, v->c_str(), v->length(), &cfg);
    napi_call_function(env, nullptr, js_cb, 1, &cfg, &promise);

    // 获取promise对象的then属性，该属性的回调方法用于处理ArkTS侧异步计算结果
    napi_value thenProperty = nullptr;
    napi_get_named_property(env, promise, "then", &thenProperty);
    // 将C++语言定义的then属性回调方法转换为ArkTS函数对象，即napi_value类型值
    napi_value thenCallback = nullptr;
    napi_create_function(env, "thenCallback", NAPI_AUTO_LENGTH, ArkTsTunCallBack, nullptr, &thenCallback);

    // 获取promise对象的catch属性，该属性的回调方法用于处理ArkTS侧异步计算异常的信息
    napi_value catchProperty = nullptr;
    napi_get_named_property(env, promise, "catch", &catchProperty);
    // 将C++语言定义的catch属性回调方法转换为ArkTS函数对象，即napi_value类型值
    napi_value catchCallback = nullptr;
    napi_create_function(
        env, "catchCallback", NAPI_AUTO_LENGTH,
        [](napi_env env, napi_callback_info info) -> napi_value {
            size_t argc = 1;
            napi_value args[1] = {nullptr};
            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            size_t strLen = 0;
            napi_get_value_string_utf8(env, args[0], nullptr, 0, &strLen); // 获取字符串长度到strLen
            char *strBuffer = new char[strLen + 1];                        // 分配合适大小的char数组
            napi_get_value_string_utf8(env, args[0], strBuffer, strLen + 1, &strLen);
            NETMANAGER_VPN_LOGE("ArkTS Async Method Calculation Exception: %{public}s", strBuffer);
            return nullptr;
        },
        nullptr, &catchCallback);

    // 通过napi_call_function执行then属性的回调，类似于ArkTS侧调用promise.then(()=>{})
    napi_call_function(env, promise, thenProperty, 1, &thenCallback, nullptr);
    // 通过napi_call_function执行catch属性的回调，类似于ArkTS侧调用promise.catch(()=>{})
    napi_call_function(env, promise, catchProperty, 1, &catchCallback, nullptr); 
//     napi_delete_reference(env, cb_protect_ref);
}

static int g_vpnNetId;

class Client : public openvpn::ClientAPI::OpenVPNClient {
private:
    VpnConfig tun;
    NetAddress tun_gw; // gateway
    std::vector<std::string> tun_proxy_bypasses;
//     NetConn_HttpProxy tun_proxy_http;
    std::string tun_proxy_host;
    int tun_proxy_port;

public:
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
            json["proxy"]["host"] = this->tun_proxy_host;
            json["proxy"]["port"] = this->tun_proxy_port;
            Json::StreamWriterBuilder writer;
            writer["indentation"] = ""; // Set the indentation to an empty string
            std::string v = Json::writeString(writer, json);
            auto info = new char[v.length() + 1];
            v.copy(info, v.length());

            napi_acquire_threadsafe_function(tsfn_connected);
            napi_call_threadsafe_function(tsfn_connected, info, napi_tsfn_blocking);
        }
    }

    virtual void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &e) override {}

    virtual void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &) override {}

    virtual void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &) override {}

    virtual void clock_tick() override {}

    virtual void log(const openvpn::ClientAPI::LogInfo &l) override { // logging delivered here
        NETMANAGER_VPN_LOGI("%{public}s", l.text.c_str());
        auto info = new char[l.text.length() + 1];
        l.text.copy(info, l.text.length());
        napi_acquire_threadsafe_function(tsfn_log);
        napi_call_threadsafe_function(tsfn_log, info, napi_tsfn_blocking);
    }

    virtual bool socket_protect(openvpn_io::detail::socket_type socket, std::string remote, bool ipv6) override {
        NETMANAGER_VPN_LOGI("socket_protect: %{public}d %{public}s", socket, remote.c_str());
        auto fd = new openvpn_io::detail::socket_type(socket);
        napi_acquire_threadsafe_function(tsfn_protect);
        napi_call_threadsafe_function(tsfn_protect, fd, napi_tsfn_blocking);
        return true;
    }

    virtual bool tun_builder_new() override { return true; }

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
//         this->tun_proxy_auto_config_url = url;
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
        Json::Value json = vpnConfigToJson(this->tun);
        Json::StreamWriterBuilder writer;
        writer["indentation"] = ""; // Set the indentation to an empty string
        std::string v = Json::writeString(writer, json);
        NETMANAGER_VPN_LOGI("tun_builder_establish: %{public}s", v.c_str());

        napi_acquire_threadsafe_function(tsfn_tun);
        napi_call_threadsafe_function(tsfn_tun, &v, napi_tsfn_blocking);

        std::unique_lock<std::mutex> lock(tun_mtx);
        NETMANAGER_VPN_LOGI("TunMainWait");
        tun_cv.wait(lock, []() { return tun_done; }); // 等待 Promise 完成
        NETMANAGER_VPN_LOGI("TunMainFinished");
        return tun_fd;
    }
};

auto client = new Client();

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
    const size_t numArgs = 5;
    size_t argc = numArgs;
    napi_value args[numArgs] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    std::string content = GetStringFromValueUtf8(env, args[0], 1024*255);
    napi_value cb_protect_fn = args[1];
    napi_value cb_tun_fn = args[2];
    napi_value cb_connected_fn = args[3];
    napi_value cb_log_fn = args[4];

    napi_value protect_name;
    napi_create_string_utf8(env, "ProtectSocket", NAPI_AUTO_LENGTH, &protect_name);
    napi_create_reference(env, cb_protect_fn, 1, &cb_protect_ref);
    napi_create_threadsafe_function(
        env, cb_protect_fn, NULL, protect_name, 0, 1, NULL, NULL, NULL,
        [](napi_env env, napi_value js_cb, void *context, void *data) {
            napi_get_reference_value(env, cb_protect_ref, &js_cb);
            auto socket = static_cast<openvpn_io::detail::socket_type *>(data);
            napi_value argv;
            napi_create_int32(env, *socket, &argv);
            delete socket;
            napi_value result = nullptr;
            napi_call_function(env, nullptr, js_cb, 1, &argv, &result);
        },
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
    
    napi_value log_name;
    napi_create_string_utf8(env, "Log", NAPI_AUTO_LENGTH, &log_name);
    napi_create_reference(env, cb_log_fn, 1, &cb_log_ref);
    napi_create_threadsafe_function(
        env, cb_log_fn, NULL, log_name, 0, 1, NULL, NULL, NULL,
        [](napi_env env, napi_value js_cb, void *context, void *data) {
            napi_get_reference_value(env, cb_log_ref, &js_cb);
            auto v = static_cast<char *>(data);
            napi_value info, rv;
            napi_create_string_utf8(env, v, strlen(v), &info);
            delete[] v;
            napi_call_function(env, nullptr, js_cb, 1, &info, &rv);
        },
        &tsfn_log);

    napi_value rv;
    openvpn::ClientAPI::Config config;
    config.content = content;
    config.echo = true;
    config.info = true;
    config.allowLocalLanAccess = true;
    config.tunPersist = true;

    openvpn::ClientAPI::EvalConfig evCfg = client->eval_config(config);
    if (evCfg.error) {
        NETMANAGER_VPN_LOGE("解析配置错误: %{public}s", evCfg.message.c_str());
        napi_create_string_utf8(env, evCfg.message.c_str(), evCfg.message.length(), &rv);
        return rv;
    }

    std::thread t([]() {
        auto status = client->connect();
        if (status.error) {
            NETMANAGER_VPN_LOGE("连接失败, status: %{public}s, msg: %{public}s", status.status.c_str(),
                                status.message.c_str());
        } else {
            NETMANAGER_VPN_LOGI("OpenVPN 连接断开\n");
        }
    });
    t.detach();
    return nullptr;
}

static napi_value StopVpn(napi_env env, napi_callback_info info) {
    client->stop();
    delete client;

    napi_delete_reference(env, cb_log_ref);
    napi_delete_reference(env, cb_protect_ref);
    napi_delete_reference(env, cb_tun_ref);
    napi_delete_reference(env, cb_connected_ref);
    napi_release_threadsafe_function(tsfn_log, napi_tsfn_release);
    napi_release_threadsafe_function(tsfn_protect, napi_tsfn_release);
    napi_release_threadsafe_function(tsfn_tun, napi_tsfn_release);
    napi_release_threadsafe_function(tsfn_connected, napi_tsfn_release);
    napi_unref_threadsafe_function(env, tsfn_log);
    napi_unref_threadsafe_function(env, tsfn_protect);
    napi_unref_threadsafe_function(env, tsfn_tun);
    napi_unref_threadsafe_function(env, tsfn_connected);

    tun_fd = -1;
    tun_done = false;

    client = new Client();

    NETMANAGER_VPN_LOGI("StopVpn successful\n");

    napi_value retValue;
    napi_create_int32(env, 0, &retValue);
    return retValue;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"startVpn", nullptr, StartVpn, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stopVpn", nullptr, StopVpn, nullptr, nullptr, nullptr, napi_default, nullptr},
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
