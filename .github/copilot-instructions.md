# `ovpn-ohos` 的 Copilot 指令

## 构建、测试与代码检查命令

### HarmonyOS 应用模块（`entry`）

- 构建 `entry/src/main/cpp/CMakeLists.txt` 使用的第三方原生依赖（输出到 `dep-ohos/`）：

```bash
bash dep-build.sh
```

- 项目 hvigor 流水线中使用的构建/打包任务：
  - 任务：`:entry:assembleHap`
  - 模块参数：`module=entry@default`、`product=default`、`requiredDeviceType=phone`
  - 来源：`.hvigor/report/report-202605220947567570.json`（`completeCommand`）

### OpenVPN3 子模块（`entry/src/main/cpp/openvpn3`）

- 配置并构建单元测试：

```bash
cd entry/src/main/cpp/openvpn3
cmake -S . -B build -GNinja
cmake --build build --target coreUnitTests
```

- 运行完整测试集：

```bash
ctest --test-dir build
```

- 运行单个测试：

```bash
./build/test/unittests/coreUnitTests --gtest_filter=Base64.tooshortdest
```

- 对 OpenVPN3 子模块执行 C++ 格式检查：

```bash
cd entry/src/main/cpp/openvpn3
pre-commit run clang-format --all-files
```

## 高层架构

- 本仓库是一个 HarmonyOS 应用（`entry` 模块）+ 原生 VPN 引擎桥接层。
- UI 从 `EntryAbility`（`entry/src/main/ets/entryability/EntryAbility.ts`）启动，并加载 `pages/Index`。
- `Index.ets` 负责管理应用沙箱内的 `.ovpn` 文件（`filesDir/ovpn`）、渲染 `VpnItem` 开关，并订阅 VPN 生命周期事件。
- `VpnItem.ets` 通过 `vpnExtension.startVpnExtensionAbility(...)` / `stopVpnExtensionAbility(...)` 启停 VPN 扩展能力（`OvpnExtAbility`）。
- `OvpnExtAbility.ts` 创建 `VpnConnection`，调用原生库 `libvpn_client.so`（`startVpn` / `stopVpn`），执行 socket protect、创建 TUN，并发布应用事件（`ovpn.READ_CONFIG_ERR`、`ovpn.CONNECTED`、`ovpn.DESTROY`）。
- 原生桥接位于 `entry/src/main/cpp/vpn_client.cpp`：继承 OpenVPN3 Client API，通过 `model.hpp` 转换隧道配置，并用 N-API 线程安全函数桥接 ArkTS 回调。
- OpenVPN3 核心代码以 git 子模块方式放在 `entry/src/main/cpp/openvpn3`（见 `.gitmodules`），并由 `entry/src/main/cpp/CMakeLists.txt` 直接编译进 `vpn_client`。
- VPN 日志由原生层写入 `filesDir/ovpn.log`；`pages/Log.ets` 通过文件监听实现实时日志查看。

## 仓库关键约定

- **事件契约是跨层 API**：`OvpnExtAbility.ts` 发布端与 `Index.ets` 订阅端之间，事件名和 payload 结构必须保持稳定（`ovpn.READ_CONFIG_ERR`、`ovpn.CONNECTED`、`ovpn.DESTROY`）。
- **N-API 回调顺序/签名必须一致**：`types/libentry/index.d.ts` 中的 `startVpn(content, protectCb, tunCb, connectedCb, filesDir)` 必须与 `vpn_client.cpp` 中 `StartVpn` 的参数解析顺序一致。
- **TUN 创建是基于 Promise 的异步流程**：原生层调用 ArkTS `tunCb` 后，会在 `ArkTsTunCallBack` 中等待 Promise `then` 回调，再继续使用返回的 fd。
- **`VpnConfig` JSON 结构是共享契约**：`model.hpp` 生成的 JSON 会在 `OvpnExtAbility.CreateTun` 中按 `vpnExt.VpnConfig` 消费。
- **证书管理流程依赖 ability context 初始化**：`EntryAbility.onCreate()` 必须继续调用 `CertMgr.getInstance().setUiAbilityContext(...)`，否则 `Browser.ets` 的客户端证书授权流程无法拉起 `com.ohos.certmanager`。
- **不同代码区域使用不同格式规则**：
  - 仓库根目录 C++ 使用根目录 `.clang-format` 与 `.clang-tidy`
  - OpenVPN3 子模块使用其自身 `.clang-format` 与 `.pre-commit-config.yaml`
- **`Log` 页面路由跨文件耦合**：`pages/Log.ets` 中的 `@Builder LogBuilder` 与 `router_map.json` 中的路由项必须同步维护。
