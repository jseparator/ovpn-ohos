/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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

import { commonEventManager } from '@kit.BasicServicesKit';
import { Want, bundleManager } from '@kit.AbilityKit';
import { vpnExtension as vpnExt, VpnExtensionAbility, connection } from '@kit.NetworkKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import vpn_client from 'libvpn_client.so';
import hilog from '@ohos.hilog';

const TAG: string = "[OvpnExtAbility]";
let bundleName: string = '';
const VPN_RUNTIME_STATUS_FILE = 'ovpn-status.json';
const MANUAL_STOP_FLAG_FILE = 'ovpn-manual-stop.flag';
const MANUAL_STOP_MARK = 'manual-stop';

export default class OvpnExtAbility extends VpnExtensionAbility {
  private VpnConnection: vpnExt.VpnConnection;
  private vpnConfig: string = '';
  private deviceIp: string = '';
  private connectedInfo: string = '';
  private statusHeartbeatTimer: number = -1;

  async onCreate(want: Want) {
    hilog.info(0x0000, TAG, `onCreate, want: ${want.abilityName}`);
    this.VpnConnection = vpnExt.createVpnConnection(this.context);
    hilog.info(0x0000, TAG, `createVpnConnection success`);
    try {
      const bi = await bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT)
      bundleName = bi.name;
      this.vpnConfig = want.parameters.cfg as string
      await this.setManualStopRequested(false)
      await this.writeRuntimeStatus('connecting')
      this.SetupVpn();
    } catch (e) {
      const msg = JSON.stringify(e)
      hilog.error(0x0000, TAG, `readTextSync Err: ${msg}`);
      await this.writeRuntimeStatus('failed', msg)
      commonEventManager.publish('ovpn.READ_CONFIG_ERR', {
        bundleName,
        data: msg
      }, () => hilog.debug(0x0000, TAG, `publisher event Err: ${msg}`))
    }
  }

  onRequest(want: Want, startId: number) {
    hilog.info(0x0000, TAG, `onRequest, want: ${want.abilityName}, startId: ${startId}`);
  }

  onConnect(want: Want) {
    hilog.info(0x0000, TAG, `onConnect, want: ${want.abilityName}, cfg: ${JSON.stringify(want)}`);
    return null;
  }

  onDisconnect(want: Want) {
    hilog.info(0x0000, TAG, `onDisconnect, want: ${want.abilityName}`);
  }

  onDestroy() {
    this.handleOnDestroy().catch((err: Error) => {
      hilog.error(0x0000, TAG, 'handleOnDestroy failed: %{public}s', JSON.stringify(err) ?? '')
    })
  }

  SetupVpn() {
    hilog.info(0x0000, TAG, '%{public}s', 'vpn SetupVpn');
    vpn_client.startVpn(this.vpnConfig, (socketFd: number) => {
      this.Protect(socketFd)
    }, async (o: string) => {
      const cfg = JSON.parse(o) as vpnExt.VpnConfig
      this.deviceIp = this.extractDeviceIpFromCfg(cfg)
      return await this.CreateTun(cfg)
    }, (info: string) => {
      hilog.info(0x0000, TAG, 'Connected: %{public}s', info);
      this.connectedInfo = info;
      this.startStatusHeartbeat()
      this.writeRuntimeStatus('connected', info).catch((err: Error) => {
        hilog.error(0x0000, TAG, 'writeRuntimeStatus connected failed: %{public}s', JSON.stringify(err) ?? '')
      })
      commonEventManager.publish('ovpn.CONNECTED', {
        bundleName,
        data: info
      }, () => {
      })
    }, this.context.filesDir);
  }

  Protect(socketFd: number) {
    hilog.info(0x0000, TAG, '%{public}s', 'vpn Protect');
    this.VpnConnection.protect(socketFd).then(() => {
      hilog.info(0x0000, TAG, '%{public}s', 'vpn Protect Success');
    }).catch((err: Error) => {
      hilog.error(0x0000, TAG, 'vpn Protect Failed %{public}s', JSON.stringify(err) ?? '');
    })
  }

  async CreateTun(cfg: vpnExt.VpnConfig) {
    hilog.info(0x0000, TAG, 'CreateTun: %{public}s', JSON.stringify(cfg))
    try {
      const tunFd = await this.VpnConnection.create(cfg)
      hilog.error(0x0000, TAG, 'tunFd: %{public}d', tunFd)
      return tunFd
    } catch (err) {
      hilog.error(0x0000, TAG, 'vpn start Fail %{public}s', JSON.stringify(err) ?? '')
      return -1
    }
  }

  Destroy() {
    hilog.info(0x0000, TAG, 'vpn Destroy');
    this.stopStatusHeartbeat()
    this.deviceIp = ''
    this.connectedInfo = ''
    connection.setAppHttpProxy({
      host: '',
      port: 0
    } as connection.HttpProxy)
    this.VpnConnection.destroy()
      .then(() => {
        hilog.info(0x0000, TAG, 'vpn Destroy Success');
      })
      .catch((err: Error) => {
        hilog.error(0x0000, TAG, 'vpn Destroy Failed: %{public}s', JSON.stringify(err) ?? '');
      })
      .finally(() => vpn_client.stopVpn())
  }

  private extractDeviceIpFromCfg(cfg: vpnExt.VpnConfig): string {
    const cfgObj = cfg as unknown as { addresses?: Array<{ address?: { address?: string } }> }
    const addresses = cfgObj.addresses ?? []
    const ip = addresses
      .map((item) => item.address?.address ?? '')
      .find((v) => v.startsWith('10.'))
    return ip ?? ''
  }

  private statusFilePath(): string {
    return `${this.context.filesDir}/${VPN_RUNTIME_STATUS_FILE}`
  }

  private manualStopFlagPath(): string {
    return `${this.context.filesDir}/${MANUAL_STOP_FLAG_FILE}`
  }

  private async isManualStopRequested(): Promise<boolean> {
    try {
      const text = await fs.readText(this.manualStopFlagPath())
      return text.trim() === MANUAL_STOP_MARK
    } catch (_) {
      return false
    }
  }

  private async setManualStopRequested(requested: boolean) {
    const filePath = this.manualStopFlagPath()
    const content = requested ? MANUAL_STOP_MARK : ''
    try {
      await fs.truncate(filePath)
    } catch (_) {
    }
    const fd = await fs.open(filePath, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE)
    await fs.write(fd.fd, content)
    await fs.close(fd)
  }

  private async handleOnDestroy() {
    hilog.info(0x0000, TAG, `onDestroy`);
    this.stopStatusHeartbeat()
    const manualStop = await this.isManualStopRequested()
    if (manualStop) {
      await this.setManualStopRequested(false)
      this.Destroy();
      await this.writeRuntimeStatus('disconnected')
      commonEventManager.publish('ovpn.DESTROY', {
        bundleName
      }, () => hilog.debug(0x0000, TAG, `publisher event DESTROY`))
      return
    }
    await this.writeRuntimeStatus('disconnected')
    commonEventManager.publish('ovpn.DESTROY', {
      bundleName
    }, () => hilog.debug(0x0000, TAG, `publisher event DESTROY by lifecycle`))
  }

  private async writeRuntimeStatus(status: string, info: string = '') {
    const filePath = this.statusFilePath()
    if (status !== 'connected') {
      this.deviceIp = ''
    }
    const activeCfg = (status === 'connected' || status === 'connecting') ? this.vpnConfig : ''
    const content = JSON.stringify({
      status,
      info,
      cfg: activeCfg,
      deviceIp: this.deviceIp,
      updatedAt: Date.now()
    })
    try {
      await fs.truncate(filePath)
    } catch (_) {
    }
    const fd = await fs.open(filePath, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE)
    await fs.write(fd.fd, content)
    await fs.close(fd)
  }

  private startStatusHeartbeat() {
    this.stopStatusHeartbeat()
    this.statusHeartbeatTimer = setInterval(() => {
      this.writeRuntimeStatus('connected', this.connectedInfo).catch((err: Error) => {
        hilog.error(0x0000, TAG, 'statusHeartbeat write failed: %{public}s', JSON.stringify(err) ?? '')
      })
    }, 3000) as unknown as number
  }

  private stopStatusHeartbeat() {
    if (this.statusHeartbeatTimer !== -1) {
      clearInterval(this.statusHeartbeatTimer)
      this.statusHeartbeatTimer = -1
    }
  }
}
