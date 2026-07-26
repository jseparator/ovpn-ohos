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
const ACTIVE_CFG = '/ovpn.active.cfg';
let bundleName: string = '';

export default class OvpnExtAbility extends VpnExtensionAbility {
  private VpnConnection: vpnExt.VpnConnection;
  private vpnConfig: string = '';
  private destroying: boolean = false;
  private tunFd: number = -1;

  async onCreate(want: Want) {
    hilog.info(0x0000, TAG, `onCreate, want: ${want.abilityName}`);
    this.VpnConnection = vpnExt.createVpnConnection(this.context);
    hilog.info(0x0000, TAG, `createVpnConnection success`);
    try {
      const bi = await bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT)
      bundleName = bi.name;

      const params = want.parameters ?? {}
      const paramCfg = (params.cfg as string) ?? ''
      const uiFilesDir = (params.filesDir as string) ?? ''
      const filesDir = uiFilesDir.length > 0 ? uiFilesDir : this.context.filesDir

      // Always prefer the persisted file — want.parameters may truncate large configs
      // (inline certs + keys can exceed system IPC size limits).
      try {
        const fileCfg = await fs.readText(filesDir + ACTIVE_CFG)
        if (fileCfg && fileCfg.length > 0) {
          this.vpnConfig = fileCfg
          hilog.info(0x0000, TAG, `loaded config from file: ${fileCfg.length} bytes`)
        } else {
          this.vpnConfig = paramCfg
          hilog.warn(0x0000, TAG, `config file empty, using params: ${paramCfg.length} bytes`)
        }
      } catch (_readErr) {
        this.vpnConfig = paramCfg
        hilog.warn(0x0000, TAG, `config file not found, using params: ${paramCfg.length} bytes`)
      }

      if (!this.vpnConfig || this.vpnConfig.length === 0) {
        const msg = 'VPN config missing after start (auth restart?)'
        hilog.error(0x0000, TAG, msg)
        commonEventManager.publish('ovpn.READ_CONFIG_ERR', {
          bundleName,
          data: msg
        }, () => {
        })
        return
      }

      this.SetupVpn(filesDir);
    } catch (e) {
      const msg = JSON.stringify(e)
      hilog.error(0x0000, TAG, `onCreate Err: ${msg}`);
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
    this.Destroy();
    hilog.info(0x0000, TAG, `onDestroy`);
    commonEventManager.publish('ovpn.DESTROY', {
      bundleName
    }, () => hilog.debug(0x0000, TAG, `publisher event DESTROY`))
  }

  SetupVpn(filesDir: string) {
    hilog.info(0x0000, TAG, 'vpn SetupVpn, filesDir: %{public}s', filesDir);
    const startErr = vpn_client.startVpn(this.vpnConfig, (socketFd: number) => {
      return this.Protect(socketFd)
    }, async (o: string) => {
      try {
        const cfg = JSON.parse(o) as vpnExt.VpnConfig
        return await this.CreateTun(cfg)
      } catch (e) {
        hilog.error(0x0000, TAG, 'CreateTun parse/setup fail: %{public}s', JSON.stringify(e) ?? '')
        return -1
      }
    }, (info: string) => {
      hilog.info(0x0000, TAG, 'Connected: %{public}s', info);
      commonEventManager.publish('ovpn.CONNECTED', {
        bundleName,
        data: info
      }, () => {
      })
    }, filesDir, (statsJson: string) => {
      hilog.debug(0x0000, TAG, 'STATS: %{public}s', statsJson);
      commonEventManager.publish('ovpn.STATS', {
        bundleName,
        data: statsJson
      }, () => {
      })
    }, (reason: string) => {
      hilog.error(0x0000, TAG, 'VPN session ended: %{public}s', reason);
      commonEventManager.publish('ovpn.ERROR', {
        bundleName,
        data: reason
      }, () => {
      })
      // Do not call Destroy/stopVpn here — releasing tsfn inside its own callback can crash.
      // UI handles ovpn.ERROR by stopVpnExtensionAbility → onDestroy → Destroy.
    });

    if (typeof startErr === 'string' && startErr.length > 0) {
      hilog.error(0x0000, TAG, 'startVpn failed: %{public}s', startErr);
      commonEventManager.publish('ovpn.ERROR', {
        bundleName,
        data: startErr
      }, () => {
      })
    }
  }

  Protect(socketFd: number): Promise<void> {
    hilog.info(0x0000, TAG, 'vpn Protect fd=%{public}d', socketFd);
    return this.VpnConnection.protect(socketFd).then(() => {
      hilog.info(0x0000, TAG, 'vpn Protect Success fd=%{public}d', socketFd);
    }).catch((err: Error) => {
      hilog.error(0x0000, TAG, 'vpn Protect Failed %{public}s', JSON.stringify(err) ?? '');
      // Still resolve: a hard throw aborts OpenVPN under browser reconnect storms.
      // Returning failure via reject causes socket_protect=false and session teardown.
      throw err
    })
  }

  async CreateTun(cfg: vpnExt.VpnConfig) {
    hilog.info(0x0000, TAG, 'CreateTun: %{public}s', JSON.stringify(cfg))
    // OpenVPN tunPersist / reconnect will call establish again. Calling
    // VpnConnection.create twice destroys the system VPN — reuse existing fd.
    if (this.tunFd >= 0) {
      hilog.info(0x0000, TAG, 'reuse existing tunFd: %{public}d', this.tunFd)
      return this.tunFd
    }
    try {
      const tunFd = await this.VpnConnection.create(cfg)
      hilog.info(0x0000, TAG, 'tunFd: %{public}d', tunFd)
      this.tunFd = tunFd
      return tunFd
    } catch (err) {
      hilog.error(0x0000, TAG, 'vpn start Fail %{public}s', JSON.stringify(err) ?? '')
      return -1
    }
  }

  Destroy() {
    if (this.destroying) {
      return
    }
    this.destroying = true
    this.tunFd = -1
    hilog.info(0x0000, TAG, 'vpn Destroy');
    try {
      connection.setAppHttpProxy({
        host: '',
        port: 0
      } as connection.HttpProxy)
    } catch (e) {
    }
    if (!this.VpnConnection) {
      try {
        vpn_client.stopVpn()
      } catch (e) {
      }
      return
    }
    this.VpnConnection.destroy()
      .then(() => {
        hilog.info(0x0000, TAG, 'vpn Destroy Success');
      })
      .catch((err: Error) => {
        hilog.error(0x0000, TAG, 'vpn Destroy Failed: %{public}s', JSON.stringify(err) ?? '');
      })
      .finally(() => {
        try {
          vpn_client.stopVpn()
        } catch (e) {
        }
      })
  }
}
