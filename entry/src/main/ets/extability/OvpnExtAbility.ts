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
import vpn_client from 'libvpn_client.so';
import hilog from '@ohos.hilog';

const TAG: string = "[OvpnExtAbility]";
let bundleName: string = '';

export default class OvpnExtAbility extends VpnExtensionAbility {
  private VpnConnection: vpnExt.VpnConnection;
  private vpnConfig: string = '';

  async onCreate(want: Want) {
    hilog.info(0x0000, TAG, `onCreate, want: ${want.abilityName}`);
    this.VpnConnection = vpnExt.createVpnConnection(this.context);
    hilog.info(0x0000, TAG, `createVpnConnection success`);
    try {
      const bi = await bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT)
      bundleName = bi.name;
      this.vpnConfig = want.parameters.cfg as string
      this.SetupVpn();
    } catch (e) {
      const msg = JSON.stringify(e)
      hilog.error(0x0000, TAG, `readTextSync Err: ${msg}`);
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

  SetupVpn() {
    hilog.info(0x0000, TAG, '%{public}s', 'vpn SetupVpn');
    vpn_client.startVpn(this.vpnConfig, (socketFd: number) => {
      this.Protect(socketFd)
    }, async (o: string) => {
      const cfg = JSON.parse(o) as vpnExt.VpnConfig
      return await this.CreateTun(cfg)
    }, (info: string) => {
      hilog.info(0x0000, TAG, 'Connected: %{public}s', info);
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
}
