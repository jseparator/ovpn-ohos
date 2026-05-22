import hilog from '@ohos.hilog';
import { BUNDLE_NAME } from 'BuildProfile';
import { vpnExtension as vpnExt } from '@kit.NetworkKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { commonEventManager } from '@kit.BasicServicesKit';
import { showToast } from '../components/Common';

const TAG: string = '[ItemVpn]'
const bundleName = BUNDLE_NAME
const abilityName = 'OvpnExtAbility'
const MANUAL_STOP_FLAG_FILE = 'ovpn-manual-stop.flag'
const MANUAL_STOP_MARK = 'manual-stop'
const VPN_DESIRED_STATE_FILE = 'ovpn-desired-state.json'
const VPN_RUNTIME_STATUS_FILE = 'ovpn-status.json'
const VPN_MANUAL_STARTING_EVENT = 'ovpn.MANUAL_STARTING'
const VPN_MANUAL_START_FAILED_EVENT = 'ovpn.MANUAL_START_FAILED'

@Component
export struct VpnItem {
  @Prop name: string = ''
  @Prop cfg: string = ''
  @Prop fullPath: string = ''
  @Prop remote: string = ''
  @Prop isOn: boolean = false
  @State display: boolean = false

  private manualStopFlagPath(): string {
    return `${this.getUIContext().getHostContext()?.filesDir}/${MANUAL_STOP_FLAG_FILE}`
  }

  private desiredStatePath(): string {
    return `${this.getUIContext().getHostContext()?.filesDir}/${VPN_DESIRED_STATE_FILE}`
  }

  private runtimeStatusPath(): string {
    return `${this.getUIContext().getHostContext()?.filesDir}/${VPN_RUNTIME_STATUS_FILE}`
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

  private async setDesiredVpnState(enabled: boolean) {
    const filePath = this.desiredStatePath()
    const content = JSON.stringify({
      enabled,
      cfg: enabled ? this.cfg : '',
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

  private async writeRuntimeStatus(status: string, info: string = '') {
    const filePath = this.runtimeStatusPath()
    const content = JSON.stringify({
      status,
      info,
      cfg: '',
      deviceIp: '',
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

  build() {
    Row() {
      Column() {
        Text(this.name)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(this.remote)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .margin({ top: 10 })
      }
      .width('85%')
      .alignItems(HorizontalAlign.Start)

      Toggle({ type: ToggleType.Switch, isOn: this.isOn })
        .onChange(async (isOn) => {
          if (isOn) {
            await this.startVpn()
          } else {
            await this.stopVpn()
          }
        })
    }
    .width('calc(100% - 30vp)')
    .borderRadius('15px')
    .borderWidth('1px')
    .borderColor(Color.Gray)
    .padding(15)
    .backgroundColor('#F9FAFB')
    .margin({
      top: 15
    })
  }

  async startVpn() {
    try {
      commonEventManager.publish(VPN_MANUAL_STARTING_EVENT, {
        bundleName,
        data: this.cfg
      }, () => {
      })
      await this.setManualStopRequested(false)
      await this.setDesiredVpnState(true)
      await vpnExt.startVpnExtensionAbility({ bundleName, abilityName, parameters: { cfg: this.cfg } })
      showToast(this.getUIContext(), 'start vpnExt Success', 2000);
      hilog.info(0x0000, TAG, '%{public}s', 'start vpnExt Success');
    } catch (err) {
      commonEventManager.publish(VPN_MANUAL_START_FAILED_EVENT, {
        bundleName,
        data: JSON.stringify(err)
      }, () => {
      })
      showToast(this.getUIContext(), 'start vpnExt Fail: ' + JSON.stringify(err), 2000);
      hilog.error(0x0000, TAG, 'start vpnExt Fail %{public}s', JSON.stringify(err) ?? '');
    }
  }

  async stopVpn() {
    try {
      await this.setManualStopRequested(true)
      await this.setDesiredVpnState(false)
      commonEventManager.publish('ovpn.MANUAL_STOPPING', { bundleName }, () => {
      })
      await vpnExt.stopVpnExtensionAbility({ bundleName, abilityName })
      await this.writeRuntimeStatus('disconnected')
      commonEventManager.publish('ovpn.MANUAL_STOP', { bundleName }, () => {
      })
      showToast(this.getUIContext(), 'stop vpnExt Success', 2000);
      hilog.info(0x0000, TAG, '%{public}s', 'stop vpnExt Success');
    } catch (err) {
      commonEventManager.publish('ovpn.MANUAL_STOP_FAILED', {
        bundleName,
        data: JSON.stringify(err)
      }, () => {
      })
      showToast(this.getUIContext(), 'stop vpnExt Fail: ' + JSON.stringify(err), 2000);
      hilog.error(0x0000, TAG, 'stop vpnExt Fail %{public}s', JSON.stringify(err) ?? '');
    }
  }
}
