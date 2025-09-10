import hilog from '@ohos.hilog';
import { BUNDLE_NAME } from 'BuildProfile';
import { vpnExtension as vpnExt } from '@kit.NetworkKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { showToast } from '../components/Common';

const TAG: string = '[ItemVpn]'
const bundleName = BUNDLE_NAME
const abilityName = 'OvpnExtAbility'

@Component
export struct VpnItem {
  @Prop name: string = ''
  @Prop cfg: string = ''
  @Prop fullPath: string = ''
  @State display: boolean = false
  @State isOn: boolean = false

  build() {
    Column() {
      Row() {
        Text(this.name)
        Button(this.display ? 'Hide' : 'Show').onClick(() => {
          this.display = !this.display
        }).buttonStyle(ButtonStyleMode.TEXTUAL).position({ right: 0 })
      }.width('90%').height(30)
      .margin({ top: 2, bottom: 2 })

      if (this.display) {
        Row() {
          TextArea({ text: this.cfg }).onChange((value) => {
            this.cfg = value;
          }).width('100%')
        }.width('90%').height(200)
        .margin({ top: 2, bottom: 2 })

        Row() {
          Toggle({ type: ToggleType.Switch, isOn: this.isOn })
            .onChange(async (isOn) => {
              this.isOn = isOn
              if (isOn) {
                await this.startVpn()
              } else {
                await this.stopVpn()
              }
            })

          Button('Save').onClick(async () => {
            try {
              const fd = await fs.open(this.fullPath, fs.OpenMode.TRUNC | fs.OpenMode.READ_WRITE)
              await fs.write(fd.fd, this.cfg)
              await fs.close(fd)
              showToast(this.getUIContext(), 'Save Success', 1000);
            } catch (e) {
              showToast(this.getUIContext(), `Save Failed: ${JSON.stringify(e)}`, 2000);
              hilog.error(0x0000, TAG, 'SaveBtnErr: %{public}s', JSON.stringify(e));
            }
          }).fontSize(24).margin({ left: 5 })
        }
      }
    }
  }

  async startVpn() {
    try {
      await vpnExt.startVpnExtensionAbility({ bundleName, abilityName, parameters: { cfg: this.cfg }})
      showToast(this.getUIContext(), 'start vpnExt Success', 2000);
      hilog.info(0x0000, TAG, '%{public}s', 'start vpnExt Success');
    } catch (err) {
      showToast(this.getUIContext(), 'start vpnExt Fail: ' + JSON.stringify(err), 2000);
      hilog.error(0x0000, TAG, 'start vpnExt Fail %{public}s', JSON.stringify(err) ?? '');
    }
  }

  async stopVpn() {
    try {
      await vpnExt.stopVpnExtensionAbility({ bundleName, abilityName })
      showToast(this.getUIContext(), 'stop vpnExt Success', 2000);
      hilog.info(0x0000, TAG, '%{public}s', 'stop vpnExt Success');
    } catch (err) {
      showToast(this.getUIContext(), 'stop vpnExt Fail: ' + JSON.stringify(err), 2000);
      hilog.error(0x0000, TAG, 'stop vpnExt Fail %{public}s', JSON.stringify(err) ?? '');
    }
  }
}
