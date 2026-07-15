import hilog from '@ohos.hilog';
import { vpnExtension as vpnExt } from '@kit.NetworkKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { showToast, BUNDLE_NAME } from '../components/Common';

const TAG: string = '[ItemVpn]'
const bundleName = BUNDLE_NAME
const abilityName = 'OvpnExtAbility'
const DELETE_WIDTH: number = 76

export function displayName(fileName: string): string {
  if (fileName.endsWith('.ovpn')) {
    return fileName.substring(0, fileName.length - 5)
  }
  return fileName
}

/** Parse first `remote <host>` from ovpn config. */
export function parseRemoteHost(cfg: string): string {
  const lines = cfg.split('\n')
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim()
    if (line.startsWith('#') || line.startsWith(';')) {
      continue
    }
    if (line.toLowerCase().startsWith('remote ')) {
      const parts = line.split(/\s+/)
      if (parts.length >= 2) {
        return parts[1]
      }
    }
  }
  return ''
}

@Component
export struct VpnItem {
  @Prop name: string = ''
  @Prop remoteHost: string = ''
  @Prop isActive: boolean = false
  @Prop isConnecting: boolean = false
  @Prop showEdit: boolean = true
  onToggle: (on: boolean) => void = (_on: boolean) => {}
  onEdit: () => void = () => {}
  onDelete: () => void = () => {}

  @State private offsetX: number = 0
  // Measured from the content row — percentage height inside a List item resolves
  // against the scrollable viewport, not the item's own size, so we track it manually.
  @State private rowHeight: number = 72
  private dragStartOffset: number = 0

  private closeSwipe() {
    this.getUIContext().animateTo({ duration: 200, curve: Curve.EaseOut }, () => {
      this.offsetX = 0
    })
  }

  private confirmDelete() {
    this.getUIContext().getPromptAction().showDialog({
      title: 'Delete Profile',
      message: `Delete "${displayName(this.name)}"? This cannot be undone.`,
      buttons: [
        { text: 'Cancel', color: '#FFFFFF' },
        { text: 'Delete', color: '#EF5350' }
      ]
    }).then((result) => {
      if (result.index === 1) {
        this.onDelete()
      } else {
        this.closeSwipe()
      }
    }).catch(() => {
      this.closeSwipe()
    })
  }

  build() {
    Stack({ alignContent: Alignment.End }) {
      // Revealed when the row is swiped left.
      Row() {
        Text($r("app.string.delete"))
          .fontColor(Color.White)
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
      }
      .width(DELETE_WIDTH)
      .height(this.rowHeight)
      .justifyContent(FlexAlign.Center)
      .backgroundColor('#EF5350')
      // Slide in from off-screen in lockstep with the content's drag offset,
      // instead of sitting static behind it and merely getting uncovered.
      .translate({ x: DELETE_WIDTH + this.offsetX })
      .onClick(() => {
        this.confirmDelete()
      })

      Column() {
        Row({ space: 12 }) {
          Toggle({ type: ToggleType.Switch, isOn: this.isActive })
            .selectedColor($r('app.color.toggle_on'))
            .onChange((isOn: boolean) => {
              this.onToggle(isOn)
            })

          Column() {
            Text('OpenVPN Profile')
              .fontSize(16)
              .fontColor($r('app.color.text_primary'))
              .fontWeight(FontWeight.Medium)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .width('100%')

            if (this.remoteHost.length > 0) {
              Text(this.remoteHost)
                .fontSize(13)
                .fontColor($r('app.color.text_secondary'))
                .margin({ top: 2 })
                .maxLines(1)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
                .width('100%')
            }

            Text(`[${displayName(this.name)}]`)
              .fontSize(13)
              .fontColor($r('app.color.text_secondary'))
              .margin({ top: 2 })
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .width('100%')

            if (this.isActive && this.isConnecting) {
              Text('CONNECTING…')
                .fontSize(12)
                .fontColor($r('app.color.status_connecting'))
                .margin({ top: 4 })
            }
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1)

          if (this.showEdit) {
            Text('✏️')
              .fontSize(18)
              .padding(6)
              .onClick(() => {
                this.onEdit()
              })
          }
        }
        .width('100%')
        .padding({ left: 16, right: 12, top: 14, bottom: 14 })
        .backgroundColor($r('app.color.card_bg'))

        Divider()
          .strokeWidth(1)
          .color($r('app.color.divider'))
          .margin({ left: 16 })
      }
      .width('100%')
      .backgroundColor($r('app.color.card_bg'))
      .translate({ x: this.offsetX })
      .onAreaChange((_oldArea: Area, newArea: Area) => {
        this.rowHeight = Number(newArea.height)
      })
      .gesture(
        PanGesture({ direction: PanDirection.Horizontal })
          .onActionStart(() => {
            this.dragStartOffset = this.offsetX
          })
          .onActionUpdate((event: GestureEvent) => {
            const next = this.dragStartOffset + event.offsetX
            this.offsetX = Math.min(0, Math.max(-DELETE_WIDTH, next))
          })
          .onActionEnd(() => {
            const open = this.offsetX < -DELETE_WIDTH / 2
            this.getUIContext().animateTo({ duration: 200, curve: Curve.EaseOut }, () => {
              this.offsetX = open ? -DELETE_WIDTH : 0
            })
          })
      )
    }
    .width('100%')
    .clip(true)
  }
}

/** Persist active profile so Extension can recover after VPN auth dialog restart. */
export async function persistActiveConfig(cfg: string, filesDir: string): Promise<void> {
  const path = filesDir + '/ovpn.active.cfg'
  try {
    const fd = await fs.open(path, fs.OpenMode.CREATE | fs.OpenMode.TRUNC | fs.OpenMode.READ_WRITE)
    await fs.write(fd.fd, cfg)
    await fs.close(fd)
  } catch (e) {
    hilog.error(0x0000, TAG, 'persistActiveConfig fail: %{public}s', JSON.stringify(e));
  }
}

export async function startVpn(cfg: string, filesDir: string, uiCtx: UIContext): Promise<boolean> {
  try {
    // Auth dialog may restart Extension and drop want.parameters — persist first.
    await persistActiveConfig(cfg, filesDir)
    await vpnExt.startVpnExtensionAbility({
      bundleName,
      abilityName,
      parameters: { cfg, filesDir }
    })
    hilog.info(0x0000, TAG, '%{public}s', 'start vpnExt Success');
    return true
  } catch (err) {
    showToast(uiCtx, 'start vpnExt Fail: ' + JSON.stringify(err), 2000);
    hilog.error(0x0000, TAG, 'start vpnExt Fail %{public}s', JSON.stringify(err) ?? '');
    return false
  }
}

export async function stopVpn(uiCtx: UIContext): Promise<boolean> {
  try {
    await vpnExt.stopVpnExtensionAbility({ bundleName, abilityName })
    hilog.info(0x0000, TAG, '%{public}s', 'stop vpnExt Success');
    return true
  } catch (err) {
    showToast(uiCtx, 'stop vpnExt Fail: ' + JSON.stringify(err), 2000);
    hilog.error(0x0000, TAG, 'stop vpnExt Fail %{public}s', JSON.stringify(err) ?? '');
    return false
  }
}

export async function saveProfile(fullPath: string, cfg: string, uiCtx: UIContext): Promise<boolean> {
  try {
    const fd = await fs.open(fullPath, fs.OpenMode.CREATE | fs.OpenMode.TRUNC | fs.OpenMode.READ_WRITE)
    await fs.write(fd.fd, cfg)
    await fs.close(fd)
    showToast(uiCtx, 'Save Success', 1000);
    return true
  } catch (e) {
    showToast(uiCtx, `Save Failed: ${JSON.stringify(e)}`, 2000);
    hilog.error(0x0000, TAG, 'SaveBtnErr: %{public}s', JSON.stringify(e));
    return false
  }
}
