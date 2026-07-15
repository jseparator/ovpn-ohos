import hilog from '@ohos.hilog';
import { fileIo as fs } from '@kit.CoreFileKit';
import { getSafeAreaInsets } from '../components/Common';
import { displayName, saveProfile } from '../components/VpnItem';

const TAG: string = '[PageEditProfile]'

interface EditParams {
  name: string
  path: string
}

@Entry
@Component
struct EditProfile {
  @State editName: string = '';
  @State editCfg: string = '';
  @State editPath: string = '';
  @State topAvoid: number = 0;
  @State bottomAvoid: number = 0;
  private saving: boolean = false;

  async aboutToAppear() {
    const insets = await getSafeAreaInsets(this.getUIContext())
    this.topAvoid = insets.top
    this.bottomAvoid = insets.bottom

    const params = this.getUIContext().getRouter().getParams() as EditParams | null
    this.editName = params?.name ?? ''
    this.editPath = params?.path ?? ''
    try {
      // Always load latest from disk — in-memory copy / TextArea cache can be stale.
      this.editCfg = await fs.readText(this.editPath)
    } catch (e) {
      hilog.error(0x0000, TAG, `readCfg fail: ${JSON.stringify(e)}`)
    }
  }

  async onSave() {
    if (this.saving) {
      return
    }
    this.saving = true
    try {
      const ok = await saveProfile(this.editPath, this.editCfg, this.getUIContext())
      if (ok) {
        // Tell Index to reload profiles from disk when it comes back into view.
        this.getUIContext().getRouter().back({ url: 'pages/Index', params: { profilesDirty: true } })
      }
    } finally {
      this.saving = false
    }
  }

  build() {
    Column() {
      Row()
        .width('100%')
        .height(this.topAvoid)
        .backgroundColor($r('app.color.top_bar_bg'))

      Row() {
        Text('‹')
          .fontSize(28)
          .fontColor($r('app.color.ovpn_orange'))
          .padding({ right: 8 })
          .onClick(() => {
            this.getUIContext().getRouter().back()
          })

        Text(displayName(this.editName))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text_primary'))
          .layoutWeight(1)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })

        Text('💾')
          .fontSize(22)
          .padding({ left: 12 })
          .onClick(() => this.onSave())
      }
      .width('100%')
      .height(56)
      .padding({ left: 16, right: 16 })
      .backgroundColor($r('app.color.top_bar_bg'))

      TextArea({ text: this.editCfg })
        .onChange((value: string) => {
          this.editCfg = value
        })
        .width('100%')
        .layoutWeight(1)
        .backgroundColor($r('app.color.card_bg'))
        .borderRadius(0)
        .fontColor($r('app.color.text_primary'))
        .padding({ left: 12, right: 12, top: 12, bottom: 12 + this.bottomAvoid })
        .fontSize(14)
        .fontFamily('monospace')
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.page_bg'))
    .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
  }
}
