import { picker, fileIo as fs, fileUri } from '@kit.CoreFileKit';
import { showToast, getSafeAreaInsets } from '../components/Common';

@Entry
@Component
struct ImportProfile {
  @State importing: boolean = false;
  @State topAvoid: number = 0;
  @State bottomAvoid: number = 0;

  getDir(): string {
    return this.getUIContext().getHostContext()?.filesDir + '/ovpn'
  }

  async aboutToAppear() {
    const insets = await getSafeAreaInsets(this.getUIContext())
    this.topAvoid = insets.top
    this.bottomAvoid = insets.bottom
  }

  async browseAndImport() {
    if (this.importing) {
      return
    }
    this.importing = true
    try {
      const dp = new picker.DocumentViewPicker();
      const uris = await dp.select({ fileSuffixFilters: ['.ovpn'] })
      if (!uris || !uris.length) {
        this.importing = false
        return
      }
      const dir = this.getDir()
      try {
        await fs.mkdir(dir)
      } catch (e) {
      }
      for (let uri of uris) {
        const fUri = new fileUri.FileUri(uri)
        const cfg = await fs.readText(fUri.path)
        const fullPath = `${dir}/${fUri.name}`
        const fd = await fs.open(fullPath, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE)
        await fs.write(fd.fd, cfg)
        await fs.close(fd)
      }
      showToast(this.getUIContext(), 'Profile imported', 1500);
      setTimeout(() => {
        // Pass dirty flag so Index.onPageShow knows to reload profiles.
        this.getUIContext().getRouter().back({ url: 'pages/Index', params: { profilesDirty: true } })
      }, 400)
    } catch (e) {
      showToast(this.getUIContext(), `fileErr: ${JSON.stringify(e)}`, 4000);
    } finally {
      this.importing = false
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

        Text($r('app.string.import_profile'))
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text_primary'))
          .layoutWeight(1)
      }
      .width('100%')
      .height(56)
      .padding({ left: 12, right: 16 })
      .backgroundColor($r('app.color.top_bar_bg'))

      Row() {
        Column() {
          Text($r('app.string.import_file_tab'))
            .fontSize(14)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.ovpn_orange'))
          Divider()
            .strokeWidth(2)
            .color($r('app.color.ovpn_orange'))
            .margin({ top: 10 })
        }
        .padding({ left: 20, right: 20, top: 14 })
      }
      .width('100%')
      .backgroundColor($r('app.color.card_bg'))

      Column({ space: 20 }) {
        Text($r('app.string.browse_hint'))
          .fontSize(15)
          .fontColor($r('app.color.text_secondary'))
          .textAlign(TextAlign.Center)
          .padding({ left: 24, right: 24 })

        Button(this.importing ? '...' : $r('app.string.browse'))
          .backgroundColor($r('app.color.ovpn_orange'))
          .fontColor(Color.White)
          .fontSize(16)
          .width('70%')
          .enabled(!this.importing)
          .onClick(() => this.browseAndImport())
      }
      .width('100%')
      .layoutWeight(1)
      .justifyContent(FlexAlign.Center)
      .backgroundColor($r('app.color.page_bg'))

      Row()
        .width('100%')
        .height(this.bottomAvoid)
        .backgroundColor($r('app.color.page_bg'))
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.page_bg'))
    .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
  }
}
