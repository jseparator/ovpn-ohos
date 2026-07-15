import fs from '@ohos.file.fs';
import { BusinessError } from '@ohos.base';
import { showToast, getSafeAreaInsets } from '../components/Common';

@Entry
@Component
struct LogTailComponent {
  @State logContent: string = 'loading...';
  @State topAvoid: number = 0;
  @State bottomAvoid: number = 0;
  private logPath: string = '';
  private isActive: boolean = true;
  private watcher?: fs.Watcher;
  private scroller: Scroller = new Scroller();

  async aboutToAppear() {
    const insets = await getSafeAreaInsets(this.getUIContext())
    this.topAvoid = insets.top
    this.bottomAvoid = insets.bottom
    this.logPath = this.getUIContext().getHostContext()?.filesDir + '/ovpn.log'
    this.startLogTail();
  }

  aboutToDisappear() {
    this.stopLogTail();
  }

  async startLogTail() {
    try {
      if (!(await this.checkFileExists())) {
        this.logContent = '日志文件不存在';
        return;
      }
      await this.readLog();

      this.watcher = fs.createWatcher(this.logPath, 0x2, async (e) => {
        if (!this.isActive) {
          return;
        }
        await this.readLog();
      })
      this.watcher.start();
    } catch (err) {
      this.logContent = `错误: ${(err as BusinessError).message}`;
    }
  }

  stopLogTail() {
    this.isActive = false;
    try {
      this.watcher?.stop()
    } catch (err) {
      console.error(`停止监听失败: ${(err as BusinessError).message}`);
    }
  }

  private async checkFileExists(): Promise<boolean> {
    try {
      const stat = await fs.stat(this.logPath);
      return stat.isFile();
    } catch {
      return false;
    }
  }

  private async readLog() {
    try {
      const fd = await fs.open(this.logPath, fs.OpenMode.READ_ONLY);
      this.logContent = await fs.readText(this.logPath, { encoding: 'utf-8' })
      await fs.close(fd);
      this.scroller.scrollEdge(Edge.Bottom);
    } catch (err) {
      this.logContent = `读取失败: ${(err as BusinessError).message}`;
    }
  }

  async clearLog() {
    try {
      await fs.truncate(this.logPath)
      this.logContent = ''
      showToast(this.getUIContext(), 'clear log success', 1000);
    } catch (e) {
      showToast(this.getUIContext(), `clearLogErr: ${JSON.stringify(e)}`, 4000);
    }
  }

  onPageShow() {
    setTimeout(() => {
      this.scroller.scrollEdge(Edge.Bottom);
    }, 1e3)
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

        Text($r('app.string.log'))
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text_primary'))
          .layoutWeight(1)

        Text('🗑️')
          .fontSize(22)
          .padding(8)
          .onClick(() => this.clearLog())
      }
      .width('100%')
      .height(56)
      .padding({ left: 12, right: 12 })
      .backgroundColor($r('app.color.top_bar_bg'))

      Scroll(this.scroller) {
        Text(this.logContent)
          .fontSize(13)
          .fontFamily('monospace')
          .textAlign(TextAlign.Start)
          .width('100%')
          .padding(12)
          .fontColor('#E0E0E0')
      }
      .scrollBar(BarState.Auto)
      .layoutWeight(1)
      .width('100%')
      .backgroundColor($r('app.color.log_bg'))
      .padding(8)

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
