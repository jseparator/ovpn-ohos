import fs from '@ohos.file.fs';
import { BusinessError } from '@ohos.base';

@Builder
export function LogBuilder(name: string, param: Object) {
  Log()
}

@Component
export struct Log {
  @State logContent: string = 'loading...';
  private logPath: string = ''; // 日志文件路径
  private isActive: boolean = true;
  private watcher?: fs.Watcher;
  private scroller: Scroller = new Scroller();

  // 组件创建时开始监听
  aboutToAppear() {
    this.logPath = this.getUIContext().getHostContext()?.filesDir + '/ovpn.log'
    this.startLogTail();
  }

  // 组件销毁时停止监听
  aboutToDisappear() {
    this.stopLogTail();
  }

  // 开始日志监听
  async startLogTail() {
    try {
      // 检查文件是否存在
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

  // 停止日志监听
  stopLogTail() {
    this.isActive = false;
    try {
      this.watcher?.stop()
    } catch (err) {
      console.error(`停止监听失败: ${(err as BusinessError).message}`);
    }
  }

  // 检查文件是否存在
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

  onPageShow() {

  }

  build() {
    NavDestination() {
      Scroll(this.scroller) {
        Text(this.logContent)
          .fontSize(16)
          .textAlign(TextAlign.Start)
          .width('100%')
          .padding(10)
          .fontColor(Color.White)
          .backgroundColor(Color.Black)
      }
      .scrollBar(BarState.Off)
      .width('100%')
      .height('100%')
    }
    .title('日志')
    .onShown(() => {
      setTimeout(() => {
        console.log('滚到末尾')
        this.scroller.scrollEdge(Edge.Bottom);
      }, 1000)
    })
  }
}