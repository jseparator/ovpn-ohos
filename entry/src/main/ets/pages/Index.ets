import hilog from '@ohos.hilog';
import { BUNDLE_NAME } from 'BuildProfile';
import { connection, vpnExtension as vpnExt } from '@kit.NetworkKit';
import { picker, fileIo as fs, fileUri } from '@kit.CoreFileKit';
import { BasicDataSource, showToast } from '../components/Common';
import { BusinessError, commonEventManager } from '@kit.BasicServicesKit';
import { VpnItem } from '../components/VpnItem';
import VPNTools from '../tools/VPNTools'

const TAG: string = '[PageIndex]'
const VPN_ABILITY_NAME: string = 'OvpnExtAbility'
const VPN_DESIRED_STATE_FILE = 'ovpn-desired-state.json'
const STATUS_HEARTBEAT_EXPIRE_MS = 10_000

interface connectData {
  info: string
  proxy: connection.HttpProxy
  deviceIp?: string
}

interface vpnRuntimeStatus {
  status?: string
  info?: string
  deviceIp?: string
  cfg?: string
  updatedAt?: number
}

interface vpnDesiredState {
  enabled?: boolean
  cfg?: string
}

let ctx: UIContext
let vpnEventHandler: ((event: string, payload?: string) => void) | undefined = undefined
try {
  commonEventManager.createSubscriber({
    events: ['ovpn.READ_CONFIG_ERR', 'ovpn.CONNECTED', 'ovpn.DESTROY', 'ovpn.MANUAL_STOPPING', 'ovpn.MANUAL_STOP',
      'ovpn.MANUAL_STOP_FAILED', 'ovpn.MANUAL_STARTING', 'ovpn.MANUAL_START_FAILED'],
    publisherBundleName: BUNDLE_NAME
  },
    (err: BusinessError, subscriber: commonEventManager.CommonEventSubscriber) => {
      if (err) {
        hilog.error(0x0000, TAG, `createSubscriberErr: ${err.code}, name: ${err.name}, msg: ${err.message}`);
        return
      }
      commonEventManager.subscribe(subscriber, (err: BusinessError, data: commonEventManager.CommonEventData) => {
        if (err) {
          hilog.error(0x0000, TAG, `subscribe event err: ${err.code}, name: ${err.name}, msg: ${err.message}`);
          return
        }
        if (data.event === 'ovpn.CONNECTED' && data.data) {
          const s = data.data as string
          const d = JSON.parse(s) as connectData;
          hilog.info(0x0000, TAG, `Connected: ${d.info}`);
          showToast(ctx, `Connected: ${d.info}`, 3000);
          if (d.proxy?.host) {
            setVpnNet(d.proxy)
          }
        } else if (data.event === 'ovpn.READ_CONFIG_ERR') {
          showToast(ctx, `Connect fail: ${data.data}`, 3000);
        }
        vpnEventHandler?.(data.event, data.data as string | undefined)
        hilog.info(0x0000, TAG, `subscribe event: ${data.event}, data: ${data.data}`);
      })
    });
} catch (e) {
  hilog.error(0x0000, TAG, `createSubscriber failed, code is ${JSON.stringify(e)}`);
}

interface ItemData {
  name: string
  cfg: string
  fullPath: string
  remote?: string
}

@Entry
@Component
struct Index {
  private data: BasicDataSource<ItemData> = new BasicDataSource<ItemData>();
  @State vpnConfig: string = '';
  @State profileCount: number = 0;
  @State connectionStatus: string = '未连接';
  @State currentDeviceIp: string = '-';
  @State activeProfileCfg: string = '';
  @Provide('navPathStack') navPathStack: NavPathStack = new NavPathStack();

  getDir(): string {
    return this.getUIContext().getHostContext()?.filesDir + '/ovpn'
  }

  getStatusFilePath(): string {
    return this.getUIContext().getHostContext()?.filesDir + '/ovpn-status.json'
  }

  getDesiredStateFilePath(): string {
    return this.getUIContext().getHostContext()?.filesDir + `/${VPN_DESIRED_STATE_FILE}`
  }

  async aboutToAppear() {
    ctx = this.getUIContext()
    vpnEventHandler = (event: string, payload?: string) => {
      if (event === 'ovpn.CONNECTED' && payload) {
        const d = JSON.parse(payload) as connectData
        this.connectionStatus = '已连接'
        this.currentDeviceIp = this.normalizeDeviceIp(d.deviceIp) ?? this.extractDeviceIpFromText(d.info) ?? '-'
        return
      }
      if (event === 'ovpn.MANUAL_STARTING' && payload) {
        this.activeProfileCfg = payload
        this.connectionStatus = '连接中...'
        this.currentDeviceIp = '-'
        return
      }
      if (event === 'ovpn.MANUAL_START_FAILED') {
        this.activeProfileCfg = ''
        this.connectionStatus = '连接失败'
        this.currentDeviceIp = '-'
        return
      }
      if (event === 'ovpn.MANUAL_STOPPING') {
        this.connectionStatus = '断开中...'
        this.activeProfileCfg = ''
        this.currentDeviceIp = '-'
        return
      }
      if (event === 'ovpn.MANUAL_STOP') {
        this.connectionStatus = '已断开'
        this.activeProfileCfg = ''
        this.currentDeviceIp = '-'
        return
      }
      if (event === 'ovpn.MANUAL_STOP_FAILED') {
        this.connectionStatus = '断开失败'
        return
      }
      if (event === 'ovpn.DESTROY') {
        this.connectionStatus = '已断开'
        this.activeProfileCfg = ''
        this.currentDeviceIp = '-'
        return
      }
      if (event === 'ovpn.READ_CONFIG_ERR') {
        this.connectionStatus = '连接失败'
        this.activeProfileCfg = ''
        this.currentDeviceIp = '-'
      }
    }

    await this.syncStatusFromRuntime()
    await this.restoreDesiredVpnConnection()

    const dir = this.getDir()
    try {
      await fs.mkdir(dir)
    } catch (e) {
    }
    try {
      const files = await fs.listFile(dir)
      for (let name of files) {
        const fullPath = dir + '/' + name
        const cfg = await fs.readText(fullPath)
        const remote = VPNTools.clientRemoteIP(cfg)
        this.data.push({
          name,
          cfg,
          fullPath,
          remote
        })
      }
      this.profileCount = this.data.totalCount()
    } catch (e) {
      console.error(e)
    }
  }

  aboutToDisappear(): void {
    vpnEventHandler = undefined
  }

  private extractDeviceIpFromText(text?: string): string | undefined {
    if (!text) {
      return undefined
    }
    const matches = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g)
    if (!matches?.length) {
      return undefined
    }
    const vpnIp = matches.find((ip: string) => ip.startsWith('10.'))
    return vpnIp
  }

  private normalizeDeviceIp(ip?: string): string | undefined {
    if (!ip || !ip.startsWith('10.')) {
      return undefined
    }
    return ip
  }

  private async syncStatusFromRuntime() {
    try {
      const text = await fs.readText(this.getStatusFilePath())
      const status = JSON.parse(text) as vpnRuntimeStatus
      const current = status.status ?? ''
      const isStatusFresh = !!status.updatedAt && Date.now() - status.updatedAt <= STATUS_HEARTBEAT_EXPIRE_MS
      if (current === 'connected') {
        if (!isStatusFresh) {
          this.connectionStatus = '已断开'
          this.activeProfileCfg = ''
          this.currentDeviceIp = '-'
          return
        }
        this.connectionStatus = '已连接'
        this.activeProfileCfg = status.cfg ?? ''
        this.currentDeviceIp = this.normalizeDeviceIp(status.deviceIp) ?? this.extractDeviceIpFromText(status.info) ?? '-'
        return
      }
      if (current === 'connecting') {
        if (!isStatusFresh) {
          this.connectionStatus = '已断开'
          this.activeProfileCfg = ''
          this.currentDeviceIp = '-'
          return
        }
        this.connectionStatus = '连接中...'
        this.activeProfileCfg = status.cfg ?? ''
        this.currentDeviceIp = '-'
        return
      }
      if (current === 'failed') {
        this.connectionStatus = '连接失败'
        this.activeProfileCfg = ''
        this.currentDeviceIp = '-'
        return
      }
      if (current === 'disconnected') {
        this.connectionStatus = '已断开'
        this.activeProfileCfg = ''
        this.currentDeviceIp = '-'
        return
      }
      this.connectionStatus = '未连接'
      this.activeProfileCfg = ''
      this.currentDeviceIp = '-'
    } catch (e) {
      this.connectionStatus = '未连接'
      this.activeProfileCfg = ''
      this.currentDeviceIp = '-'
    }
  }

  private async restoreDesiredVpnConnection() {
    try {
      const text = await fs.readText(this.getDesiredStateFilePath())
      const desired = JSON.parse(text) as vpnDesiredState
      if (!desired.enabled || !desired.cfg) {
        this.activeProfileCfg = ''
        return
      }
      this.activeProfileCfg = desired.cfg
      if (this.connectionStatus === '已连接' || this.connectionStatus === '连接中...') {
        return
      }
      this.connectionStatus = '连接中...'
      await vpnExt.startVpnExtensionAbility({
        bundleName: BUNDLE_NAME,
        abilityName: VPN_ABILITY_NAME,
        parameters: { cfg: desired.cfg }
      })
    } catch (_) {
    }
  }

  private isToggleOn(item: ItemData): boolean {
    if (this.connectionStatus !== '已连接' && this.connectionStatus !== '连接中...') {
      return false
    }
    if (!this.activeProfileCfg) {
      return false
    }
    return item.cfg === this.activeProfileCfg
  }

  private statusColor(): string {
    if (this.connectionStatus.startsWith('已连接')) {
      return '#16A34A'
    }
    if (this.connectionStatus.includes('失败')) {
      return '#DC2626'
    }
    if (this.connectionStatus.includes('中') || this.connectionStatus.includes('请求')) {
      return '#2563EB'
    }
    return '#6B7280'
  }

  private async pickAndImportProfiles() {
    try {
      const dp = new picker.DocumentViewPicker();
      const uris = await dp.select({ fileSuffixFilters: ['.ovpn'] })
      if (!uris || !uris.length) {
        return
      }
      const dir = this.getDir()
      for (let uri of uris) {
        const fUri = new fileUri.FileUri(uri)
        const cfg = await fs.readText(fUri.path)
        const fullPath = `${dir}/${fUri.name}`
        const fd = await fs.open(fullPath, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE)
        await fs.write(fd.fd, cfg)
        await fs.close(fd)
        const remote = VPNTools.clientRemoteIP(cfg)
        this.data.push({
          name: fUri.name,
          cfg,
          fullPath,
          remote
        })
      }
      this.profileCount = this.data.totalCount()
    } catch (e) {
      showToast(this.getUIContext(), `fileErr: ${JSON.stringify(e)}`, 4000);
    }
  }

  build() {
    Navigation(this.navPathStack) {
      Column({ space: 12 }) {
        Column({ space: 12 }) {
          Row({ space: 12 }) {
            Row() {
              Image($r('app.media.uploadfile'))
                .width(20)
                .height(20)
            }
            .width(40)
            .height(40)
            .borderRadius(12)
            .backgroundColor('#E8EEFF')
            .justifyContent(FlexAlign.Center)

            Column({ space: 4 }) {
              Text('导入 VPN 配置')
                .fontSize(18)
                .fontWeight(FontWeight.Bold)
                .fontColor('#1E293B')
              Text('选择 .ovpn 文件后即可在下方列表快速连接')
                .fontSize(13)
                .fontColor('#64748B')
                .maxLines(2)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)
          }
          .width('100%')

          Button({ type: ButtonType.Capsule, stateEffect: true }) {
            Row({ space: 10 }) {
              Row() {
                Image($r('app.media.uploadfile'))
                  .width(18)
                  .height(18)
              }
              .width(32)
              .height(32)
              .borderRadius(16)
              .backgroundColor('#FFFFFF26')
              .justifyContent(FlexAlign.Center)

              Column({ space: 2 }) {
                Text('导入配置文件')
                  .fontSize(15)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(Color.White)
                Text('支持选择多个 .ovpn')
                  .fontSize(11)
                  .fontColor('#DBEAFE')
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Text('去选择')
                .fontSize(12)
                .fontColor('#DBEAFE')
            }
            .width('100%')
          }
          .width('100%')
          .height(56)
          .backgroundColor('#1E40AF')
          .borderRadius(18)
          .borderWidth('1px')
          .borderColor('#1D4ED8')
          .padding({
            left: 14,
            right: 14
          })
          .onClick(async () => {
            await this.pickAndImportProfiles()
          })
        }
        .width('100%')
        .backgroundColor(Color.White)
        .padding({
          top: 18,
          right: 16,
          bottom: 18,
          left: 16
        })
        .borderRadius(20)
        .borderWidth('1px')
        .borderColor('#E5E7EB')

        Row() {
          Text('配置列表')
            .fontSize(18)
            .fontWeight(FontWeight.Bold)
            .fontColor('#111827')
          Text(`${this.profileCount} 个配置`)
            .fontSize(13)
            .fontColor('#6B7280')
        }
        .width('100%')
        .padding({
          left: 4,
          right: 4
        })
        .justifyContent(FlexAlign.SpaceBetween)

        if (this.profileCount > 0) {
          List({ space: 0 }) {
            LazyForEach(this.data, (item: ItemData) => {
              ListItem() {
                VpnItem({
                  name: item.name,
                  cfg: item.cfg,
                  fullPath: item.fullPath,
                  remote: item.remote ?? '',
                  isOn: this.isToggleOn(item)
                })
              }
              .width('100%')
              .gesture(
                LongPressGesture()
                  .onAction((event: GestureEvent) => {
                    this.getUIContext().showAlertDialog({
                      title: '温馨提示',
                      message: '您确定删除当前配置文件吗？',
                      primaryButton: {
                        value: '确定',
                        action: () => {

                        }
                      },
                      secondaryButton: {
                        value: '取消',
                        defaultFocus: true,
                        action: () => {

                        }
                      },
                      cancel: () => {

                      }
                    })
                  })
              )
            })
          }
          .width('100%')
          .layoutWeight(1)
          .margin({
            top: 4
          })
          .edgeEffect(EdgeEffect.Spring)
          .divider({
            strokeWidth: 0,
            color: Color.Transparent,
            startMargin: 0,
            endMargin: 0
          })
          .scrollBar(BarState.Off)
        } else {
          Column({ space: 10 }) {
            Image($r('app.media.uploadfile'))
              .width(36)
              .height(36)
              .opacity(0.45)
            Text('还没有可用配置')
              .fontSize(16)
              .fontWeight(FontWeight.Medium)
              .fontColor('#374151')
            Text('点击上方按钮导入 .ovpn 文件后即可连接')
              .fontSize(13)
              .fontColor('#9CA3AF')
          }
          .width('100%')
          .layoutWeight(1)
          .justifyContent(FlexAlign.Center)
          .alignItems(HorizontalAlign.Center)
          .margin({
            top: 8
          })
        }

        Column({ space: 10 }) {
          Column({ space: 4 }) {
            Text('当前连接状态')
              .fontSize(13)
              .fontColor('#6B7280')
            Text(this.connectionStatus)
              .fontSize(14)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.statusColor())
              .maxLines(2)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)

          Column({ space: 4 }) {
            Text('当前设备 IP')
              .fontSize(13)
              .fontColor('#6B7280')
            Text(this.currentDeviceIp)
              .fontSize(14)
              .fontWeight(FontWeight.Medium)
              .fontColor('#111827')
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .padding({
          top: 12,
          right: 14,
          bottom: 12,
          left: 14
        })
        .backgroundColor(Color.White)
        .borderRadius(14)
        .borderWidth('1px')
        .borderColor('#E5E7EB')
      }
      .width('100%')
      .height('100%')
      .padding(12)
      .backgroundColor('#F3F5F8')
    }
    .title('OpenVPN Connect')
    .backgroundColor('#F3F5F8')
    .mode(NavigationMode.Stack)
    .menus([
      {
        value: '日志',
        icon: $r('app.media.history_log'),
        action: async () => {
          this.navPathStack.pushPathByName('Log', '')
        }
      },
      {
        value: '清理',
        icon: $r('app.media.log_clear'),
        action: async () => {
          try {
            await fs.truncate(this.getUIContext().getHostContext()?.filesDir + '/ovpn.log')
            showToast(this.getUIContext(), `clear log success`, 1000);
          } catch (e) {
            showToast(this.getUIContext(), `clearLogErr: ${JSON.stringify(e)}`, 4000);
          }
        }
      }
    ])
  }
}

async function setVpnNet(proxy: connection.HttpProxy) {
  try {
    proxy.exclusionList = ['10.', '192.168', '172.16']
    connection.setAppHttpProxy(proxy)
  } catch (e) {
    hilog.error(0x0000, TAG, 'SetAppHttpProxyErr: %{public}s', JSON.stringify(e));
  }
}
