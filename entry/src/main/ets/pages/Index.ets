import hilog from '@ohos.hilog';
import { connection } from '@kit.NetworkKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { BasicDataSource, showToast, BUNDLE_NAME, getSafeAreaInsets } from '../components/Common';
import { BusinessError, commonEventManager } from '@kit.BasicServicesKit';
import {
  VpnItem,
  parseRemoteHost,
  startVpn,
  stopVpn
} from '../components/VpnItem';
import { startVpnKeepAlive, stopVpnKeepAlive } from '../components/VpnKeepAlive';

const TAG: string = '[PageIndex]'
const RATE_HISTORY_MAX: number = 40

interface connectData {
  info: string
  pac: string
  proxy: connection.HttpProxy
}

interface StatsData {
  bytesIn: number
  bytesOut: number
}

interface ItemData {
  name: string
  cfg: string
  fullPath: string
  remoteHost: string
}

function formatDuration(totalSec: number): string {
  const h = Math.floor(totalSec / 3600)
  const m = Math.floor((totalSec % 3600) / 60)
  const s = totalSec % 60
  const pad = (n: number): string => (n < 10 ? `0${n}` : `${n}`)
  return `${pad(h)}:${pad(m)}:${pad(s)}`
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${Math.max(0, Math.round(bytes))} B`
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`
  }
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) {
    return `${Math.max(0, Math.round(bytesPerSec))} B/S`
  }
  if (bytesPerSec < 1024 * 1024) {
    return `${(bytesPerSec / 1024).toFixed(2)} KB/S`
  }
  return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/S`
}

@Entry
@Component
struct Index {
  private data: BasicDataSource<ItemData> = new BasicDataSource<ItemData>();
  @State profileCount: number = 0;
  @State connState: string = 'idle';
  @State activeProfile: string = '';
  @State activeRemote: string = '';
  @State connectInfo: string = '';
  @State durationText: string = '00:00:00';
  @State rateInText: string = '0 B/S';
  @State rateOutText: string = '0 B/S';
  @State bytesInText: string = '0 B';
  @State bytesOutText: string = '0 B';
  @State rateAxisText: string = '0 B/S';
  @State rateHistory: number[] = [];
  @State rateHistoryMax: number = 1;
  @State disconnectedItems: ItemData[] = [];
  @State disconnectedExpanded: boolean = false;
  @State topAvoid: number = 0;
  @State bottomAvoid: number = 0;
  private connectedAt: number = 0;
  private durationTimer: number = -1;
  private loadingProfiles: boolean = false;
  private firstPageShow: boolean = true;
  private profilesDirty: boolean = false;
  private lastBytesIn: number = 0;
  private lastBytesOut: number = 0;
  private lastStatsAt: number = 0;
  private subscriber?: commonEventManager.CommonEventSubscriber;

  getDir(): string {
    return this.getUIContext().getHostContext()?.filesDir + '/ovpn'
  }

  async aboutToAppear() {
    await this.initSafeArea()
    await this.loadProfiles()
    this.subscribeEvents()
  }

  async initSafeArea() {
    const insets = await getSafeAreaInsets(this.getUIContext())
    this.topAvoid = insets.top
    this.bottomAvoid = insets.bottom
  }

  aboutToDisappear() {
    this.stopDurationTimer()
    if (this.subscriber) {
      try {
        commonEventManager.unsubscribe(this.subscriber)
      } catch (e) {
      }
    }
  }

  onPageShow() {
    if (this.firstPageShow) {
      this.firstPageShow = false
      return
    }
    // ImportProfile sets profilesDirty=true via router.back params.
    const params = this.getUIContext().getRouter().getParams() as Record<string, boolean> | null
    if (params?.profilesDirty) {
      this.profilesDirty = true
    }
    if (this.profilesDirty) {
      this.profilesDirty = false
      this.loadProfiles().then(() => {
        // Editing the active profile's config can change its remote host display.
        if (this.activeProfile) {
          const item = this.findActiveItem()
          if (item) {
            this.activeRemote = item.remoteHost
          }
        }
      })
    }
    if (this.connState === 'connected' && this.connectedAt > 0) {
      this.refreshDuration()
    }
  }

  async loadProfiles() {
    if (this.loadingProfiles) {
      return
    }
    this.loadingProfiles = true
    const dir = this.getDir()
    try {
      await fs.mkdir(dir)
    } catch (e) {
    }
    try {
      const files = await fs.listFile(dir)
      const items: ItemData[] = []
      for (let name of files) {
        const fullPath = dir + '/' + name
        const cfg = await fs.readText(fullPath)
        items.push({ name, cfg, fullPath, remoteHost: parseRemoteHost(cfg) })
      }
      this.data.replaceAll(items)
      this.profileCount = this.data.totalCount()
    } catch (e) {
      console.error(e)
      this.profileCount = this.data.totalCount()
    } finally {
      this.loadingProfiles = false
    }
  }

  subscribeEvents() {
    try {
      commonEventManager.createSubscriber({
        events: ['ovpn.READ_CONFIG_ERR', 'ovpn.CONNECTED', 'ovpn.DESTROY', 'ovpn.STATS', 'ovpn.ERROR'],
        publisherBundleName: BUNDLE_NAME
      },
        (err: BusinessError, subscriber: commonEventManager.CommonEventSubscriber) => {
          if (err) {
            hilog.error(0x0000, TAG, `createSubscriberErr: ${err.code}, name: ${err.name}, msg: ${err.message}`);
            return
          }
          this.subscriber = subscriber
          commonEventManager.subscribe(subscriber, (err: BusinessError, data: commonEventManager.CommonEventData) => {
            if (err) {
              hilog.error(0x0000, TAG, `subscribe event err: ${err.code}, name: ${err.name}, msg: ${err.message}`);
              return
            }
            this.handleEvent(data)
          })
        });
    } catch (e) {
      hilog.error(0x0000, TAG, `createSubscriber failed, code is ${JSON.stringify(e)}`);
    }
  }

  handleEvent(data: commonEventManager.CommonEventData) {
    if (data.event === 'ovpn.CONNECTED' && data.data) {
      try {
        const d = JSON.parse(data.data as string) as connectData;
        hilog.info(0x0000, TAG, `Connected: ${d.info}`);
        this.connectInfo = d.info
        this.connState = 'connected'
        this.connectedAt = Date.now()
        this.disconnectedExpanded = false
        this.lastBytesIn = 0
        this.lastBytesOut = 0
        this.lastStatsAt = 0
        this.rateHistory = []
        this.bytesInText = '0 B'
        this.bytesOutText = '0 B'
        this.rateInText = '0 B/S'
        this.rateOutText = '0 B/S'
        this.startDurationTimer()
        const hostCtx = this.getUIContext().getHostContext()
        if (hostCtx) {
          startVpnKeepAlive(hostCtx)
        }
        if (d.pac) {
          try {
            connection.setPacUrl(d.pac)
          } catch (e) {
            hilog.error(0x0000, TAG, 'SetPacErr: %{public}s', JSON.stringify(e));
          }
        }
        if (d.proxy?.host) {
          setVpnNet(d.proxy)
        }
      } catch (e) {
        hilog.error(0x0000, TAG, `parse CONNECTED err: ${JSON.stringify(e)}`);
      }
      return
    }
    if (data.event === 'ovpn.STATS' && data.data) {
      this.applyStatsJson(data.data as string)
      return
    }
    if (data.event === 'ovpn.DESTROY') {
      const hostCtx = this.getUIContext().getHostContext()
      if (hostCtx) {
        stopVpnKeepAlive(hostCtx)
      }
      this.resetConnection()
      return
    }
    if (data.event === 'ovpn.ERROR') {
      const reason = (data.data as string) ?? 'VPN error'
      hilog.error(0x0000, TAG, `VPN ERROR: ${reason}`)
      // Transient disconnects are auto-retried in native; only surface fatal errors.
      showToast(this.getUIContext(), reason, 3000)
      const hostCtx = this.getUIContext().getHostContext()
      if (hostCtx) {
        stopVpnKeepAlive(hostCtx)
      }
      stopVpn(this.getUIContext()).finally(() => {
        this.resetConnection()
      })
      return
    }
    if (data.event === 'ovpn.READ_CONFIG_ERR') {
      showToast(this.getUIContext(), `Config error: ${data.data}`, 3000)
      const hostCtx = this.getUIContext().getHostContext()
      if (hostCtx) {
        stopVpnKeepAlive(hostCtx)
      }
      this.resetConnection()
      return
    }
    hilog.info(0x0000, TAG, `subscribe event: ${data.event}, data: ${data.data}`);
  }

  applyStatsJson(jsonText: string) {
    try {
      const s = JSON.parse(jsonText) as StatsData
      const bytesIn = Number(s.bytesIn) || 0
      const bytesOut = Number(s.bytesOut) || 0
      const now = Date.now()
      let rateIn = 0
      let rateOut = 0
      if (this.lastStatsAt > 0) {
        const dt = (now - this.lastStatsAt) / 1000
        if (dt > 0.2) {
          rateIn = Math.max(0, (bytesIn - this.lastBytesIn) / dt)
          rateOut = Math.max(0, (bytesOut - this.lastBytesOut) / dt)
        }
      }
      this.lastBytesIn = bytesIn
      this.lastBytesOut = bytesOut
      this.lastStatsAt = now
      this.bytesInText = formatBytes(bytesIn)
      this.bytesOutText = formatBytes(bytesOut)
      this.rateInText = formatRate(rateIn)
      this.rateOutText = formatRate(rateOut)
      const peak = Math.max(rateIn, rateOut, 1)
      this.rateAxisText = formatRate(peak)
      const next = this.rateHistory.slice()
      next.push(rateIn + rateOut)
      if (next.length > RATE_HISTORY_MAX) {
        next.shift()
      }
      this.rateHistory = next
      // Update peak cache so barHeight() doesn't scan the array on every render.
      this.rateHistoryMax = Math.max(1, ...next)
      this.refreshDuration()
    } catch (e) {
      hilog.error(0x0000, TAG, `parse STATS err: ${jsonText}`);
    }
  }

  /** Duration = now - connectedAt (wall clock), not a +1 counter. */
  refreshDuration() {
    if (this.connectedAt <= 0) {
      this.durationText = '00:00:00'
      return
    }
    const elapsedSec = Math.max(0, Math.floor((Date.now() - this.connectedAt) / 1000))
    this.durationText = formatDuration(elapsedSec)
  }

  startDurationTimer() {
    this.stopDurationTimer()
    this.refreshDuration()
    const tick = (): void => {
      if (this.connState !== 'connected' || this.connectedAt <= 0) {
        this.durationTimer = -1
        return
      }
      this.refreshDuration()
      this.durationTimer = setTimeout(tick, 1000) as number
    }
    this.durationTimer = setTimeout(tick, 1000) as number
  }

  stopDurationTimer() {
    if (this.durationTimer >= 0) {
      clearTimeout(this.durationTimer)
      this.durationTimer = -1
    }
  }

  resetConnection() {
    this.stopDurationTimer()
    this.connState = 'idle'
    this.activeProfile = ''
    this.activeRemote = ''
    this.connectInfo = ''
    this.durationText = '00:00:00'
    this.rateInText = '0 B/S'
    this.rateOutText = '0 B/S'
    this.bytesInText = '0 B'
    this.bytesOutText = '0 B'
    this.rateAxisText = '0 B/S'
    this.rateHistory = []
    this.rateHistoryMax = 1
    this.disconnectedItems = []
    this.lastBytesIn = 0
    this.lastBytesOut = 0
    this.lastStatsAt = 0
    this.disconnectedExpanded = false
  }

  async handleToggle(item: ItemData, on: boolean) {
    if (on) {
      if (this.activeProfile === item.name && this.connState !== 'idle') {
        return
      }
      if (this.connState !== 'idle' && this.activeProfile !== item.name) {
        await stopVpn(this.getUIContext())
        const hostCtx = this.getUIContext().getHostContext()
        if (hostCtx) {
          await stopVpnKeepAlive(hostCtx)
        }
        this.resetConnection()
      }
      this.activeProfile = item.name
      this.activeRemote = item.remoteHost
      this.connState = 'connecting'
      this.disconnectedItems = this.buildDisconnectedItems()
      this.rateInText = '0 B/S'
      this.rateOutText = '0 B/S'
      const filesDir = this.getUIContext().getHostContext()?.filesDir ?? ''
      const ok = await startVpn(item.cfg, filesDir, this.getUIContext())
      if (!ok) {
        this.resetConnection()
      }
    } else {
      if (this.activeProfile !== item.name || this.connState === 'idle') {
        return
      }
      await stopVpn(this.getUIContext())
      const hostCtx = this.getUIContext().getHostContext()
      if (hostCtx) {
        await stopVpnKeepAlive(hostCtx)
      }
      this.resetConnection()
    }
  }

  async deleteProfile(item: ItemData) {
    try {
      if (this.activeProfile === item.name) {
        await stopVpn(this.getUIContext())
        const hostCtx = this.getUIContext().getHostContext()
        if (hostCtx) {
          await stopVpnKeepAlive(hostCtx)
        }
        this.resetConnection()
      }
      await fs.unlink(item.fullPath)
      const idx = this.data.indexOf((d) => d.fullPath === item.fullPath)
      if (idx >= 0) {
        this.data.remove(idx)
      }
      this.profileCount = this.data.totalCount()
    } catch (e) {
      showToast(this.getUIContext(), `Delete failed: ${JSON.stringify(e)}`, 2000)
    }
  }

  goEdit(item: ItemData) {
    this.getUIContext().getRouter().pushUrl({
      url: 'pages/EditProfile',
      params: { name: item.name, path: item.fullPath }
    }).catch((e: Error) => {
      showToast(this.getUIContext(), `openEditErr: ${JSON.stringify(e)}`, 4000);
    })
  }

  goImport() {
    this.getUIContext().getRouter().pushUrl({ url: 'pages/ImportProfile' }).catch((e: Error) => {
      showToast(this.getUIContext(), `openImportErr: ${JSON.stringify(e)}`, 4000);
    })
  }

  goLog() {
    this.getUIContext().getRouter().pushUrl({ url: 'pages/Log' }).catch((e: Error) => {
      showToast(this.getUIContext(), `openLogErr: ${JSON.stringify(e)}`, 4000);
    })
  }

  findActiveItem(): ItemData | undefined {
    for (let i = 0; i < this.data.totalCount(); i++) {
      const item = this.data.getData(i)
      if (item.name === this.activeProfile) {
        return item
      }
    }
    return undefined
  }

  @Builder
  TopBar() {
    Row() {
      Text('☰')
        .fontSize(22)
        .fontColor($r('app.color.text_primary'))
        .padding({ left: 4, right: 16, top: 8, bottom: 8 })

      Text($r('app.string.profiles_title'))
        .fontSize(20)
        .fontWeight(FontWeight.Bold)
        .fontColor($r('app.color.text_primary'))
        .layoutWeight(1)

      Text('📄')
        .fontSize(20)
        .padding(8)
        .onClick(() => this.goLog())
    }
    .width('100%')
    .height(56)
    .padding({ left: 12, right: 12 })
    .backgroundColor($r('app.color.top_bar_bg'))
  }

  @Builder
  SectionHeader(title: string, expandable: boolean, expanded: boolean, onTap: () => void) {
    Row() {
      Text(title)
        .fontSize(13)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.text_secondary'))
        .letterSpacing(1)
      Blank()
      if (expandable) {
        Text(expanded ? '⌃' : '⌄')
          .fontSize(16)
          .fontColor($r('app.color.text_secondary'))
      }
    }
    .width('100%')
    .padding({ left: 16, right: 16, top: 8, bottom: 8 })
    .onClick(() => {
      if (expandable) {
        onTap()
      }
    })
  }

  @Builder
  EmptyState() {
    Column({ space: 12 }) {
      Text($r('app.string.empty_profiles'))
        .fontSize(20)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.text_primary'))

      Text($r('app.string.empty_profiles_hint'))
        .fontSize(14)
        .fontColor($r('app.color.text_secondary'))
        .textAlign(TextAlign.Center)
        .padding({ left: 32, right: 32 })

      Button($r('app.string.import_profile'))
        .backgroundColor($r('app.color.ovpn_orange'))
        .fontColor(Color.White)
        .fontSize(16)
        .margin({ top: 8 })
        .onClick(() => this.goImport())
    }
    .width('100%')
    .layoutWeight(1)
    .justifyContent(FlexAlign.Center)
  }

  @Builder
  ProfileRow(item: ItemData) {
    VpnItem({
      name: item.name,
      remoteHost: item.remoteHost,
      isActive: this.activeProfile === item.name && this.connState !== 'idle',
      isConnecting: this.activeProfile === item.name && this.connState === 'connecting',
      showEdit: true,
      onToggle: (on: boolean) => {
        this.handleToggle(item, on)
      },
      onEdit: () => {
        this.goEdit(item)
      },
      onDelete: () => {
        this.deleteProfile(item)
      }
    })
  }

  @Builder
  IdleProfiles() {
    Column() {
      this.SectionHeader('DISCONNECTED', false, false, () => {
      })

      List() {
        LazyForEach(this.data, (item: ItemData) => {
          ListItem() {
            this.ProfileRow(item)
          }
          .width('100%')
        }, (item: ItemData) => item.fullPath)
      }
      .width('100%')
      .layoutWeight(1)
      .divider({ strokeWidth: 0 })
    }
    .width('100%')
    .layoutWeight(1)
  }

  @Builder
  ConnectedView() {
    Scroll() {
      Column() {
        this.SectionHeader('CONNECTED', false, false, () => {
        })

        VpnItem({
          name: this.activeProfile,
          remoteHost: this.activeRemote,
          isActive: true,
          isConnecting: this.connState === 'connecting',
          showEdit: true,
          onToggle: (on: boolean) => {
            if (!on) {
              stopVpn(this.getUIContext())
              const hostCtx = this.getUIContext().getHostContext()
              if (hostCtx) {
                stopVpnKeepAlive(hostCtx)
              }
              this.resetConnection()
            }
          },
          onEdit: () => {
            const item = this.findActiveItem()
            if (item) {
              this.goEdit(item)
            }
          },
          onDelete: () => {
            const item = this.findActiveItem()
            if (item) {
              this.deleteProfile(item)
            }
          }
        })

        this.SectionHeader('DISCONNECTED', true, this.disconnectedExpanded, () => {
          this.disconnectedExpanded = !this.disconnectedExpanded
        })

        if (this.disconnectedExpanded) {
          ForEach(this.disconnectedItems, (item: ItemData) => {
            this.ProfileRow(item)
          }, (item: ItemData) => item.fullPath)
        }

        if (this.connState === 'connected') {
          this.ConnectionStats()
        } else if (this.connState === 'connecting') {
          Column() {
            LoadingProgress()
              .width(36)
              .height(36)
              .color($r('app.color.ovpn_orange'))
            Text('CONNECTING…')
              .fontSize(14)
              .fontColor($r('app.color.status_connecting'))
              .margin({ top: 12 })
          }
          .width('100%')
          .padding(32)
          .alignItems(HorizontalAlign.Center)
        }
      }
      .width('100%')
      .justifyContent(FlexAlign.Start)
    }
    .width('100%')
    .layoutWeight(1)
    .scrollBar(BarState.Off)
    .align(Alignment.Top)
  }

  buildDisconnectedItems(): ItemData[] {
    const result: ItemData[] = []
    for (let i = 0; i < this.data.totalCount(); i++) {
      const item = this.data.getData(i)
      if (item.name !== this.activeProfile) {
        result.push(item)
      }
    }
    return result
  }

  @Builder
  ConnectionStats() {
    Column() {
      Text('CONNECTION STATS')
        .fontSize(13)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.text_secondary'))
        .letterSpacing(1)
        .width('100%')
        .padding({ left: 16, right: 16, top: 16, bottom: 8 })

      // Sparkline chart
      Column() {
        Text(this.rateAxisText)
          .fontSize(11)
          .fontColor($r('app.color.text_secondary'))
          .width('100%')
          .textAlign(TextAlign.Start)

        Row() {
          ForEach(this.rateHistory, (v: number) => {
            Column()
              .width(5)
              .height(this.barHeight(v))
              .backgroundColor($r('app.color.rate_in'))
              .borderRadius(1)
              .margin({ left: 0.5, right: 0.5 })
          }, (v: number, idx: number) => `rh-${idx}-${v}`)
        }
        .width('100%')
        .height(88)
        .alignItems(VerticalAlign.Bottom)
        .justifyContent(FlexAlign.End)

        Text('0 B/S')
          .fontSize(11)
          .fontColor($r('app.color.text_secondary'))
          .width('100%')
          .textAlign(TextAlign.Start)
          .margin({ top: 4 })
      }
      .width('100%')
      .padding({ left: 16, right: 16, bottom: 10 })
      .backgroundColor($r('app.color.stats_bg'))

      Divider()
        .strokeWidth(1)
        .color($r('app.color.divider'))

      // Stats row 1: BYTES IN | BYTES OUT
      Row() {
        Column({ space: 4 }) {
          Row() {
            Text('BYTES IN')
              .fontSize(11)
              .fontWeight(FontWeight.Bold)
              .fontColor($r('app.color.text_secondary'))
              .letterSpacing(0.8)
            Blank()
            Text('↓')
              .fontSize(26)
              .fontColor($r('app.color.rate_in'))
          }
          .width('100%')

          Text(this.rateInText)
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('app.color.rate_in'))

          Text(this.bytesInText)
            .fontSize(12)
            .fontColor($r('app.color.text_secondary'))
        }
        .layoutWeight(1)
        .alignItems(HorizontalAlign.Start)
        .padding({ left: 16, right: 12, top: 14, bottom: 14 })

        Column()
          .width(1)
          .height(68)
          .backgroundColor($r('app.color.divider'))

        Column({ space: 4 }) {
          Row() {
            Text('BYTES OUT')
              .fontSize(11)
              .fontWeight(FontWeight.Bold)
              .fontColor($r('app.color.text_secondary'))
              .letterSpacing(0.8)
            Blank()
            Text('↑')
              .fontSize(26)
              .fontColor($r('app.color.rate_out'))
          }
          .width('100%')

          Text(this.rateOutText)
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('app.color.rate_out'))

          Text(this.bytesOutText)
            .fontSize(12)
            .fontColor($r('app.color.text_secondary'))
        }
        .layoutWeight(1)
        .alignItems(HorizontalAlign.Start)
        .padding({ left: 16, right: 12, top: 14, bottom: 14 })
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)

      Divider()
        .strokeWidth(1)
        .color($r('app.color.divider'))

      // Stats row 2: DURATION
      Row() {
        Column({ space: 6 }) {
          Text('DURATION')
            .fontSize(11)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('app.color.text_secondary'))
            .letterSpacing(0.8)

          Text(this.durationText)
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('app.color.text_primary'))
        }
        .layoutWeight(1)
        .alignItems(HorizontalAlign.Start)
        .padding({ left: 16, right: 12, top: 14, bottom: 14 })
      }
      .width('100%')
    }
    .width('100%')
    .margin({ top: 8 })
  }

  barHeight(v: number): number {
    const h = Math.floor((Math.max(0, v) / this.rateHistoryMax) * 68)
    return h < 2 ? 2 : h
  }

  @Builder
  Fab() {
    Button('+')
      .width(56)
      .height(56)
      .borderRadius(28)
      .fontSize(28)
      .fontColor(Color.White)
      .backgroundColor($r('app.color.ovpn_orange'))
      .shadow({ radius: 8, color: '#4DEA7D26', offsetY: 3 })
      .position({ right: 20, bottom: 28 + this.bottomAvoid })
      .onClick(() => this.goImport())
  }

  build() {
    Stack({ alignContent: Alignment.TopEnd }) {
      Column() {
        // Fill status-bar area with the same color as the top bar below it
        Row()
          .width('100%')
          .height(this.topAvoid)
          .backgroundColor($r('app.color.top_bar_bg'))

        this.TopBar()

        if (this.profileCount === 0 && this.connState === 'idle') {
          this.EmptyState()
        } else if (this.connState !== 'idle') {
          this.ConnectedView()
        } else {
          this.IdleProfiles()
        }

        // Fill gesture / nav-bar area with the same page color
        Row()
          .width('100%')
          .height(this.bottomAvoid)
          .backgroundColor($r('app.color.page_bg'))
      }
      .width('100%')
      .height('100%')
      .backgroundColor($r('app.color.page_bg'))

      this.Fab()
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.page_bg'))
    .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
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
