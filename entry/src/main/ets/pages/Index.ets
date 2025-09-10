import hilog from '@ohos.hilog';
import { BUNDLE_NAME } from 'BuildProfile';
import { connection } from '@kit.NetworkKit';
import { picker, fileIo as fs, fileUri } from '@kit.CoreFileKit';
import { BasicDataSource, showToast } from '../components/Common';
import { BusinessError, commonEventManager } from '@kit.BasicServicesKit';
import { VpnItem } from '../components/VpnItem';

const TAG: string = '[PageIndex]'

interface connectData {
  info: string
  proxy: connection.HttpProxy
}

let ctx: UIContext
try {
  commonEventManager.createSubscriber({
    events: ['ovpn.READ_CONFIG_ERR', 'ovpn.CONNECTED', 'ovpn.DESTROY'],
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
          return;
        }
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
}

@Entry
@Component
struct Index {
  private data: BasicDataSource<ItemData> = new BasicDataSource<ItemData>();
  @State vpnConfig: string = '';

  getDir(): string {
    return this.getUIContext().getHostContext()?.filesDir + '/ovpn'
  }

  async aboutToAppear() {
    ctx = this.getUIContext()
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
        this.data.push({ name, cfg, fullPath })
      }
    } catch (e) {
      console.error(e)
    }
  }

  build() {
    Column() {
      Image($r('app.media.logo_splash'))
        .autoResize(true)
        .fitOriginalSize(true)
        .objectFit(ImageFit.CENTER)
        .width('85%')
        .height('12%')
        .margin({ top: 2 })

      List() {
        LazyForEach(this.data, (item: ItemData) => {
          ListItem() {
            VpnItem(item)
          }.width('100%')
        })
      }.width('100%').height('auto')

      Row() {
        Button('Add').onClick(async () => {
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
              this.data.push({ name: fUri.name, cfg, fullPath })
            }
          } catch (e) {
            showToast(this.getUIContext(), `fileErr: ${JSON.stringify(e)}`, 4000);
          }
        }).fontSize(24).margin({ left: 5 })

        Button('Log').onClick(async () => {
          try {
            await this.getUIContext().getRouter().pushUrl({ url: 'pages/Log' })
          } catch (e) {
            showToast(this.getUIContext(), `openLogErr: ${JSON.stringify(e)}`, 4000);
          }
        }).fontSize(24).margin({ left: 5 })

        Button('Clear').onClick(async () => {
          try {
            await fs.truncate(this.getUIContext().getHostContext()?.filesDir + '/ovpn.log')
            showToast(this.getUIContext(), `clear log success`, 1000);
          } catch (e) {
            showToast(this.getUIContext(), `clearLogErr: ${JSON.stringify(e)}`, 4000);
          }
        }).fontSize(24).margin({ left: 5 })

      }.width('90%').margin({ top: 5, bottom: 5 })

      Row(){
        Button('Browser').onClick(async () => {
          try {
            await this.getUIContext().getRouter().pushUrl({ url: 'pages/Browser' })
          } catch (e) {
            showToast(this.getUIContext(), `browserErr: ${JSON.stringify(e)}`, 4000);
          }
        }).fontSize(24).margin({ left: 5 })
      }.width('90%')
    }.width('100%').height('100%')
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
