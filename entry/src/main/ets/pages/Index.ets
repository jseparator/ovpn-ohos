import hilog from '@ohos.hilog';
import { BUNDLE_NAME } from 'BuildProfile';
import { connection } from '@kit.NetworkKit';
import { picker, fileIo as fs, fileUri } from '@kit.CoreFileKit';
import { BasicDataSource, showToast } from '../components/Common';
import { router } from '@kit.ArkUI';
import { BusinessError, commonEventManager } from '@kit.BasicServicesKit';
import { VpnItem } from '../components/VpnItem';

const TAG: string = '[PageIndex]'

interface connectData {
  info: string
  proxy: connection.HttpProxy
}

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
          if (d.proxy.host) {
            AlertDialog.show({
              title: `AutoSetProxy`,
              message: `SetProxy to ${d.proxy.host}:${d.proxy.port}`,
              primaryButton: {
                value: 'Yes',
                async action() {
                  hilog.info(0x0000, TAG, `SetProxy: ${d.proxy.host}:${d.proxy.port}`);
                  setVpnNet(d.proxy)
                }
              },
              secondaryButton: {
                value: 'No',
                action() {
                }
              }
            })
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
    return getContext(this).filesDir + '/ovpn'
  }

  async aboutToAppear() {
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
            const dp = new picker.DocumentViewPicker(getContext(this));
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
            showToast(`fileErr: ${JSON.stringify(e)}`, 4000);
          }
        }).fontSize(24).margin({ left: 5 })

        Button('Browser').onClick(async () => {
          try {
            await router.pushUrl({ url: 'pages/Browser' })
          } catch (e) {
            showToast(`browserErr: ${JSON.stringify(e)}`, 4000);
          }
        }).fontSize(24).margin({ left: 5 })
      }.width('90%').height('12%')
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
