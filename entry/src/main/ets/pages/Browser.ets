import hilog from '@ohos.hilog';
import { webview } from '@kit.ArkWeb';
import CertMgr from '../components/CertMgr';
import { showToast } from '../components/Common';

const TAG: string = '[PageBrowser]'

@Entry
@Component
struct Browser {
  private controller: webview.WebviewController = new webview.WebviewController();
  @State url: string = 'https://www.google.com/';

  async aboutToAppear() {
    webview.WebviewController.setWebDebuggingAccess(true);
  }

  aboutToDisappear() {
  }

  onBackPress(): boolean | void {
    try {
      const bfe = this.controller.getBackForwardEntries()
      if (bfe.currentIndex == 0) {
        return false
      }
      const u = bfe.getItemAtIndex(bfe.currentIndex - 1)
      this.url = u.historyUrl
      this.controller.backward()
      return true
    } catch (e) {
      hilog.error(0x0000, TAG, 'backwardErr: %{public}s', JSON.stringify(e));
      return false
    }
  }

  build() {
    Column() {
      Row() {
        Flex() {
          Button('X', { type: ButtonType.Normal, stateEffect: true }).onClick(() => {
            this.getUIContext().getRouter().back()
          }).width(50).margin({ left: 2 })
            .borderRadius({ topLeft: 8, bottomLeft: 8 })
            .fontColor(Color.Red).fontWeight(FontWeight.Bold)

          TextInput({ text: this.url })
            .onChange((v) => {
              this.url = v;
            })
            .borderRadius(0)
            .enterKeyType(EnterKeyType.Go)
            .type(InputType.URL)
            .onSubmit((_, e) => {
              this.controller.loadUrl(e.text)
            })

          Button('GO', { type: ButtonType.Normal, stateEffect: true }).onClick(() => {
            this.controller.loadUrl(this.url)
          }).width(60).margin({ right: 2 })
            .borderRadius({ topRight: 8, bottomRight: 8 })
            .fontWeight(FontWeight.Bold)
        }
      }.width('100%')

      Row() {
        Web({ src: this.url, controller: this.controller, renderMode: RenderMode.SYNC_RENDER })
          .domStorageAccess(true)
          .javaScriptAccess(true)
          .multiWindowAccess(true)
          .databaseAccess(true)
          .fileAccess(true)
          .cacheMode(CacheMode.Default)
          .darkMode(WebDarkMode.On)
          .onHttpErrorReceive((e) => {
            hilog.error(0x0000, TAG, 'WebHttpErr: %{public}s, res: %{public}s', e.request.getRequestUrl(),
              e.response.getReasonMessage());
            showToast(this.getUIContext(), `WebHttpErr: ${e.request.getRequestUrl()}, ${e.response.getReasonMessage()}`,
              3000);
          })
          .onErrorReceive((e) => {
            hilog.error(0x0000, TAG, 'WebErr: %{public}s, err: %{public}s', e.request.getRequestUrl(),
              e.error.getErrorInfo());
            showToast(this.getUIContext(), `WebErr: ${e.request.getRequestUrl()}, ${e.error.getErrorInfo()}`, 3000);
          })
          .onClientAuthenticationRequest(async (e) => {
            hilog.info(0x0000, TAG, 'ClientAuthReq: %{public}s, types: %{public}s', e.host, e.keyTypes.join(','));
            showToast(this.getUIContext(), `ClientAuthReq: ${e.host}`, 3000);
            try {
              const authUri = await CertMgr.getInstance().grantAppPm(e.host, e.issuers, e.keyTypes)
              e.handler.confirm(authUri);
            } catch (e) {
              hilog.error(0x0000, TAG, `GetPrivateCertificateErr: ${JSON.stringify(e)}`);
            }
          })
          .onSslErrorEventReceive(e => {
            hilog.error(0x0000, TAG, 'onSslErrorEventReceive: %{public}s, types: %{public}s', JSON.stringify(e.error));
            e.handler.handleConfirm()
          })
          .onOverrideUrlLoading((e) => {
            this.url = e.getRequestUrl()
            return false
          })
          .onWindowExit(() => {
            hilog.info(0x0000, TAG, "NewWebViewComp onWindowExit");
          })
          .onControllerAttached(() => {
            this.controller.setCustomUserAgent('Mozilla/5.0 (Linux; Android 12; moto g22 Build/STAS32.79-77-28-63-9; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/139.0.7258.143 Mobile Safari/537.36')
          })
          .width('100%')
          .height('100%')
      }.width('100%').height('100%')
    }.width('100%').height('100%')
  }
}

