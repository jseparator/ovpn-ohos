import { common, Want, bundleManager } from '@kit.AbilityKit';
import hilog from '@ohos.hilog';

const TAG: string = '[CertMgr]'

export default class CertMgr {
  private static sInstance: CertMgr;
  private abilityCtx?: common.UIAbilityContext;
  private appUid = "";

  public static getInstance(): CertMgr {
    if (CertMgr.sInstance == null) {
      CertMgr.sInstance = new CertMgr();
    }
    return CertMgr.sInstance;
  }

  public setUiAbilityContext(ctx: common.UIAbilityContext): void {
    this.abilityCtx = ctx;
  }

  async grantAppPm(host: string, issuers: string[], keyTypes: string[]) {
    if (!this.appUid) {
      let bundleFlags = bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT
        | bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION;
      const data = await bundleManager.getBundleInfoForSelf(bundleFlags)
      hilog.info(0x0000, TAG, 'getBundleInfoForSelf successfully. Data: %{public}s', JSON.stringify(data));
      this.appUid = data.appInfo.uid.toString();
    }

    const res = await this.abilityCtx?.startAbilityForResult({
      bundleName: "com.ohos.certmanager",
      abilityName: "MainAbility",
      uri: "requestAuthorize",
      parameters: {
        appUid: this.appUid, // 传入申请应用的appUid
        host
      }
    } as Want)
    if (!res.resultCode && res.want && res.want.parameters) {
      return res.want.parameters.authUri as string; // 授权成功后获取返回的authUri
    }
    throw new Error('Failed')
  }
}