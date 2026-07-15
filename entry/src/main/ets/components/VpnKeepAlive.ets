/*
 * Keep the UI process alive while VPN is connected.
 * System stops VpnExtensionAbility when the caller process exits.
 */

import { backgroundTaskManager } from '@kit.BackgroundTasksKit';
import { wantAgent } from '@kit.AbilityKit';
import { BusinessError } from '@kit.BasicServicesKit';
import hilog from '@ohos.hilog';
import { BUNDLE_NAME } from './Common';

const TAG = '[VpnKeepAlive]'
let running = false

export async function startVpnKeepAlive(context: Context): Promise<void> {
  if (running) {
    return
  }
  try {
    const wantAgentInfo: wantAgent.WantAgentInfo = {
      wants: [{
        bundleName: BUNDLE_NAME,
        abilityName: 'EntryAbility'
      }],
      operationType: wantAgent.OperationType.START_ABILITY,
      requestCode: 0,
      wantAgentFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
    }
    const agent = await wantAgent.getWantAgent(wantAgentInfo)
    await backgroundTaskManager.startBackgroundRunning(
      context,
      backgroundTaskManager.BackgroundMode.DATA_TRANSFER,
      agent
    )
    running = true
    hilog.info(0x0000, TAG, 'startBackgroundRunning ok')
  } catch (e) {
    const err = e as BusinessError
    hilog.error(0x0000, TAG, `startBackgroundRunning fail: ${err.code} ${err.message}`)
  }
}

export async function stopVpnKeepAlive(context: Context): Promise<void> {
  if (!running) {
    return
  }
  try {
    await backgroundTaskManager.stopBackgroundRunning(context)
    hilog.info(0x0000, TAG, 'stopBackgroundRunning ok')
  } catch (e) {
    const err = e as BusinessError
    hilog.error(0x0000, TAG, `stopBackgroundRunning fail: ${err.code} ${err.message}`)
  } finally {
    running = false
  }
}
