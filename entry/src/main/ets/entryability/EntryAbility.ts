/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import AbilityConstant from "@ohos.app.ability.AbilityConstant";
import hilog from "@ohos.hilog";
import UIAbility from "@ohos.app.ability.UIAbility";
import Want from "@ohos.app.ability.Want";
import { window } from "@kit.ArkUI";
import { BusinessError } from "@kit.BasicServicesKit";

/** Match app.color.top_bar_bg — status bar sits right above the in-app top bar. */
const STATUS_BAR_BG = "#252525";

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    hilog.info(0x0000, "testTag", "%{public}s", "Ability onCreate");
  }

  onDestroy() {
    hilog.info(0x0000, "testTag", "%{public}s", "Ability onDestroy");
  }

  private async applySystemBars(win: window.Window) {
    try {
      // Full-screen so page background can paint behind status / nav bars.
      await win.setWindowLayoutFullScreen(true);
      win.setWindowBackgroundColor(STATUS_BAR_BG);
      await win.setWindowSystemBarProperties({
        statusBarContentColor: "#FFFFFF",
        navigationBarContentColor: "#FFFFFF",
      });
      hilog.info(0x0000, "testTag", "system bars applied");
    } catch (e) {
      hilog.error(
        0x0000,
        "testTag",
        "applySystemBars failed: %{public}s",
        JSON.stringify(e),
      );
    }
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    hilog.info(0x0000, "testTag", "%{public}s", "Ability onWindowStageCreate");

    windowStage.loadContent("pages/Index", async (err: BusinessError) => {
      if (err && err.code) {
        hilog.error(
          0x0000,
          "testTag",
          "Failed to load the content. Cause: %{public}s",
          JSON.stringify(err) ?? "",
        );
        return;
      }
      try {
        const win = await windowStage.getMainWindow();
        await this.applySystemBars(win);
      } catch (e) {
        hilog.error(
          0x0000,
          "testTag",
          "getMainWindow after load failed: %{public}s",
          JSON.stringify(e),
        );
      }
    });
  }

  onWindowStageDestroy() {
    hilog.info(0x0000, "testTag", "%{public}s", "Ability onWindowStageDestroy");
  }

  onForeground() {
    hilog.info(0x0000, "testTag", "%{public}s", "Ability onForeground");
  }

  onBackground() {
    hilog.info(0x0000, "testTag", "%{public}s", "Ability onBackground");
  }
}
