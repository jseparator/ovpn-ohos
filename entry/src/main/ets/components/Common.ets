/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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

import { window } from '@kit.ArkUI';
import { common } from '@kit.AbilityKit';

export interface SafeAreaInsets {
  top: number;
  bottom: number;
}

/** Top/bottom safe-area insets (in vp), for pages that draw behind the status/nav bars. */
export async function getSafeAreaInsets(ctx: UIContext): Promise<SafeAreaInsets> {
  try {
    const hostCtx = ctx.getHostContext() as common.UIAbilityContext
    const win = await window.getLastWindow(hostCtx)
    const sys = win.getWindowAvoidArea(window.AvoidAreaType.TYPE_SYSTEM)
    const nav = win.getWindowAvoidArea(window.AvoidAreaType.TYPE_NAVIGATION_INDICATOR)
    return { top: ctx.px2vp(sys.topRect.height), bottom: ctx.px2vp(nav.bottomRect.height) }
  } catch (e) {
    return { top: 0, bottom: 0 }
  }
}

export function showToast(ctx: UIContext, msg: string, dur: number) {
  try {
    ctx.getPromptAction().showToast({
      message: msg,
      duration: dur
    })
  } catch (error) {
    console.log('showToastErr: ', error)
  }
}

/** Same as AppScope/app.json5 bundleName; avoids BuildProfile (build-generated) import. */
export const BUNDLE_NAME: string = 'com.im5v.vpn';

// BasicDataSource实现了IDataSource接口，用于管理listener监听，以及通知LazyForEach数据更新
export class BasicDataSource<T> implements IDataSource {
  private listeners: DataChangeListener[] = [];
  private data: T[] = [];

  public add(index: number, data: T): void {
    this.data.splice(index, 0, data);
    this.notifyDataAdd(index);
  }

  public push(data: T): void {
    this.data.push(data);
    this.notifyDataAdd(this.data.length - 1);
  }

  public remove(index: number): void {
    if (index < 0 || index >= this.data.length) {
      return;
    }
    this.data.splice(index, 1);
    this.notifyDataDelete(index);
  }

  public clear(): void {
    this.data = [];
    this.notifyDataReload();
  }

  public replaceAll(items: T[]): void {
    this.data = items.slice();
    this.notifyDataReload();
  }

  public totalCount(): number {
    return this.data.length;
  }

  public indexOf(predicate: (item: T) => boolean): number {
    for (let i = 0; i < this.data.length; i++) {
      if (predicate(this.data[i])) {
        return i;
      }
    }
    return -1;
  }

  public getData(index: number): T {
    return this.data[index];
  }

  // 该方法为框架侧调用，为LazyForEach组件向其数据源处添加listener监听
  registerDataChangeListener(listener: DataChangeListener): void {
    if (this.listeners.indexOf(listener) < 0) {
      this.listeners.push(listener);
    }
  }

  // 该方法为框架侧调用，为对应的LazyForEach组件在数据源处去除listener监听
  unregisterDataChangeListener(listener: DataChangeListener): void {
    const pos = this.listeners.indexOf(listener);
    if (pos >= 0) {
      this.listeners.splice(pos, 1);
    }
  }

  // 通知LazyForEach组件需要重载所有子组件
  notifyDataReload(): void {
    this.listeners.forEach(listener => {
      listener.onDataReloaded();
    })
  }

  // 通知LazyForEach组件需要在index对应索引处添加子组件
  notifyDataAdd(index: number): void {
    this.listeners.forEach(listener => {
      listener.onDataAdd(index);
      // 写法2：listener.onDatasetChange([{type: DataOperationType.ADD, index: index}]);
    })
  }

  // 通知LazyForEach组件在index对应索引处数据有变化，需要重建该子组件
  notifyDataChange(index: number): void {
    this.listeners.forEach(listener => {
      listener.onDataChange(index);
      // 写法2：listener.onDatasetChange([{type: DataOperationType.CHANGE, index: index}]);
    })
  }

  // 通知LazyForEach组件需要在index对应索引处删除该子组件
  notifyDataDelete(index: number): void {
    this.listeners.forEach(listener => {
      listener.onDataDelete(index);
      // 写法2：listener.onDatasetChange([{type: DataOperationType.DELETE, index: index}]);
    })
  }

  // 通知LazyForEach组件将from索引和to索引处的子组件进行交换
  notifyDataMove(from: number, to: number): void {
    this.listeners.forEach(listener => {
      listener.onDataMove(from, to);
      // 写法2：listener.onDatasetChange(
      //         [{type: DataOperationType.EXCHANGE, index: {start: from, end: to}}]);
    })
  }

  notifyDatasetChange(operations: DataOperation[]): void {
    this.listeners.forEach(listener => {
      listener.onDatasetChange(operations);
    })
  }
}