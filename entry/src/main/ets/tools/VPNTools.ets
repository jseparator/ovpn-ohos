class VPNTools {
  public clientRemoteIP(cfg: string): string {
    const strs = cfg.split('\n')
    const remoteItem = strs.filter(item => item.includes('remote'))
    if (remoteItem && remoteItem.length > 0) {
      let remote = remoteItem[0]
      const remoteEles = remote.split(' ')
      if (remoteEles && remoteEles.length > 2) {
        remote = remoteEles[1]
        return remote
      }
      return ''
    }
    return ''
  }
}

export default new VPNTools()