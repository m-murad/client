// @flow
import logger from '../logger'
import * as ConfigGen from '../actions/config-gen'
import * as NotificationsGen from '../actions/notifications-gen'
import * as RPCTypes from '../constants/types/rpc-gen'
import {throttle} from 'lodash-es'
import engine from '../engine'

// We get a counter for badge state, if we get one that's less than what we've seen we toss it
let lastBadgeStateVersion = -1

const throttledDispatch = throttle((dispatch, action) => dispatch(action), 1000, {
  leading: false,
  trailing: true,
})

// TODO: DESKTOP-6662 - Move notification listeners to their own actions
export default (cb: ?Function): void => {
  engine().setIncomingActionCreators(
    'keybase.1.NotifyBadges.badgeState',
    ({badgeState}, _, dispatch, getState) => {
      if (badgeState.inboxVers < lastBadgeStateVersion) {
        logger.info(
          `Ignoring older badgeState, got ${badgeState.inboxVers} but have seen ${lastBadgeStateVersion}`
        )
        return
      }

      lastBadgeStateVersion = badgeState.inboxVers
      const conversations = badgeState.conversations
      const totalChats = (conversations || []).reduce((total, c) => total + c.unreadMessages, 0)
      const action = NotificationsGen.createReceivedBadgeState({badgeState})
      if (totalChats > 0) {
        // Defer this slightly so we don't get flashing if we're quickly receiving and reading
        throttledDispatch(dispatch, action)
      } else {
        // If clearing go immediately
        throttledDispatch.cancel()
        dispatch(action)
      }

      if (cb) {
        const count = (badgeState.conversations || []).reduce(
          (total, c) =>
            c.badgeCounts ? total + c.badgeCounts[`${RPCTypes.commonDeviceType.mobile}`] : total,
          0
        )

        cb(count)
      }
    }
  )

  engine().setIncomingActionCreators('keybase.1.NotifyTracking.trackingChanged', ({isTracking, username}) => [
    ConfigGen.createUpdateFollowing({isTracking, username}),
  ])
}
