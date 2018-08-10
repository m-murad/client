// @flow
import * as I from 'immutable'
import * as Constants from '../constants/wallets'
import * as Types from '../constants/types/wallets'
import * as WalletsGen from '../actions/wallets-gen'
import HiddenString from '../util/hidden-string'

const initialState: Types.State = Constants.makeState()

export default function(state: Types.State = initialState, action: WalletsGen.Actions) {
  switch (action.type) {
    case WalletsGen.resetStore:
      return initialState
    case WalletsGen.accountsReceived:
      const accountMap = I.Map(action.payload.accounts.map(account => [account.accountID, account]))
      return state.set('accountMap', accountMap)
    case WalletsGen.assetsReceived:
      return state.setIn(['assetsMap', action.payload.accountID], I.List(action.payload.assets))
    case WalletsGen.paymentDetailReceived:
      // $FlowIssue state.updateIn not found?
      return state.updateIn(['paymentsMap', action.payload.accountID], payments =>
        payments.update(payments.findIndex(p => p.id === action.payload.paymentID), payment =>
          payment.merge({
            publicNote: action.payload.publicNote,
            publicNoteType: action.payload.publicNoteType,
            txID: action.payload.txID,
          })
        )
      )
    case WalletsGen.paymentsReceived:
      return state.setIn(['paymentsMap', action.payload.accountID], I.List(action.payload.payments))
    case WalletsGen.displayCurrenciesReceived:
      return state.set('currencies', I.List(action.payload.currencies))
    case WalletsGen.displayCurrencyReceived:
      return state.setIn(['currencyMap', action.payload.accountID], action.payload.currency)
    case WalletsGen.secretKeyReceived:
      return state.set('exportedSecretKey', action.payload.secretKey)
    case WalletsGen.secretKeySeen:
      return state.set('exportedSecretKey', new HiddenString(''))
    case WalletsGen.selectAccount:
      return state
        .set('exportedSecretKey', new HiddenString(''))
        .set('selectedAccount', action.payload.accountID)
    case WalletsGen.validateAccountName:
      return state.merge({
        accountName: action.payload.name,
        accountNameValidationState: 'waiting',
      })
    case WalletsGen.validatedAccountName:
      if (action.payload.name !== state.accountName) {
        // this wasn't from the most recent call
        return state
      }
      return state.merge({
        accountName: '',
        accountNameError: (action.error && action.payload.error) || '',
        accountNameValidationState: action.error ? 'error' : 'valid',
      })
    case WalletsGen.validateSecretKey:
      return state.merge({
        secretKey: action.payload.secretKey,
        secretKeyValidationState: 'waiting',
      })
    case WalletsGen.validatedSecretKey:
      if (action.payload.secretKey.stringValue() !== state.secretKey.stringValue()) {
        // this wasn't from the most recent call
        return state
      }
      return state.merge({
        secretKey: new HiddenString(''),
        secretKeyError: action.error ? action.payload.error : '',
        secretKeyValidationState: action.error ? 'error' : 'valid',
      })
    case WalletsGen.clearErrors:
      return state.merge({
        accountName: '',
        accountNameError: '',
        accountNameValidationState: 'none',
        linkExistingAccountError: '',
        secretKey: new HiddenString(''),
        secretKeyError: '',
        secretKeyValidationState: 'none',
      })
    case WalletsGen.linkedExistingAccount:
      return action.error
        ? state.set('linkExistingAccountError', action.payload.error)
        : state.merge({
            accountName: '',
            accountNameError: '',
            accountNameValidationState: 'none',
            linkExistingAccountError: '',
            secretKey: new HiddenString(''),
            secretKeyError: '',
            secretKeyValidationState: 'none',
            selectedAccount: action.payload.accountID,
          })
    // Saga only actions
    case WalletsGen.exportSecretKey:
    case WalletsGen.linkExistingAccount:
    case WalletsGen.loadAssets:
    case WalletsGen.loadPaymentDetail:
    case WalletsGen.loadPayments:
    case WalletsGen.loadDisplayCurrencies:
    case WalletsGen.loadDisplayCurrency:
    case WalletsGen.changeDisplayCurrency:
    case WalletsGen.changeAccountName:
    case WalletsGen.deleteAccount:
    case WalletsGen.deleteAccount:
    case WalletsGen.loadAccounts:
      return state
    default:
      /*::
      declare var ifFlowErrorsHereItsCauseYouDidntHandleAllActionTypesAbove: (action: empty) => any
      ifFlowErrorsHereItsCauseYouDidntHandleAllActionTypesAbove(action);
      */
      return state
  }
}
