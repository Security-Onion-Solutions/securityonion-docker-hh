import store from '../store';
import { HIDE_ALERT } from '../constants/mutation-types';

export const resetAlert = () => {
  if (store.state.alertModule.showAlert) store.commit(HIDE_ALERT);
};
