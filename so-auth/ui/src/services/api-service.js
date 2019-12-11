import Vue from 'vue';
import store from '../store';
import { SET_ALERT, SHOW_ALERT, STORE_API_RESPONSE } from '../constants/mutation-types';

export const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

export const handleHtpError = (error) => {
  if (error != null) {
    if (error.response) {
      store.commit(STORE_API_RESPONSE, error.response.data);
      if (error.response.status < 500) {
        store.commit(SET_ALERT, { type: 'error', message: store.state.apiResponseModule.message });
      } else store.commit(SET_ALERT, { type: 'warning', message: store.state.apiResponseModule.message });
    } else {
      store.commit(SET_ALERT, { type: 'error', message: 'No response from server' });
    }
    store.commit(SHOW_ALERT);
  }
};

export const handleHttpResponse = (res) => {
  if (res != null) {
    store.commit(STORE_API_RESPONSE, res.data);
    store.commit(SET_ALERT, { type: 'success', message: store.state.apiResponseModule.message });
    store.commit(SHOW_ALERT);
  }
};

export const createUser = (username, password) => {
  const data = {
    username,
    password,
  };

  return Vue.prototype.$axios.post('/users/create_user', data);
};

export const register = (username, password) => {
  const data = {
    username,
    password,
  };

  return Vue.prototype.$axios.post('/auth/register', data);
};

export const loginUser = (username, password, rememberMe) => {
  const data = {
    username,
    password,
    remember_me: rememberMe,
  };

  return Vue.prototype.$axios.post('/auth/login', data);
};

export const changePassword = (username, oldPassword, newPassword) => {
  const data = {
    username,
    old_password: oldPassword,
    new_password: newPassword,
  };

  return Vue.prototype.$axios.put('/users/change_password', data);
};
