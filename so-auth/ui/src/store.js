import Vue from 'vue';
import Vuex from 'vuex';
import VuexPersistence from 'vuex-persist';

import {
  HIDE_ALERT,
  RESET_FIRST_RUN,
  SET_ALERT,
  SET_FIRST_RUN,
  SHOW_ALERT,
  STORE_API_RESPONSE,
} from './constants/mutation-types';
import { CHECK_FIRST_RUN } from './constants/action-types';

Vue.use(Vuex);

const vuexLocal = new VuexPersistence({
  storage: window.localStorage,
});

const apiResponseModule = {
  state: {
    status: 'status',
    message: 'message',
  },
  mutations: {
    [STORE_API_RESPONSE](state, apiResponse) {
      state.status = apiResponse.status;
      state.message = apiResponse.message;
    },
  },
};

const alertModule = {
  state: {
    alertType: 'alertType',
    message: 'message',
    showAlert: false,
  },
  mutations: {
    [SET_ALERT](state, { type, message }) {
      state.alertType = type;
      state.message = message;
    },
    [SHOW_ALERT](state) { state.showAlert = true; },
    [HIDE_ALERT](state) { state.showAlert = false; },
  },
};

const globalModule = {
  state: {
    firstRun: true,
  },
  mutations: {
    [SET_FIRST_RUN](state, isFirstRun) {
      state.firstRun = isFirstRun;
    },
    [RESET_FIRST_RUN](state) {
      state.firstRun = true;
    },
  },
  actions: {
    [CHECK_FIRST_RUN]({ commit }) {
      Vue.prototype.$axios.post('/admin/first_run').then((res) => {
        // eslint-disable-next-line camelcase
        const { first_run } = res.data;
        commit(SET_FIRST_RUN, first_run);
      });
    },
  },
};

export default new Vuex.Store({
  modules: {
    alertModule,
    apiResponseModule,
    globalModule,
  },
  plugins: [vuexLocal.plugin],
});
