import Vue from 'vue';
import Vuex from 'vuex';

Vue.use(Vuex);

export default new Vuex.Store({
  state: {
    api_response: {
      status: '...',
      message: '...',
      alert_type: '...',
      original_uri: '...',
    },
    show_alert: false,
  },
  mutations: {

  },
  actions: {

  },
});

