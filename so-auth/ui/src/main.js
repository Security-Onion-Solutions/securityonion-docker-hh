import Vue from 'vue';
import './plugins/axios';
import VueCookie from 'vue-cookie';
import onExit from 'signal-exit';
import App from './App.vue';
import router from './router';
import './plugins/ant-design-vue';
import store from './store';
import { RESET_FIRST_RUN } from './constants/mutation-types';

onExit(() => {
  store.commit(RESET_FIRST_RUN);
});

store.commit(RESET_FIRST_RUN);


Vue.config.productionTip = false;

Vue.use(VueCookie);

new Vue({
  router,
  store,
  render: (h) => h(App),
}).$mount('#app');
