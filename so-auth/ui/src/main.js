import Vue from 'vue';
import './plugins/axios';
import VueCookie from 'vue-cookie';
import App from './App.vue';
import router from './router';
import './plugins/ant-design-vue';
import store from './store';

Vue.config.productionTip = false;

Vue.use(VueCookie);

new Vue({
  router,
  store,
  render: h => h(App),
}).$mount('#app');
