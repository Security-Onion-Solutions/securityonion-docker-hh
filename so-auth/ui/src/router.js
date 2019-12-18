import Vue from 'vue';
import Router from 'vue-router';
import store from './store';
import { CHECK_FIRST_RUN } from './constants/action-types';

Vue.use(Router);


const router = new Router({
  mode: 'history',
  base: process.env.VUE_APP_UI_BASE_PATH,
  routes: [
    {
      path: '/',
    },
    {
      path: '/login',
      name: 'login',
      component: () => import('./views/Login.vue'),
    },
    {
      path: '/register',
      name: 'register',
      component: () => import('./views/Register.vue'),
    },
    {
      path: '/create-user',
      name: 'create-user',
      component: () => import('./views/Register.vue'),
    },
    {
      path: '/change-password',
      name: 'change-password',
      component: () => import('./views/ChangePassword.vue'),
    },
  ],
});

router.beforeResolve((to, from, next) => {
  if (to.path === '/register') {
    if (store.state.globalModule.firstRun) next();
    else next('login');
  } else if (store.state.globalModule.firstRun) {
    store.dispatch(CHECK_FIRST_RUN).then(() => {
      if (store.state.globalModule.firstRun) next('register');
      else next();
    });
  } else if (to.path === '/') next('login');
  else next();
});

export default router;
