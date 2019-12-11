/*
eslint-disable no-shadow,
no-underscore-dangle,
no-unused-expressions,
implicit-arrow-linebreak,
no-param-reassign,
no-unused-vars
 */
import Vue from 'vue';
import axios from 'axios';

const config = {
  baseURL: process.env.VUE_APP_API_URI || `${process.env.VUE_APP_REQUEST_SCHEME}://${window.location.host}/so-auth/api`,
  timeout: 60 * 1000, // Timeout
};

const axiosInstance = axios.create(config);

Plugin.install = (Vue, options) => {
  Vue.axios = axiosInstance;
  window.axios = axiosInstance;
  Object.defineProperties(Vue.prototype, {
    axios: {
      get() {
        return axiosInstance;
      },
    },
    $axios: {
      get() {
        return axiosInstance;
      },
    },
  });
};

Vue.use(Plugin);

export default Plugin;
