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
  baseURL: process.env.VUE_APP_API_URI,
  timeout: 60 * 1000, // Timeout
  // withCredentials: true, // Check cross-site Access-Control
};

const axiosInstance = axios.create(config);

/* axiosInstance.interceptors.request.use(
  (config) => {
    // Do something before request is sent
  },
  (error) => {
    // Do something with request error
    Promise.reject(error);
  },

);

// Add a response interceptor
axiosInstance.interceptors.response.use(
  response =>
    // Do something with response data
    response,
  error =>
    // Do something with response error
    Promise.reject(error),
); */

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
