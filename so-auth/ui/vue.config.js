module.exports = {
  publicPath: process.env.VUE_APP_UI_BASE_PATH,
  css: {
    loaderOptions: {
      less: {
        javascriptEnabled: true,
      },
    },
  },
};

