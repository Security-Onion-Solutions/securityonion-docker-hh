<template>
  <div class="content-container">
    <div class="center-horizontal">
      <api-response-alert/>
    </div>
    <div class="center">
      <slot></slot>
    </div>
  </div>
</template>

<script>
import ApiResponseAlert from './ApiResponseAlert.vue';

export default {
  name: 'ContentContainer',
  components: { ApiResponseAlert },
};
</script>

<style scoped lang="less">
  @import "../antd-variables";

  .content-container {
    height: 100%;
  }
  .center {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .center-horizontal {
    position: absolute;
    z-index: 10;
    width: 100%;
  }
</style>

