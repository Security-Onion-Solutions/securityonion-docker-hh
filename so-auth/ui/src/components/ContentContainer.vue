<template>
  <div class="content-container">
    <div class="center">
      <div class="center-horizontal">
        <div
          v-if="visible"
          class="alert-placement"
        >
          <api-response-alert/>
        </div>
        <slot ref="messageContainer"></slot>
      </div>
    </div>
  </div>
</template>

<script>
import ApiResponseAlert from './ApiResponseAlert.vue';

export default {
  name: 'ContentContainer',
  components: { ApiResponseAlert },
  computed: {
    visible() {
      return this.$store.state.alertModule.showAlert;
    },
  },
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
  .alert-placement {
    position: absolute;
    transform: translate(0, -6rem);
    margin-bottom: 4rem;
    /*width: 100%;*/
  }
  .center-horizontal {
    display: flex;
    justify-content: center;
  }
</style>
