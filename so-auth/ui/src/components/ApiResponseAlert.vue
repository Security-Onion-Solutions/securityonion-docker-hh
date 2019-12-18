<template>
  <div>
    <a-alert
      v-if="visible"
      :message="alert_message"
      :type="alert_type"
      closable
      showIcon
      banner
      :afterClose="handleClose"
    />
  </div>
</template>

<script>
import { HIDE_ALERT } from '../constants/mutation-types';

export default {
  name: 'ApiResponseAlert',
  data() {
    return { };
  },
  computed: {
    visible() {
      return this.$store.state.alertModule.showAlert;
    },
    alert_message() {
      return this.$store.state.alertModule.message;
    },
    alert_type() {
      return this.$store.state.alertModule.alertType;
    },
  },
  methods: {
    handleClose() {
      this.$store.commit(HIDE_ALERT);
    },
  },
};
</script>

<style scoped>

</style>
