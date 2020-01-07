<template>
  <div>
    <a-alert
      :message="alert_type_pretty"
      :description="alert_message"
      :type="alert_type"
      closable
      showIcon
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
    alert_message() {
      return this.$store.state.alertModule.message;
    },
    alert_type() {
      return this.$store.state.alertModule.alertType;
    },
    alert_type_pretty() {
      const string = this.alert_type;
      return string.charAt(0).toUpperCase() + string.slice(1);
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
