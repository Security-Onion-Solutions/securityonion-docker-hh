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
export default {
  name: 'ApiResponseAlert',
  data() {
    return { };
  },
  computed: {
    visible() {
      return this.$store.state.show_alert;
    },
    alert_message() {
      return this.$store.state.api_response.message;
    },
    alert_type() {
      return this.$store.state.api_response.alert_type;
    },
  },
  methods: {
    handleClose() {
      this.$store.state.show_alert = false;
    },
  },
};
</script>

<style scoped>

</style>

