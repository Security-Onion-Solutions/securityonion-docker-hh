<template>
  <content-container>
    <change-password-card/>
  </content-container>
</template>

<script>
import ContentContainer from '../components/ContentContainer.vue';
import ChangePasswordCard from '../components/ChangePasswordCard.vue';

export default {
  name: 'ChangePassword',
  components: { ChangePasswordCard, ContentContainer },
};
</script>

<style scoped>

</style>
