<template>
  <content-container>
    <register-card/>
  </content-container>
</template>

<script>
import ContentContainer from '../components/ContentContainer.vue';
import RegisterCard from '../components/RegisterCard.vue';

export default {
  name: 'Login',
  components: { RegisterCard, ContentContainer },
};
</script>

<style></style>
