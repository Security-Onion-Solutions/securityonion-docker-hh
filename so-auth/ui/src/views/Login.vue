<template>
  <content-container>
    <login-card/>
  </content-container>
</template>

<script>
import LoginCard from '../components/LoginCard.vue';
import ContentContainer from '../components/ContentContainer.vue';

export default {
  name: 'Login',
  components: { ContentContainer, LoginCard },
};
</script>

<style></style>

