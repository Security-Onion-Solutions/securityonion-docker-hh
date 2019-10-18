<template>
  <a-card>
    <a-form
      layout="vertical"
      :form="form"
      @submit="handleSubmit"
    >
      <a-row>
        <a-col>
          <a-form-item
            :validate-status="fieldError('username')"
            style="margin-bottom: 0.5em;"
            has-feedback
          >
            <a-input
              v-decorator="[
                'username',
                {rules: [{ required: true, message: 'Please input your username' }]}
              ]"
              placeholder="Username"
            >
              <a-icon
                slot="prefix"
                type="user"
                style="color:rgba(0,0,0,0.25)"
              />
            </a-input>
          </a-form-item>
          <a-form-item
            :validate-status="fieldError('password')"
            style="margin-bottom: 0.5em;"
            has-feedback
          >
            <a-input
              v-decorator="[
                'password',
                {rules: [{ required: true, message: 'Please input your password' }]}
              ]"
              type="password"
              placeholder="Password"
            >
              <a-icon
                slot="prefix"
                type="lock"
                style="color:rgba(0,0,0,.25)"
              />
            </a-input>
          </a-form-item>
        </a-col>
        <a-form-item style="margin-bottom: 0.5em;">
          <router-link to="/change_password">Change password</router-link>
        </a-form-item>
        <a-form-item style="margin-left: 0.25em;">
          <a-checkbox
            v-decorator="[
              'remember',
              {
                valuePropName: 'checked',
                initialValue: false,
              }
            ]"
          >
            Remember me
          </a-checkbox>
        </a-form-item>
      </a-row>
      <a-row>
        <a-col :span="12">
          <a-form-item style="margin: 0; padding: 0" >
            <a-button
              type="primary"
              html-type="submit"
              @submit="handleSubmit"
              :disabled="!!(fieldError('username') || fieldError('password'))"
            >
              Log in
            </a-button>
          </a-form-item>
        </a-col>
        <!--
        <a-col :span="12">
          <div class="login-link">
            Or
            <router-link to="/register">
              register now
            </router-link>
          </div>
        </a-col>
        -->
      </a-row>
    </a-form>
  </a-card>
</template>

<script>
import AFormItem from 'ant-design-vue/es/form/FormItem';
import ARow from 'ant-design-vue/es/grid/Row';
import ACol from 'ant-design-vue/es/grid/Col';

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

export default {
  name: 'LoginCard',
  components: { ACol, ARow, AFormItem },
  data() {
    return {
      form: this.$form.createForm(this),
      validating: false,
    };
  },
  beforeMount() {
    if (this.$store.state.show_alert) {
      this.$store.state.show_alert = false;
    }
  },
  methods: {
    fieldError(type) {
      if (this.validating) { return 'validating'; }
      const { getFieldError, isFieldTouched } = this.form;
      return isFieldTouched(type) && getFieldError(type) ? 'error' : '';
    },
    handleSubmit(e) {
      e.preventDefault();
      this.form.validateFields((err) => {
        if (!err) {
          this.validating = true;
          const data = {
            username: this.form.getFieldValue('username'),
            password: this.form.getFieldValue('password'),
            remember_me: this.form.getFieldValue('remember'),
          };

          setTimeout(() => {
            this.$axios.post('/auth/login', data)
              .then(async (res) => {
                this.$store.state.api_response = res.data;
                this.$store.state.api_response.alert_type = 'success';
                this.$store.state.show_alert = true;

                await sleep(100);

                if (res.data.redirect !== '') {
                  window.location = res.data.redirect;
                }
              })
              .catch((error) => {
                if (error.response) {
                  this.$store.state.api_response = error.response.data;
                  if (error.response.status < 500) {
                    this.$store.state.api_response.alert_type = 'error';
                  } else {
                    this.$store.state.api_response.alert_type = 'warning';
                  }
                } else if (error) {
                  this.$store.state.api_response.alert_type = 'error';
                  this.$store.state.api_response.message = 'No response from server';
                }
                this.$store.state.show_alert = true;
              });
          }, 2000);
          this.validating = false;
        }
      });
    },
  },
};
</script>

<style scoped lang="less">
  @import "../antd-variables";
  @import "common_styles";

  .login-link {
    padding-top: .25em;
    float: right;
  }
</style>
