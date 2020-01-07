<template>
  <a-card>
    <div
      style="display: flex; justify-content: center; margin-bottom: 2rem"
    >
      <img
        src="../assets/security_onion_logo.svg"
        width="80%"
        alt="Security Onion logo">
    </div>
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
          <router-link to="/change-password">Change password</router-link>
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
      </a-row>
    </a-form>
  </a-card>
</template>

<script>
import AFormItem from 'ant-design-vue/es/form/FormItem';
import ARow from 'ant-design-vue/es/grid/Row';
import ACol from 'ant-design-vue/es/grid/Col';
import {
  handleHtpError, handleHttpResponse, loginUser,
} from '../services/api-service';
import { resetAlert } from '../services/helper-service';

require('../assets/security_onion_logo.svg');

export default {
  name: 'LoginCard',
  components: { ACol, ARow, AFormItem },
  data() {
    return {
      form: this.$form.createForm(this),
    };
  },
  beforeMount() {
    resetAlert();
  },
  methods: {
    fieldError(type) {
      const { getFieldError, isFieldTouched } = this.form;
      return isFieldTouched(type) && getFieldError(type) ? 'error' : '';
    },
    handleSubmit(e) {
      e.preventDefault();
      this.form.validateFields((err) => {
        if (!err) {
          setTimeout(() => {
            loginUser(
              this.form.getFieldValue('username'),
              this.form.getFieldValue('password'),
              this.form.getFieldValue('remember'),
            )
              .then((res) => {
                if (res.data.redirect !== '') {
                  window.location = res.data.redirect;
                } else {
                  handleHttpResponse(res);
                }
              })
              .catch((error) => {
                handleHtpError(error);
                this.form.resetFields();
              });
          }, 2000);
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
