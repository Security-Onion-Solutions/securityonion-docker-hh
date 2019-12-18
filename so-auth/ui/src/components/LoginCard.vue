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
import {
  handleHtpError, handleHttpResponse, loginUser, sleep,
} from '../services/api-service';
import { resetAlert } from '../services/helper-service';


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
    resetAlert();
  },
  methods: {
    fieldError(type) {
      if (this.validating) { return 'validating'; }
      const { getFieldError, isFieldTouched } = this.form;
      return isFieldTouched(type) && getFieldError(type) ? 'error' : '';
    },
    handleSubmit(e) {
      e.preventDefault();
      this.validating = true;
      this.form.validateFields((err) => {
        if (!err) {
          setTimeout(() => {
            loginUser(
              this.form.getFieldValue('username'),
              this.form.getFieldValue('password'),
              this.form.getFieldValue('remember'),
            )
              .then(async (res) => {
                handleHttpResponse(res);

                await sleep(1000);

                if (res.data.redirect !== '') {
                  window.location = res.data.redirect;
                }
              })
              .catch((error) => {
                handleHtpError(error);
                this.form.resetFields();
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
