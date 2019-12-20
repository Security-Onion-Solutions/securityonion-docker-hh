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
                {rules: [{ required: true, message: 'Please input a username' }]}
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
            :validate-status="fieldError('password1')"
            style="margin-bottom: 0.5em;"
            has-feedback
          >
            <a-input
              v-decorator="[
                'password1',
                {rules:
                  [
                    { required: true, message: 'Please input a password' },
                  ]
                }
              ]"
              v-on:change="handlePassword"
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
          <a-form-item
            :validate-status="fieldError('password2')"
            has-feedback
          >
            <a-input
              v-decorator="[
                'password2',
                {rules:
                  [
                    { validator: this.passwordConfirmMatch }
                  ]
                }
              ]"
              type="password"
              placeholder="Confirm Password"
            >
              <a-icon
                slot="prefix"
                type="lock"
                style="color:rgba(0,0,0,.25)"
              />
            </a-input>
          </a-form-item>
        </a-col>
      </a-row>
      <a-row>
        <a-col :span="12">
          <a-form-item style="margin: 0; padding: 0" >
            <a-button
              type="primary"
              html-type="submit"
              @submit="handleSubmit"
              :disabled="!!(fieldError('username')
                || fieldError('password1')
                || fieldError('password2'))"
            >
              {{ buttonText }}
            </a-button>
          </a-form-item>
        </a-col>
        <a-col
          :span="12"
          v-if="this.$route.path !== '/register'"
        >
          <div class="login-link">
            Or
            <router-link to="/login">
              return to login
            </router-link>
          </div>
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
  createUser, handleHtpError, handleHttpResponse, register, sleep,
} from '../services/api-service';
import { resetAlert } from '../services/helper-service';
import { CHECK_FIRST_RUN } from '../constants/action-types';


export default {
  name: 'RegisterCard',
  components: { ACol, ARow, AFormItem },
  data() {
    return {
      form: this.$form.createForm(this),
    };
  },
  computed: {
    buttonText() {
      return this.$route.path === '/register' ? 'Register' : 'Create User';
    },
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
            if (this.$route.path === '/register') {
              register(this.form.getFieldValue('username'), this.form.getFieldValue('password2'))
                .then(async (res) => {
                  handleHttpResponse(res);

                  await sleep(1000);

                  this.$store.dispatch(CHECK_FIRST_RUN).then(() => this.$router.push({ name: 'login' }));
                })
                .catch((error) => {
                  handleHtpError(error);
                  this.form.resetFields();
                });
            } else {
              createUser(this.form.getFieldValue('username'), this.form.getFieldValue('password2'))
                .then(async (res) => handleHttpResponse(res))
                .catch((error) => {
                  handleHtpError(error);
                  this.form.resetFields();
                });
            }
          }, 2000);
        }
      });
    },
    handlePassword() {
      if (this.form.isFieldTouched('password2')) {
        this.form.resetFields(['password2']);
      }
    },
    passwordConfirmMatch(rule, value, callback) {
      const fieldsEqual = this.form.getFieldValue('password1') === this.form.getFieldValue('password2');

      if (!fieldsEqual) {
        if (this.form.getFieldValue('password2') === '') {
          callback('Please confirm your password');
        } else {
          callback('Your passwords must match');
        }
      } else {
        callback();
      }
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
  .warning {
    text-align: center;
    font-weight: lighter;
    color: @error-color;
  }
</style>
