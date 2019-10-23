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
            :validate-status="fieldError('password0')"
            style="margin-bottom: 0"
            has-feedback
          >
            <a-input
              v-decorator="[
                'password0',
                {rules:
                  [
                    { required: true, message: 'Please input your old password' },
                  ]
                }
              ]"
              type="password"
              placeholder="Old Password"
            >
              <a-icon
                slot="prefix"
                type="lock"
                style="color:rgba(0,0,0,.25)"
              />
            </a-input>
          </a-form-item>
          <a-divider style="margin-top: 1.25em"/>
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
                    { required: true, message: 'Please input your password' },
                  ]
                }
              ]"
              v-on:change="handlePassword"
              type="password"
              placeholder="New Password"
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
              Change password
            </a-button>
          </a-form-item>
        </a-col>
        <a-col :span="12">
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

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));


export default {
  name: 'ChangePasswordCard',
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
            old_password: this.form.getFieldValue('password0'),
            new_password: this.form.getFieldValue('password2'),
          };

          setTimeout(() => {
            this.$axios.put('/users/change_password', data)
              .then(async (res) => {
                this.$store.state.api_response = res.data;
                this.$store.state.api_response.alert_type = 'success';
                this.$store.state.show_alert = true;

                await sleep(2000);

                this.$router.push('login');
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
    padding-top: 0.25em;
    float: right;
  }
</style>

