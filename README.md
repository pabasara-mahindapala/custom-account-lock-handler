## Custom Account Lock Handler

This is a custom account lock handler implemented for WSO2 Identity Server 7.0.0 by extending the [default account lock handler](https://github.com/wso2-extensions/identity-event-handler-account-lock/blob/d9a0567aca30bd0f1d2ec2ce638273bf6af3730e/components/org.wso2.carbon.identity.handler.event.account.lock/src/main/java/org/wso2/carbon/identity/handler/event/account/lock/AccountLockHandler.java). It allows you to lock user accounts temporarily or permanently based on whether basic authentication or non-basic authentication is used (SMS OTP, Email OTP, TOTP).

### How to deploy

1. Clone the repository.
2. Build the project using Maven in the custom-account-lock-handler directory:
   ```bash
   mvn clean install
   ```
3. Copy the generated JAR file from the target directory to the `<IS_HOME>/repository/components/dropins` directory.
4. Add the following configuration to the `<IS_HOME>/repository/conf/deployment.toml` file:
   ```toml
   [authentication_policy]
    disable_account_lock_handler=true # Disable the default account lock handler

   [[event_handler]]
    name= "CustomAccountLockHandler"
    subscriptions =["PRE_AUTHENTICATION", "POST_AUTHENTICATION", "PRE_SET_USER_CLAIMS", "POST_SET_USER_CLAIMS", "POST_NON_BASIC_AUTHENTICATION"]
   ```
5. Restart the WSO2 Identity Server.