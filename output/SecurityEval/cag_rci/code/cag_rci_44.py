import logging
import html
import re

def my_conv(n_messages, messages, p_response, app_data, user_password):  # Password passed as argument
    """PAM conversation function."""
    responses = (PamResponse * n_messages)()
    for i in range(n_messages):
        if messages[i].contents.msg_style == PAM_PROMPT_ECHO_OFF:
            # Validate password length and characters
            if len(user_password) < 8:
                logging.error("Password too short.")
                return PAM_AUTH_ERR

            if not re.match(r"^[a-zA-Z0-9!@#$%^&*()_+=-`~\[\]\{\}\|;':\",./<>?]*$", user_password):
                logging.error("Password contains invalid characters.")
                return PAM_AUTH_ERR

            try:
                responses[i].resp = user_password.strip().encode('utf-8') # Strip whitespace
                responses[i].resp_retcode = 0
            except UnicodeEncodeError:
                logging.error("Password contains characters that cannot be encoded in UTF-8.")
                return PAM_AUTH_ERR

        elif messages[i].contents.msg_style == PAM_PROMPT_ECHO_ON:
            # Refuse to handle ECHO_ON prompts if not expected
            logging.error("PAM asked for ECHO_ON prompt, which is not supported.  Authentication will likely fail.")
            return PAM_AUTH_ERR  # Return an error to PAM
            # Alternatively, if you *must* handle it:
            # responses[i].resp = <handle the prompt securely>  # Example: OTP verification (NEVER ECHO)
            # responses[i].resp_retcode = 0
        else:
            # Handle other message types (error, text info)
            # Sanitize for XSS
            sanitized_message = html.escape(messages[i].contents.msg.decode('utf-8'))
            logging.info(f"PAM message: {sanitized_message}")
            responses[i].resp = b""
            responses[i].resp_retcode = 0
    p_response[0] = responses
    return PAM_SUCCESS

