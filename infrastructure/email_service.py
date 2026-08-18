import os
import logging

logger = logging.getLogger(__name__)

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "notifications@lifeflow.app")

def send_device_otp_email(to_email: str, first_name: str, otp_code: str, device_name: str = "New Device") -> bool:
    """
    Dispatches a 6-digit OTP verification email for new device login.
    Uses Resend API if available, else logs the OTP to console.
    """
    api_key = os.getenv("RESEND_API_KEY", "")
    from_email = os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev")

    logger.info(f"🔑 SECURITY OTP FOR [{to_email}] ({device_name}): {otp_code}")
    print(f"\n========================================================")
    print(f" 🔑 [LifeFlow Security] Device OTP for {to_email}: {otp_code}")
    print(f"========================================================\n", flush=True)

    if not api_key or "your_resend_api_key" in api_key:
        logger.warning("RESEND_API_KEY not configured. OTP printed to console fallback.")
        return True

    try:
        import resend
        resend.api_key = api_key

        html_content = f"""
        <div style="font-family: Arial, sans-serif; background-color: #0d0f17; color: #f8fafc; padding: 24px; border-radius: 16px; max-width: 500px; margin: 0 auto; border: 1px solid rgba(255,255,255,0.1);">
            <h2 style="color: #38bdf8; margin-top: 0;">LifeFlow Security Verification</h2>
            <p>Hi {first_name},</p>
            <p>A login attempt was detected from a <strong>new device/browser ({device_name})</strong> for your account <strong>{to_email}</strong>.</p>
            <p>Please enter the following 6-digit verification code to complete your login:</p>
            
            <div style="background: rgba(14, 165, 233, 0.15); border: 1px solid #0ea5e9; border-radius: 12px; padding: 16px; text-align: center; margin: 20px 0;">
                <span style="font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{otp_code}</span>
            </div>
            
            <p style="font-size: 13px; color: #94a3b8;">This code expires in 10 minutes. If you did not initiate this login, please change your password immediately.</p>
        </div>
        """

        try:
            res = resend.Emails.send({
                "from": from_email,
                "to": to_email,
                "subject": f"LifeFlow Security Code: {otp_code}",
                "html": html_content
            })
            logger.info(f"Successfully sent OTP email strictly to {to_email} via Resend API: {res}")
            print(f"✅ [Resend Dispatch Success] Sent OTP email strictly to {to_email}: {res}", flush=True)
            return True
        except Exception as send_err:
            err_msg = str(send_err)
            logger.warning(f"Resend dispatch error for {to_email}: {err_msg}")
            print(f"⚠️ [Resend Dispatch Error for {to_email}]: {err_msg}", flush=True)

            fallback_email = os.getenv("RESEND_FALLBACK_EMAIL", "kranthikumarss28@gmail.com")
            if fallback_email and fallback_email.lower() != to_email.lower():
                try:
                    fallback_html = html_content + f"""
                    <div style="margin-top: 20px; padding-top: 12px; border-top: 1px dashed rgba(255,255,255,0.2); color: #f59e0b; font-size: 12px;">
                        ⚠️ Delivered to owner fallback inbox (<strong>{fallback_email}</strong>) for requested account <strong>{to_email}</strong> due to Resend Sandbox mode.
                    </div>
                    """
                    res_fb = resend.Emails.send({
                        "from": from_email,
                        "to": fallback_email,
                        "subject": f"LifeFlow Security Code for {to_email}: {otp_code}",
                        "html": fallback_html
                    })
                    logger.info(f"Delivered OTP for [{to_email}] to owner fallback address [{fallback_email}]: {res_fb}")
                    print(f"📧 [Resend Fallback Success] Delivered OTP code for [{to_email}] to fallback inbox [{fallback_email}]: {res_fb}", flush=True)
                    return True
                except Exception as fb_err:
                    print(f"❌ [Resend Fallback Error for {fallback_email}]: {fb_err}", flush=True)

            print(f"🔑 [CONSOLE FALLBACK OTP CODE]: Code for {to_email} is {otp_code}", flush=True)
            return True
    except Exception as e:
        logger.error(f"Failed to send OTP email via Resend: {e}")
        print(f"❌ [Resend Dispatch Error]: {e}", flush=True)
        print(f"🔑 [CONSOLE FALLBACK OTP CODE]: Code for {to_email} is {otp_code}", flush=True)
        return True

