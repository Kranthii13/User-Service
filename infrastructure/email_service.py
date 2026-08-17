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
            logger.info(f"Successfully sent OTP email to {to_email} via Resend API: {res}")
            print(f"✅ [Resend Dispatch Success] Sent OTP email to {to_email}: {res}", flush=True)
            return True
        except Exception as send_err:
            err_msg = str(send_err)
            logger.warning(f"Resend dispatch error for {to_email}: {err_msg}")
            if to_email.lower() == "kranthikumarss28@gmail.com":
                print(f"⚠️ [Resend Fallback] Retrying dispatch for {to_email}...", flush=True)
                try:
                    res_fallback = resend.Emails.send({
                        "from": from_email,
                        "to": "kranthikumarss28@gmail.com",
                        "subject": f"LifeFlow Verification Code: {otp_code}",
                        "html": html_content
                    })
                    print(f"✅ [Resend Fallback Success] Sent OTP email to kranthikumarss28@gmail.com: {res_fallback}", flush=True)
                except Exception as fb_err:
                    print(f"❌ [Resend Fallback Error]: {fb_err}", flush=True)
            else:
                print(f"ℹ️ [Resend Free Tier Limit] Recipient {to_email} is unverified on onboarding@resend.dev. OTP Code logged to console: {otp_code}", flush=True)
            return True
    except Exception as e:
        logger.error(f"Failed to send OTP email via Resend: {e}")
        print(f"❌ [Resend Dispatch Error]: {e}", flush=True)
        print(f"🔑 [CONSOLE FALLBACK OTP CODE]: Code for {to_email} is {otp_code}", flush=True)
        return True

