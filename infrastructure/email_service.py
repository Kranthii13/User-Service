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
    logger.info(f"🔑 SECURITY OTP FOR [{to_email}] ({device_name}): {otp_code}")
    print(f"\n========================================================")
    print(f" 🔑 [LifeFlow Security] Device OTP for {to_email}: {otp_code}")
    print(f"========================================================\n", flush=True)

    if not RESEND_API_KEY or "your_resend_api_key" in RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not configured. OTP printed to console fallback.")
        return True

    try:
        import resend
        resend.api_key = RESEND_API_KEY

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

        resend.Emails.send({
            "from": RESEND_FROM_EMAIL,
            "to": to_email,
            "subject": f"LifeFlow Security Code: {otp_code} (New Device)",
            "html": html_content
        })
        logger.info(f"Successfully sent OTP email to {to_email} via Resend API.")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email via Resend: {e}")
        return False
